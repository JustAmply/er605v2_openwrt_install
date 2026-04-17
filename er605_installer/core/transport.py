from __future__ import annotations

import contextlib
import http.server
import os
import queue
import re
import shutil
import socket
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from threading import Lock

from er605_installer.core.passwords import normalize_mac


@dataclass
class SSHResult:
    returncode: int
    stdout: str
    stderr: str
    command: list[str]


class SSHClient:
    def __init__(self, repo_root: Path, known_hosts_path: Path):
        self.repo_root = repo_root
        self.known_hosts_path = known_hosts_path
        self.openssl_conf = repo_root / "openssl.cnf"
        self.ssh_path = shutil.which("ssh")
        self._active_process: subprocess.Popen | None = None
        self._active_process_lock = Lock()

    def ensure_available(self) -> None:
        if not self.ssh_path:
            raise RuntimeError("ssh executable was not found on PATH")

    @contextlib.contextmanager
    def _askpass_env(self, password: str):
        helper_suffix = ".cmd" if os.name == "nt" else ".sh"
        runtime_dir = self.known_hosts_path.parent / ".runtime"
        runtime_dir.mkdir(parents=True, exist_ok=True)
        helper = runtime_dir / f"askpass-{uuid.uuid4().hex}{helper_suffix}"
        try:
            if os.name == "nt":
                helper.write_text("@echo off\r\necho %ER605_INSTALLER_PASSWORD%\r\n", encoding="utf-8")
            else:
                helper.write_text("#!/bin/sh\nprintf '%s\\n' \"$ER605_INSTALLER_PASSWORD\"\n", encoding="utf-8")
                helper.chmod(0o700)
            env = os.environ.copy()
            env["SSH_ASKPASS"] = str(helper)
            env["SSH_ASKPASS_REQUIRE"] = "force"
            env["ER605_INSTALLER_PASSWORD"] = password
            env.setdefault("DISPLAY", "er605-installer")
            if self.openssl_conf.exists():
                env["OPENSSL_CONF"] = str(self.openssl_conf)
            yield env
        finally:
            try:
                helper.unlink(missing_ok=True)
            except OSError:
                pass

    def run_script(
        self,
        host: str,
        username: str,
        password: str,
        script: str,
        timeout: int = 120,
    ) -> SSHResult:
        self.ensure_available()
        self.known_hosts_path.parent.mkdir(parents=True, exist_ok=True)
        command = [
            self.ssh_path,
            "-tt",
            "-o",
            "BatchMode=no",
            "-o",
            "PreferredAuthentications=password",
            "-o",
            "PubkeyAuthentication=no",
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-o",
            f"UserKnownHostsFile={self.known_hosts_path}",
            "-o",
            "HostKeyAlgorithms=+ssh-rsa",
            "-o",
            "PubkeyAcceptedAlgorithms=+ssh-rsa",
            "-o",
            "ConnectTimeout=15",
            f"{username}@{host}",
        ]
        with self._askpass_env(password) as env:
            process = subprocess.Popen(
                command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=0,
                env=env,
            )
            with self._active_process_lock:
                self._active_process = process
            try:
                stdout = self._drive_interactive_session(process, script, timeout)
            except Exception:
                process.kill()
                process.wait(timeout=5)
                raise
            finally:
                with self._active_process_lock:
                    if self._active_process is process:
                        self._active_process = None
        return SSHResult(returncode=process.returncode, stdout=stdout, stderr="", command=command)

    def abort_active(self) -> None:
        with self._active_process_lock:
            process = self._active_process
        if process is None:
            return
        if process.poll() is None:
            process.kill()

    def _drive_interactive_session(
        self,
        process: subprocess.Popen,
        script: str,
        timeout: int,
    ) -> str:
        if process.stdin is None or process.stdout is None:
            raise RuntimeError("ssh process pipes were not created")

        output_queue: queue.Queue[str | None] = queue.Queue()
        output_parts: list[str] = []

        def reader() -> None:
            try:
                while True:
                    chunk = process.stdout.read(1)
                    if not chunk:
                        break
                    output_queue.put(chunk)
            finally:
                output_queue.put(None)

        reader_thread = threading.Thread(target=reader, daemon=True)
        reader_thread.start()

        def drain(timeout_slice: float) -> bool:
            try:
                item = output_queue.get(timeout=timeout_slice)
            except queue.Empty:
                return False
            if item is None:
                return True
            output_parts.append(item)
            return True

        def combined() -> str:
            return "".join(output_parts)

        def wait_for(markers: tuple[str, ...], step_timeout: float, start_index: int = 0) -> str:
            end_time = time.monotonic() + step_timeout
            while time.monotonic() < end_time:
                text = combined()
                if any(marker in text[start_index:] for marker in markers):
                    return text
                process_state = process.poll()
                if process_state is not None:
                    while drain(0):
                        pass
                    return combined()
                drain(0.2)
            recent_output = combined()[max(0, start_index - 200):]
            raise TimeoutError(
                f"timed out waiting for ssh prompt: {markers}; recent output tail:\n{recent_output[-1000:]}"
            )

        def send(text: str, delay: float = 0.0) -> None:
            process.stdin.write(text)
            process.stdin.flush()
            if delay > 0:
                time.sleep(delay)

        command_body = script.rstrip("\n")
        lines = command_body.splitlines()
        if len(lines) < 4:
            raise RuntimeError("ssh script is missing the expected enable/debug sequence")
        enable_cmd = lines[0] + "\n"
        debug_cmd = lines[1] + "\n"
        debug_password = lines[2] + "\n"
        if lines[-1] == "exit":
            root_commands = "\n".join(lines[3:-1]).rstrip("\n")
            exit_cmd: str | None = lines[-1] + "\n"
        else:
            root_commands = "\n".join(lines[3:]).rstrip("\n")
            exit_cmd = None

        wait_for((">", "#", "root@ER605:"), timeout)
        send(enable_cmd, delay=0.05)
        wait_for(("#", "root@ER605:"), timeout)
        if "root@ER605:" not in combined():
            send(debug_cmd, delay=0.05)
            wait_for(("Enter your password:", "root@ER605:"), timeout)
            if "root@ER605:" not in combined():
                send(debug_password, delay=0.05)
                wait_for(("root@ER605:",), timeout)
        if root_commands:
            for line in root_commands.splitlines():
                while drain(0):
                    pass
                line_start = len(combined())
                send(line + "\n", delay=0.02)
                wait_for(("root@ER605:", "\n> ", "> "), timeout, start_index=line_start)
        if exit_cmd is not None:
            send(exit_cmd, delay=0.02)
        try:
            process.stdin.close()
        except OSError:
            pass

        end_time = time.monotonic() + timeout
        while time.monotonic() < end_time:
            while drain(0):
                pass
            if process.poll() is not None:
                reader_thread.join(timeout=5)
                while drain(0):
                    pass
                return combined()
            time.sleep(0.2)
        raise TimeoutError("timed out waiting for ssh command completion")


class QuietHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format: str, *args) -> None:  # noqa: A003
        return


class HostedFiles:
    def __init__(self, host: str, directory: Path):
        self.host = host
        self.directory = directory
        self.httpd: http.server.ThreadingHTTPServer | None = None
        self.port: int | None = None
        self._thread: threading.Thread | None = None

    def __enter__(self) -> "HostedFiles":
        handler = lambda *args, **kwargs: QuietHTTPRequestHandler(  # noqa: E731
            *args,
            directory=str(self.directory),
            **kwargs,
        )
        self.httpd = http.server.ThreadingHTTPServer((self.host, 0), handler)
        self.port = int(self.httpd.server_address[1])
        self._thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if self.httpd is not None:
            self.httpd.shutdown()
            self.httpd.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)


def detect_host_ip(router_ip: str) -> str:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.connect((router_ip, 1))
        return str(sock.getsockname()[0])


def can_connect(host: str, port: int, timeout: float = 1.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def discover_router_mac(router_ip: str) -> str:
    can_connect(router_ip, 22, timeout=1.0)
    commands = (
        ["arp", "-a", router_ip],
        ["ip", "neigh", "show", router_ip],
    )
    mac_patterns = (
        re.compile(r"(?i)\b([0-9a-f]{2}(?:[:-][0-9a-f]{2}){5})\b"),
        re.compile(r"(?i)\b([0-9a-f]{12})\b"),
    )
    for command in commands:
        try:
            output = subprocess.check_output(command, stderr=subprocess.DEVNULL, text=True)
        except (FileNotFoundError, subprocess.CalledProcessError):
            continue
        for line in output.splitlines():
            if router_ip not in line:
                continue
            for pattern in mac_patterns:
                match = pattern.search(line)
                if not match:
                    continue
                try:
                    return normalize_mac(match.group(1))
                except ValueError:
                    continue
    return ""
