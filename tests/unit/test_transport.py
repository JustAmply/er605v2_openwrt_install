import queue
import shutil
import unittest
import uuid
from pathlib import Path
from unittest import mock

from er605_installer.core.transport import SSHClient, discover_router_mac


class _ScriptedStdout:
    def __init__(self, initial_text: str):
        self._queue: queue.Queue[str | None] = queue.Queue()
        self.feed(initial_text)

    def feed(self, text: str) -> None:
        for char in text:
            self._queue.put(char)

    def close(self) -> None:
        self._queue.put(None)

    def read(self, _size: int = 1) -> str:
        item = self._queue.get(timeout=2)
        if item is None:
            return ""
        return item


class _ScriptedStdin:
    def __init__(self, process: "_ScriptedProcess"):
        self.process = process
        self.writes: list[str] = []

    def write(self, text: str) -> None:
        self.writes.append(text)
        self.process.on_write(text)

    def flush(self) -> None:
        return

    def close(self) -> None:
        return


class _ScriptedProcess:
    def __init__(self):
        self.stdout = _ScriptedStdout(">")
        self.stdin = _ScriptedStdin(self)
        self.returncode: int | None = None

    def on_write(self, text: str) -> None:
        if text == "enable\n":
            self.stdout.feed("#")
        elif text == "debug\n":
            self.stdout.feed("Enter your password:")
        elif text == "35bb07df68b0c2b4\n":
            self.stdout.feed("root@ER605:/#")
        elif text == "echo hello\n":
            self.stdout.feed("hello\nroot@ER605:/#")
        elif text == "touch /tmp/test\n":
            self.stdout.feed("root@ER605:/#")
        elif text == "exit\n":
            self.returncode = 0
            self.stdout.feed("Connection to 192.168.0.1 closed.\n")
            self.stdout.close()

    def poll(self):
        return self.returncode

    def kill(self):
        self.returncode = -9
        self.stdout.close()

    def wait(self, timeout=None):
        return self.returncode


class TransportTests(unittest.TestCase):
    def _tempdir(self):
        root = Path.cwd() / ".test_tmp"
        root.mkdir(exist_ok=True)
        case_dir = root / f"transport-{uuid.uuid4().hex}"
        case_dir.mkdir()

        class _TempDir:
            def __enter__(self_inner):
                return str(case_dir)

            def __exit__(self_inner, exc_type, exc, tb):
                shutil.rmtree(case_dir, ignore_errors=True)

        return _TempDir()

    def test_drive_interactive_session_sends_enable_debug_sequence(self) -> None:
        with self._tempdir() as temp_dir:
            repo_root = Path(temp_dir)
            known_hosts = repo_root / "known_hosts"
            client = SSHClient(repo_root=repo_root, known_hosts_path=known_hosts)
            process = _ScriptedProcess()
            script = "enable\ndebug\n35bb07df68b0c2b4\necho hello\nexit\n"

            output = client._drive_interactive_session(process, script, timeout=2)

            self.assertIn("root@ER605:/#", output)
            self.assertEqual(
                process.stdin.writes,
                ["enable\n", "debug\n", "35bb07df68b0c2b4\n", "echo hello\n", "exit\n"],
            )

    def test_drive_interactive_session_accepts_prompt_without_leading_newline(self) -> None:
        with self._tempdir() as temp_dir:
            repo_root = Path(temp_dir)
            known_hosts = repo_root / "known_hosts"
            client = SSHClient(repo_root=repo_root, known_hosts_path=known_hosts)
            process = _ScriptedProcess()
            script = "enable\ndebug\n35bb07df68b0c2b4\ntouch /tmp/test\nexit\n"

            output = client._drive_interactive_session(process, script, timeout=2)

            self.assertIn("root@ER605:/#", output)
            self.assertEqual(
                process.stdin.writes,
                ["enable\n", "debug\n", "35bb07df68b0c2b4\n", "touch /tmp/test\n", "exit\n"],
            )

    def test_discover_router_mac_parses_windows_arp_output(self) -> None:
        arp_output = """
Interface: 192.168.0.1 --- 0xf
  Internet Address      Physical Address      Type
  192.168.0.1          b8-fb-b3-2c-d7-69     dynamic
"""
        with mock.patch("er605_installer.core.transport.can_connect", return_value=True):
            with mock.patch("subprocess.check_output", return_value=arp_output):
                mac = discover_router_mac("192.168.0.1")

        self.assertEqual(mac, "B8:FB:B3:2C:D7:69")


if __name__ == "__main__":
    unittest.main()
