from __future__ import annotations

import getpass
import re
import shlex
import shutil
import socket
import textwrap
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from er605_installer.core.backup import ManagedBackupReceiver, md5_file, verify_backup_dir
from er605_installer.core.passwords import derive_passwords
from er605_installer.core.state import SessionStore
from er605_installer.core.transport import (
    HostedFiles,
    SSHClient,
    can_connect,
    detect_host_ip,
    discover_router_mac,
)

MAX_INITRAMFS_SIZE = 5_242_880
BACKUP_FIRST_FILE_TIMEOUT = 45
SUPPORTED_FIRMWARE_MAX = (2, 2, 5)
SUPPORTED_FIRMWARE_MIN = (2, 1, 1)


@dataclass
class Inputs:
    router_ip: str
    username: str
    mac: str
    host_ip: str
    firmware_version: str
    session_dir: Path
    dry_run: bool
    skip_openwrt_probe: bool
    wizard_mode: bool = False


class InstallerWorkflow:
    def __init__(self, repo_root: Path, session_store: SessionStore, inputs: Inputs):
        self.repo_root = repo_root
        self.store = session_store
        self.inputs = inputs
        self.state = session_store.load()
        self._hydrate_inputs_from_state()
        self.ssh = SSHClient(repo_root=repo_root, known_hosts_path=session_store.known_hosts_path)
        self.initramfs_path = repo_root / "openwrt-initramfs-compact.bin"
        self.flash_script_path = repo_root / "er605v2_write_initramfs.sh"
        self.md5_path = repo_root / "md5sums"

    def _print(self, message: str) -> None:
        print(message)

    def _hydrate_inputs_from_state(self) -> None:
        self.inputs.router_ip = self.inputs.router_ip or self.state.router_ip
        self.inputs.username = self.inputs.username or self.state.username
        self.inputs.mac = self.inputs.mac or self.state.mac
        self.inputs.host_ip = self.inputs.host_ip or self.state.host_ip
        self.inputs.firmware_version = self.inputs.firmware_version or self.state.firmware_version

    def _discover_router_ip(self) -> str:
        candidates = ("192.168.0.1", "192.168.1.1")
        matches = [candidate for candidate in candidates if can_connect(candidate, 22)]
        if len(matches) == 1:
            return matches[0]
        return ""

    def _prompt_with_default(self, label: str, default: str = "") -> str:
        prompt = f"{label} [{default}]: " if default else f"{label}: "
        value = input(prompt).strip()
        return value or default

    def _confirm_yes_no(self, prompt: str, default_yes: bool = True) -> bool:
        suffix = "[Y/n]" if default_yes else "[y/N]"
        while True:
            answer = input(f"{prompt} {suffix} ").strip().lower()
            if not answer:
                return default_yes
            if answer in {"y", "yes"}:
                return True
            if answer in {"n", "no"}:
                return False
            self._print("Please answer yes or no.")

    def _default_host_ip(self, router_ip: str) -> str:
        if self.inputs.host_ip:
            return self.inputs.host_ip
        if self.state.host_ip:
            return self.state.host_ip
        if not router_ip:
            return ""
        try:
            return detect_host_ip(router_ip)
        except OSError:
            return ""

    def _detect_host_ip_or_empty(self, router_ip: str) -> str:
        if not router_ip:
            return ""
        try:
            return detect_host_ip(router_ip)
        except OSError:
            return ""

    def _wizard_status_lines(self) -> list[str]:
        checkpoints = self.state.checkpoints
        steps = [
            ("Preflight", checkpoints["preflight_completed"]),
            ("Backup", checkpoints["backup_verified"]),
            ("Transfer", checkpoints["initramfs_transferred"]),
            ("Flash", checkpoints["initramfs_installed"]),
            ("Handoff", checkpoints["openwrt_probe_succeeded"]),
        ]
        return [f"- {label}: {'done' if completed else 'pending'}" for label, completed in steps]

    def _print_wizard_overview(self) -> None:
        self._print(
            "\n".join(
                [
                    "ER605 installer wizard",
                    *self._wizard_status_lines(),
                    "",
                    "Router session:",
                    f"- Router IP: {self.state.router_ip}",
                    f"- GUI user: {self.state.username}",
                    f"- Router MAC: {self.state.mac}",
                    f"- Host IP for transfers: {self.state.host_ip}",
                    f"- Firmware version: {self.state.firmware_version or 'auto-detect during preflight'}",
                    f"- Session directory: {self.store.session_dir}",
                ]
            )
        )

    def _confirm_or_edit_identity(self) -> None:
        original_router_ip = self.state.router_ip
        original_mac = self.state.mac
        self._print_wizard_overview()
        if self._confirm_yes_no("Use these values?", default_yes=True):
            return
        self.inputs.router_ip = self._prompt_with_default(
            "Router IP",
            self.inputs.router_ip or self.state.router_ip or "192.168.0.1",
        )
        self.inputs.username = self._prompt_with_default(
            "GUI username",
            self.inputs.username or self.state.username or "admin",
        )
        self.inputs.mac = self._prompt_with_default(
            "Router MAC address",
            self.inputs.mac or self.state.mac,
        )
        if self.inputs.router_ip != original_router_ip or self.inputs.mac != original_mac:
            self.inputs.host_ip = ""
            self.inputs.firmware_version = ""
        self._rebind_session_for_identity()
        host_default = self._default_host_ip(self.inputs.router_ip)
        if self.inputs.router_ip != self.state.router_ip:
            host_default = self._detect_host_ip_or_empty(self.inputs.router_ip)
        if host_default:
            self.inputs.host_ip = self._prompt_with_default("Host IP for transfers", host_default)
        firmware_default = self.inputs.firmware_version
        if self.inputs.router_ip == self.state.router_ip and self.inputs.mac == self.state.mac:
            firmware_default = firmware_default or self.state.firmware_version
        if firmware_default:
            self.inputs.firmware_version = self._prompt_with_default("Firmware version", firmware_default)
        self._sync_identity()
        self._print_wizard_overview()

    def _confirm_step(self, step_label: str, details: list[str], prompt: str) -> bool:
        self._print("\n".join([step_label, *details]))
        if self._confirm_yes_no(prompt, default_yes=True):
            return True
        self._print(f"{step_label} skipped.")
        return False

    def _confirm_step_if_wizard(self, step_label: str, details: list[str], prompt: str) -> bool:
        if not self.inputs.wizard_mode:
            return True
        return self._confirm_step(step_label, details, prompt)

    def _require_inputs(self) -> None:
        if not self.inputs.router_ip:
            self.inputs.router_ip = self._discover_router_ip()
        if not self.inputs.router_ip:
            self.inputs.router_ip = self._prompt_with_default("Router IP", "192.168.0.1")
        if not self.inputs.username:
            self.inputs.username = self._prompt_with_default("GUI username", "admin")
        if not self.inputs.mac:
            self.inputs.mac = discover_router_mac(self.inputs.router_ip)
        if not self.inputs.mac:
            self.inputs.mac = self._prompt_with_default("Router MAC address")
        if not self.inputs.router_ip or not self.inputs.username or not self.inputs.mac:
            raise RuntimeError("router identity is incomplete; supply or confirm IP, username, and MAC address")

    def _sync_identity(self) -> None:
        derived = derive_passwords(self.inputs.mac, self.inputs.username)
        if not self.inputs.host_ip:
            self.inputs.host_ip = detect_host_ip(self.inputs.router_ip)
        self.state.router_ip = self.inputs.router_ip
        self.state.username = self.inputs.username
        self.state.mac = derived["normalized_mac"]
        self.state.host_ip = self.inputs.host_ip
        if self.inputs.firmware_version:
            self.state.firmware_version = self.inputs.firmware_version
        self.state.root_password = derived["root_password"]
        self.state.debug_password = derived["debug_password"]
        self.store.save(self.state)

    def _rebind_session_for_identity(self) -> None:
        target_dir = resolve_session_dir(
            repo_root=self.repo_root,
            explicit=None,
            router_ip=self.inputs.router_ip,
            mac=self.inputs.mac,
        ).resolve()
        self.inputs.session_dir = target_dir
        if target_dir == self.store.session_dir.resolve():
            return
        self.store = SessionStore(target_dir)
        self.state = self.store.load()
        self.ssh = SSHClient(repo_root=self.repo_root, known_hosts_path=self.store.known_hosts_path)

    def _print_identity_summary(self) -> None:
        self._print(
            "\n".join(
                [
                    "Using router session:",
                    f"- Router IP: {self.state.router_ip}",
                    f"- GUI user: {self.state.username}",
                    f"- Router MAC: {self.state.mac}",
                    f"- Host IP for transfers: {self.state.host_ip}",
                    f"- Session directory: {self.store.session_dir}",
                ]
            )
        )

    def _prompt_login_password(self) -> str:
        return getpass.getpass(f"Stock GUI password for {self.inputs.username}@{self.inputs.router_ip}: ")

    def _write_transcript(self, action: str, payload: str) -> None:
        self.store.write_transcript(action, payload)

    @contextmanager
    def _runtime_dir(self, prefix: str):
        runtime_root = self.store.session_dir / ".runtime"
        runtime_root.mkdir(parents=True, exist_ok=True)
        path = runtime_root / f"{prefix}-{uuid.uuid4().hex}"
        path.mkdir()
        try:
            yield path
        finally:
            shutil.rmtree(path, ignore_errors=True)

    def _run_stock_script(
        self,
        login_password: str,
        root_commands: str,
        timeout: int,
        action_name: str,
        allow_disconnect: bool = False,
        success_marker: str | None = None,
    ) -> str:
        completion_marker = f"ER605KV command_completed={uuid.uuid4().hex}"
        script = f"enable\ndebug\n{self.state.debug_password}\n{root_commands}\n"
        if not allow_disconnect:
            script += f'echo "{completion_marker}"\nexit\n'
        result = self.ssh.run_script(
            host=self.state.router_ip,
            username=self.state.username,
            password=login_password,
            script=script,
            timeout=timeout,
        )
        transcript = textwrap.dedent(
            f"""\
            COMMAND: {' '.join(result.command)}
            RETURN CODE: {result.returncode}
            --- STDOUT ---
            {result.stdout}
            --- STDERR ---
            {result.stderr}
            """
        )
        self._write_transcript(action_name, transcript)
        combined_output = result.stdout + result.stderr
        if result.returncode != 0:
            if not allow_disconnect and completion_marker in combined_output:
                return combined_output
            if allow_disconnect:
                disconnected = any(
                    marker in combined_output
                    for marker in (
                        "Connection to ",
                        "Connection closed by remote host",
                        "Connection reset by peer",
                        "client_loop: send disconnect",
                    )
                )
                marker_seen = success_marker is None or success_marker in combined_output
                if disconnected and marker_seen:
                    return combined_output
            raise RuntimeError(f"ssh command failed for {action_name}; see session logs")
        return combined_output

    def _expected_initramfs_md5(self) -> str:
        for line in self.md5_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line.endswith("openwrt-initramfs-compact.bin"):
                return line.split()[0]
        raise RuntimeError("failed to locate initramfs checksum in md5sums")

    def _validate_local_artifacts(self) -> None:
        if not self.initramfs_path.exists():
            raise RuntimeError("openwrt-initramfs-compact.bin is missing")
        if not self.flash_script_path.exists():
            raise RuntimeError("er605v2_write_initramfs.sh is missing")
        size = self.initramfs_path.stat().st_size
        if size > MAX_INITRAMFS_SIZE:
            raise RuntimeError(
                f"initramfs image is too large: {size} bytes > {MAX_INITRAMFS_SIZE} bytes"
            )
        expected_md5 = self._expected_initramfs_md5()
        actual_md5 = md5_file(self.initramfs_path)
        if actual_md5 != expected_md5:
            raise RuntimeError(
                f"initramfs md5 mismatch: expected {expected_md5}, got {actual_md5}"
            )

    def _check_router_tcp(self) -> None:
        with socket.create_connection((self.inputs.router_ip, 22), timeout=5):
            return

    def _parse_remote_report(self, report: str) -> dict[str, str | list[str]]:
        parsed: dict[str, str | list[str]] = {"mtd": [], "ubi_volumes": []}
        current_section: str | None = None
        for raw_line in report.splitlines():
            line = raw_line.strip()
            if line == "ER605_SECTION_MTD_BEGIN":
                current_section = "mtd"
                continue
            if line == "ER605_SECTION_MTD_END":
                current_section = None
                continue
            if line == "ER605_SECTION_UBI_BEGIN":
                current_section = "ubi_volumes"
                continue
            if line == "ER605_SECTION_UBI_END":
                current_section = None
                continue
            if current_section is not None:
                parsed[current_section].append(line)
                continue
            if line.startswith("ER605KV "):
                key, _, value = line[8:].partition("=")
                parsed[key] = value
        return parsed

    def _firmware_tuple(self, version: str) -> tuple[int, int, int]:
        match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", version.strip())
        if not match:
            raise RuntimeError(
                "could not determine stock firmware version; pass --firmware-version explicitly"
            )
        return tuple(int(group) for group in match.groups())

    def _assert_supported_firmware(self, version: str) -> None:
        current = self._firmware_tuple(version)
        if current < SUPPORTED_FIRMWARE_MIN or current > SUPPORTED_FIRMWARE_MAX:
            raise RuntimeError(
                f"unsupported stock firmware branch {version}; supported range is "
                f"{SUPPORTED_FIRMWARE_MIN[0]}.{SUPPORTED_FIRMWARE_MIN[1]}.{SUPPORTED_FIRMWARE_MIN[2]} "
                f"through {SUPPORTED_FIRMWARE_MAX[0]}.{SUPPORTED_FIRMWARE_MAX[1]}.{SUPPORTED_FIRMWARE_MAX[2]}"
            )

    def _parse_total_mtd_bytes(self, mtd_lines: list[str]) -> int:
        total = 0
        for line in mtd_lines:
            match = re.match(r"mtd\d+:\s+([0-9a-fA-F]+)\s", line)
            if match:
                total += int(match.group(1), 16)
        return total

    def _assert_local_free_space(self, required_bytes: int) -> None:
        free = shutil.disk_usage(self.store.backup_dir).free
        if free < required_bytes:
            raise RuntimeError(
                f"insufficient free space in {self.store.backup_dir}: need {required_bytes}, have {free}"
            )

    def _build_preflight_script(self) -> str:
        return textwrap.dedent(
            """\
            echo "ER605KV debug_shell=1"
            model=""
            if [ -r /proc/device-tree/model ]; then
              model=$(tr -d '\\000' < /proc/device-tree/model)
            fi
            sysinfo_model=""
            if [ -r /tmp/sysinfo/model ]; then
              sysinfo_model=$(cat /tmp/sysinfo/model)
            fi
            banner=""
            if [ -r /etc/banner ]; then
              banner=$(tr '\\n' ' ' < /etc/banner)
            fi
            firmware=""
            for candidate in /tmp/firmware.ver /etc/firmware /etc/banner /etc/version; do
              if [ -r "$candidate" ]; then
                firmware=$(sed -n 's/.*\\([0-9][0-9]*\\.[0-9][0-9]*\\.[0-9][0-9]*\\).*/\\1/p' "$candidate" | head -n 1)
                if [ -n "$firmware" ]; then
                  break
                fi
              fi
            done
            if [ -z "$firmware" ]; then
              firmware_mtd=$(sed -n 's/^\\(mtd[0-9][0-9]*\\):.*"firmware-info"$/\\1/p' /proc/mtd | head -n 1)
              if [ -n "$firmware_mtd" ]; then
                firmware=$(dd if=/dev/${firmware_mtd}ro bs=512 count=1 2>/dev/null | tr -cd '[:print:]\\n' | sed -n 's/.*software-version[^0-9]*\\([0-9][0-9]*\\.[0-9][0-9]*\\.[0-9][0-9]*\\).*/\\1/p' | head -n 1)
              fi
            fi
            tmp_free_kb=$(df -k /tmp | awk 'NR==2 {print $4}')
            echo "ER605KV model=$model"
            echo "ER605KV sysinfo_model=$sysinfo_model"
            echo "ER605KV banner=$banner"
            echo "ER605KV firmware_version=$firmware"
            echo "ER605KV tmp_free_kb=$tmp_free_kb"
            echo "ER605_SECTION_MTD_BEGIN"
            cat /proc/mtd
            echo "ER605_SECTION_MTD_END"
            echo "ER605_SECTION_UBI_BEGIN"
            for p in /sys/class/ubi/ubi0_*; do
              if [ -r "$p/name" ]; then
                cat "$p/name"
              fi
            done
            echo "ER605_SECTION_UBI_END"
            """
        )

    def preflight(self) -> None:
        self._require_inputs()
        self.store.ensure_layout()
        self._sync_identity()
        self._print_identity_summary()
        if not self._confirm_step_if_wizard(
            "Step 1/5: Preflight",
            [
                "- Validate local initramfs files and checksum",
                "- Connect to the router and inspect model, firmware, UBI volumes, and free space",
                "- Save detected values into the current session",
            ],
            "Run preflight now?",
        ):
            return
        self.ssh.ensure_available()
        self._validate_local_artifacts()
        if self.inputs.dry_run:
            self._print("dry-run: local artifact validation and TCP reachability passed")
            return
        self._check_router_tcp()
        login_password = self._prompt_login_password()
        report = self._run_stock_script(
            login_password=login_password,
            root_commands=self._build_preflight_script(),
            timeout=120,
            action_name="preflight",
        )
        parsed = self._parse_remote_report(report)
        if parsed.get("debug_shell") != "1":
            raise RuntimeError("failed to confirm stock debug shell access")
        model = str(parsed.get("model", ""))
        sysinfo_model = str(parsed.get("sysinfo_model", ""))
        effective_model = sysinfo_model or model
        if "ER605" not in effective_model or "v2" not in effective_model.lower():
            mtd_names = {
                match.group(1)
                for line in list(parsed.get("mtd", []))
                if (match := re.search(r'"([^"]+)"', line))
            }
            required_names = {
                "kernel",
                "kernel.b",
                "rootfs",
                "rootfs.b",
                "firmware-info",
                "firmware-info.b",
                "tddp",
                "tddp.b",
            }
            if not required_names.issubset(mtd_names):
                raise RuntimeError(
                    f"unexpected hardware model reported by router: {effective_model or model!r}"
                )
        firmware_version = self.inputs.firmware_version or self.state.firmware_version or str(parsed.get("firmware_version", ""))
        if not firmware_version:
            firmware_version = self._prompt_with_default(
                "Detected firmware version was empty, enter stock firmware version",
            )
        self._assert_supported_firmware(firmware_version)
        self.inputs.firmware_version = firmware_version
        self.state.firmware_version = firmware_version
        self.state.hardware_model = effective_model or model
        self.state.stock_banner = str(parsed.get("banner", ""))
        tmp_free_kb = int(str(parsed.get("tmp_free_kb", "0")) or "0")
        required_tmp_kb = (self.initramfs_path.stat().st_size + self.flash_script_path.stat().st_size) // 1024 + 128
        if tmp_free_kb < required_tmp_kb:
            raise RuntimeError(f"/tmp free space too small: need {required_tmp_kb} KiB, have {tmp_free_kb} KiB")
        ubi_volumes = {entry.strip() for entry in parsed.get("ubi_volumes", [])}
        if not {"kernel", "kernel.b"}.issubset(ubi_volumes):
            raise RuntimeError(f"required UBI volumes not present: found {sorted(ubi_volumes)}")
        total_mtd_bytes = self._parse_total_mtd_bytes(list(parsed.get("mtd", [])))
        self._assert_local_free_space(total_mtd_bytes + 16 * 1024 * 1024)
        self.state.checkpoints["preflight_completed"] = True
        self.store.save(self.state)
        self._print("preflight completed successfully")

    def _build_backup_script(self, skip_files: set[str], backup_host: str, backup_port: int) -> str:
        if skip_files:
            skip_case = " | ".join(f'"{name}"' for name in sorted(skip_files))
            should_skip = textwrap.dedent(
                f"""\
                should_skip() {{
                  case "$1" in
                    {skip_case}) return 0 ;;
                    *) return 1 ;;
                  esac
                }}
                """
            )
        else:
            should_skip = "should_skip() { return 1; }\n"
        return textwrap.dedent(
            f"""\
            #!/bin/sh
            BACKUP_URL="http://{backup_host}:{backup_port}"
            {should_skip.rstrip()}

            sed 1d /proc/mtd | while IFS= read -r line; do
              MTD_DEV=${{line%%:*}}
              REST=${{line#*:}}
              set -- $REST
              MTD_SIZE_HEX=$1
              MTD_NAME=$(echo "$line" | cut -d '"' -f2)
              FILENAME="${{MTD_DEV}}_${{MTD_NAME}}.backup"
              SIZE_BYTES=$((0x$MTD_SIZE_HEX))
              if should_skip "$FILENAME"; then
                echo "Skipping upload of $FILENAME"
                continue
              fi
              echo "Uploading $FILENAME"
              curl -f -sS -X PUT -H "Content-Length: $SIZE_BYTES" --data-binary @/dev/${{MTD_DEV}}ro "$BACKUP_URL/$FILENAME" || exit 1
            done

            : > /tmp/md5sums
            sed 1d /proc/mtd | while IFS= read -r line; do
              MTD_DEV=${{line%%:*}}
              MTD_NAME=$(echo "$line" | cut -d '"' -f2)
              FILENAME="${{MTD_DEV}}_${{MTD_NAME}}.backup"
              SUM=$(dd if=/dev/${{MTD_DEV}}ro 2>/dev/null | md5sum | cut -d" " -f1)
              printf '%s\\t%s\\n' "$SUM" "$FILENAME" >> /tmp/md5sums
            done

            MD5_SIZE=$(wc -c < /tmp/md5sums | tr -d ' ')
            echo "Uploading md5sums"
            curl -f -sS -X PUT -H "Content-Length: $MD5_SIZE" --data-binary @/tmp/md5sums "$BACKUP_URL/md5sums" || exit 1
            """
        )

    def _build_backup_launch_script(self, script_text: str) -> str:
        commands = ["cd /tmp", ": > backup.sh"]
        for line in script_text.splitlines():
            commands.append(f"printf '%s\\n' {shlex.quote(line)} >> backup.sh")
        commands.extend(["chmod +x backup.sh", "./backup.sh"])
        return "\n".join(commands)

    def backup(self) -> None:
        if not self.state.checkpoints["preflight_completed"]:
            self.preflight()
            if not self.state.checkpoints["preflight_completed"]:
                return
        if not self._confirm_step_if_wizard(
            "Step 2/5: Backup",
            [
                "- Read all MTD partitions from the router",
                f"- Store backup files under {self.store.backup_dir}",
                "- Verify uploaded files against md5sums and write recovery notes",
            ],
            "Start full backup now?",
        ):
            return
        if self.inputs.dry_run:
            self._print("dry-run: backup would create remote script and receive files")
            return
        verified_files = set()
        md5sums_path = self.store.backup_dir / "md5sums"
        if md5sums_path.exists():
            try:
                manifest = verify_backup_dir(self.store.backup_dir, md5sums_path)
                verified_files = {name for name, entry in manifest.items() if entry.verified}
            except ValueError:
                verified_files = set()
        def on_backup_progress(entry, count):
            self._print(f"backup progress: received {count} file(s), latest {entry.filename} ({entry.size} bytes)")

        receiver = ManagedBackupReceiver(
            host=self.state.host_ip,
            output_dir=self.store.backup_dir,
            progress_callback=on_backup_progress,
        )
        receiver.start()
        login_password = self._prompt_login_password()
        report_box: dict[str, str] = {}
        error_box: dict[str, Exception] = {}

        def run_backup_script() -> None:
            try:
                report_box["report"] = self._run_stock_script(
                    login_password=login_password,
                    root_commands=self._build_backup_launch_script(
                        self._build_backup_script(
                            skip_files=verified_files,
                            backup_host=self.state.host_ip,
                            backup_port=receiver.port,
                        )
                    ),
                    timeout=1800,
                    action_name="backup",
                )
            except Exception as exc:  # pragma: no cover - exercised via workflow tests
                error_box["error"] = exc

        worker = threading.Thread(target=run_backup_script, daemon=True)
        worker.start()
        try:
            start_time = time.monotonic()
            while worker.is_alive():
                if receiver.received:
                    break
                if receiver._error is not None:
                    raise receiver._error
                if time.monotonic() - start_time > BACKUP_FIRST_FILE_TIMEOUT:
                    self.ssh.abort_active()
                    raise RuntimeError(
                        f"backup made no progress within {BACKUP_FIRST_FILE_TIMEOUT} seconds"
                    )
                time.sleep(0.2)
            worker.join()
            if error_box:
                raise error_box["error"]
            report = report_box["report"]
            self._write_transcript("backup-router-output", report)
        finally:
            receiver.join(timeout=5)
            receiver.close()
        if not receiver.received and not (self.store.backup_dir / "md5sums").exists():
            raise RuntimeError("backup ended without receiving any files")
        manifest = verify_backup_dir(self.store.backup_dir, self.store.backup_dir / "md5sums")
        self.state.backup_manifest = manifest
        self.state.checkpoints["backup_verified"] = True
        self.store.save(self.state)
        self._write_recovery_notes()
        self._print("backup completed and verified")

    def verify_backup(self) -> None:
        if not self._confirm_step_if_wizard(
            "Verify backup",
            [
                f"- Recheck the files already stored under {self.store.backup_dir}",
                "- Refresh the session manifest and recovery notes",
            ],
            "Verify the existing backup now?",
        ):
            return
        md5_path = self.store.backup_dir / "md5sums"
        if not md5_path.exists():
            raise RuntimeError("backup md5sums file is missing; run backup first")
        manifest = verify_backup_dir(self.store.backup_dir, md5_path)
        self.state.backup_manifest = manifest
        self.state.checkpoints["backup_verified"] = True
        self.store.save(self.state)
        self._write_recovery_notes()
        self._print("backup verification passed")

    def _write_recovery_notes(self) -> None:
        lines = [
            "ER605 recovery notes",
            "",
            f"Router IP during stock phase: {self.state.router_ip}",
            f"Router MAC: {self.state.mac}",
            f"Detected hardware model: {self.state.hardware_model or 'unknown'}",
            f"Detected firmware version: {self.state.firmware_version or 'unknown'}",
            "",
            "Artifacts in this session:",
            f"- Backup directory: {self.store.backup_dir}",
            f"- Backup manifest: {self.store.manifest_path}",
            "",
            "Expected recovery workflow:",
            "- Keep the full MTD dump intact.",
            "- If the router becomes unbootable after the initramfs flash path, recovery may require UART access.",
            "- Use the verified backup images as the source of truth when restoring partitions.",
            "- The vendor recovery mode should not be treated as reliable after this install path.",
            "",
            "Important:",
            "- Do not delete md5sums or the session logs.",
            "- Keep a copy of the backup directory off the host machine before further flashing.",
        ]
        self.store.recovery_notes_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def _build_transfer_script(self, host: str, port: int) -> str:
        return textwrap.dedent(
            f"""\
            cd /tmp
            curl -f -sS -o er605v2_write_initramfs.sh http://{host}:{port}/er605v2_write_initramfs.sh
            curl -f -sS -o openwrt-initramfs-compact.bin http://{host}:{port}/openwrt-initramfs-compact.bin
            chmod +x er605v2_write_initramfs.sh
            remote_md5=$(md5sum openwrt-initramfs-compact.bin | awk '{{print $1}}')
            remote_size=$(wc -c < openwrt-initramfs-compact.bin)
            echo "ER605KV remote_md5=$remote_md5"
            echo "ER605KV remote_size=$remote_size"
            echo "ER605_SECTION_UBI_BEGIN"
            for p in /sys/class/ubi/ubi0_*; do
              if [ -r "$p/name" ]; then
                cat "$p/name"
              fi
            done
            echo "ER605_SECTION_UBI_END"
            """
        )

    def _build_flash_script(self) -> str:
        return textwrap.dedent(
            """\
            cd /tmp
            ./er605v2_write_initramfs.sh openwrt-initramfs-compact.bin
            flash_status=$?
            echo "ER605KV flash_status=$flash_status"
            if [ "$flash_status" -ne 0 ]; then
              exit "$flash_status"
            fi
            sync
            reboot
            """
        )

    def _typed_flash_confirmation(self) -> None:
        expected = f"FLASH {self.state.mac}"
        self._print(
            "\n".join(
                [
                    "Flash confirmation required.",
                    f"Router IP: {self.state.router_ip}",
                    f"Router MAC: {self.state.mac}",
                    f"Firmware branch: {self.state.firmware_version}",
                    f"Initramfs md5: {self._expected_initramfs_md5()}",
                    "Target UBI volumes: kernel, kernel.b",
                    f"Type exactly: {expected}",
                ]
            )
        )
        typed = input("> ").strip()
        if typed != expected:
            raise RuntimeError("flash confirmation failed; refusing to continue")

    def _probe_openwrt(self, timeout_seconds: int = 180) -> bool:
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            try:
                with socket.create_connection(("192.168.1.1", 80), timeout=5):
                    self.state.checkpoints["openwrt_probe_succeeded"] = True
                    self.store.save(self.state)
                    self._print("detected OpenWrt web service on 192.168.1.1:80")
                    return True
            except OSError:
                time.sleep(5)
        return False

    def _handle_openwrt_probe(self) -> None:
        self._print(
            "\n".join(
                [
                    "Step 5/5: OpenWrt Handoff",
                    "- The temporary OpenWrt environment should appear on 192.168.1.1 after reboot",
                    "- You may need to move your host onto the ER605 link or assign a static 192.168.1.x address",
                ]
            )
        )
        if self.inputs.skip_openwrt_probe:
            self._print("skipping automatic OpenWrt probe because --skip-openwrt-probe was requested")
            self._print_openwrt_network_handoff()
            return
        if self.inputs.wizard_mode and not self._confirm_yes_no("Try automatic OpenWrt probe now?", default_yes=True):
            self._print_openwrt_network_handoff()
            self._print("Automatic probe skipped for now. Rerun `er605-installer` later to retry it.")
            return
        if self._probe_openwrt():
            return
        self._print(
            "\n".join(
                [
                    "Flash completed, but the temporary OpenWrt web UI did not answer automatically yet.",
                    "This usually means the host is still on the old network or another adapter is already using 192.168.1.1.",
                ]
            )
        )
        self._print_openwrt_network_handoff()
        self._print("Rerun `er605-installer` later to retry the probe once your host is on the ER605 link.")

    def _print_openwrt_network_handoff(self) -> None:
        self._print(
            "\n".join(
                [
                    "OpenWrt network handoff warning.",
                    "After the reboot, the temporary OpenWrt environment should come up on 192.168.1.1.",
                    f"Your stock router IP {self.state.router_ip} will no longer be the correct address.",
                    "If another network on this host already uses 192.168.1.1, disable that connection temporarily.",
                    "Your Ethernet adapter may need a static address such as 192.168.1.2/24 with no gateway.",
                    "Then open http://192.168.1.1 over the ER605 Ethernet link.",
                ]
            )
        )

    def _transfer_initramfs(self, login_password: str) -> None:
        expected_md5 = self._expected_initramfs_md5()
        with self._runtime_dir("install-host") as transfer_dir:
            shutil.copy2(self.flash_script_path, transfer_dir / self.flash_script_path.name)
            shutil.copy2(self.initramfs_path, transfer_dir / self.initramfs_path.name)
            with HostedFiles(self.state.host_ip, transfer_dir) as hosted:
                report = self._run_stock_script(
                    login_password=login_password,
                    root_commands=self._build_transfer_script(
                        host=self.state.host_ip,
                        port=int(hosted.port),
                    ),
                    timeout=600,
                    action_name="install-initramfs-transfer",
                )
        parsed = self._parse_remote_report(report)
        remote_md5 = str(parsed.get("remote_md5", ""))
        remote_size = int(str(parsed.get("remote_size", "0")) or "0")
        if remote_md5 != expected_md5:
            raise RuntimeError(f"remote initramfs md5 mismatch: expected {expected_md5}, got {remote_md5}")
        if remote_size != self.initramfs_path.stat().st_size:
            raise RuntimeError(
                f"remote initramfs size mismatch: expected {self.initramfs_path.stat().st_size}, got {remote_size}"
            )
        ubi_volumes = {entry.strip() for entry in parsed.get("ubi_volumes", [])}
        if not {"kernel", "kernel.b"}.issubset(ubi_volumes):
            raise RuntimeError(f"required UBI volumes not present before flash: found {sorted(ubi_volumes)}")
        self.state.checkpoints["initramfs_transferred"] = True
        self.store.save(self.state)
        self._print("initramfs files transferred and verified on the router")

    def install_initramfs(self) -> None:
        if not self.state.checkpoints["backup_verified"]:
            raise RuntimeError("backup has not been verified; refusing to flash")
        self._validate_local_artifacts()
        if self.inputs.dry_run:
            self._print("dry-run: install-initramfs would transfer files and stop before flash")
            return
        login_password: str | None = None
        if not self.state.checkpoints["initramfs_transferred"]:
            if not self._confirm_step_if_wizard(
                "Step 3/5: Transfer Initramfs",
                [
                    "- Host the initramfs image and flash helper from this PC",
                    "- Download both files to /tmp on the router",
                    "- Verify checksum, size, and target UBI volumes before any write",
                ],
                "Transfer initramfs files to the router now?",
            ):
                return
            login_password = self._prompt_login_password()
            self._transfer_initramfs(login_password)
        else:
            self._print("Step 3/5: Transfer Initramfs already completed in this session.")
        if not self._confirm_step_if_wizard(
            "Step 4/5: Flash Initramfs",
            [
                "- Write the initramfs image to the kernel UBI volumes",
                "- Reboot the router immediately afterward",
                "- The stock router IP will stop being valid after reboot",
            ],
            "Proceed to flashing step?",
        ):
            return
        if login_password is None:
            login_password = self._prompt_login_password()
        self._typed_flash_confirmation()
        flash_report = self._run_stock_script(
            login_password=login_password,
            root_commands=self._build_flash_script(),
            timeout=300,
            action_name="install-initramfs-flash",
            allow_disconnect=True,
            success_marker="ER605KV flash_status=0",
        )
        if "ER605KV flash_status=0" not in flash_report:
            raise RuntimeError("flash status marker was not observed; refusing to mark flash as successful")
        self._write_transcript("install-initramfs-flash-output", flash_report)
        self.state.checkpoints["initramfs_installed"] = True
        self.store.save(self.state)
        self._handle_openwrt_probe()

    def resume(self) -> None:
        self.store.ensure_layout()
        self._require_inputs()
        self._sync_identity()
        self._confirm_or_edit_identity()
        if not self.state.checkpoints["preflight_completed"]:
            self.preflight()
            if not self.state.checkpoints["preflight_completed"]:
                return
        if not self.state.checkpoints["backup_verified"]:
            self.backup()
            if not self.state.checkpoints["backup_verified"]:
                return
        if not self.state.checkpoints["initramfs_installed"]:
            self.install_initramfs()
            if not self.state.checkpoints["initramfs_installed"]:
                return
            if not self.state.checkpoints["openwrt_probe_succeeded"]:
                return
        if not self.state.checkpoints["openwrt_probe_succeeded"]:
            self._handle_openwrt_probe()
            if not self.state.checkpoints["openwrt_probe_succeeded"]:
                return
        self._print("Wizard completed successfully.")


def load_config(path: Path | None) -> dict:
    if path is None or not path.exists():
        return {}
    import tomllib

    return tomllib.loads(path.read_text(encoding="utf-8"))


def resolve_session_dir(repo_root: Path, explicit: str | None, router_ip: str, mac: str) -> Path:
    if explicit:
        return Path(explicit).expanduser().resolve()
    safe_mac = re.sub(r"[^0-9A-Fa-f]", "", mac or "unknown").lower() or "unknown"
    safe_ip = router_ip.replace(".", "-") if router_ip else "router"
    return (repo_root / ".er605_sessions" / f"{safe_ip}-{safe_mac}").resolve()
