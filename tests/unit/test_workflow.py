import unittest
from pathlib import Path
import shutil
import time
import uuid
from unittest import mock

from er605_installer.core.state import SessionStore
from er605_installer.core.transport import SSHResult
from er605_installer.core.workflow import Inputs, InstallerWorkflow


class WorkflowTests(unittest.TestCase):
    def _tempdir(self):
        root = Path.cwd() / ".test_tmp"
        root.mkdir(exist_ok=True)
        case_dir = root / f"workflow-{uuid.uuid4().hex}"
        case_dir.mkdir()
        class _TempDir:
            def __enter__(self_inner):
                return str(case_dir)
            def __exit__(self_inner, exc_type, exc, tb):
                shutil.rmtree(case_dir, ignore_errors=True)
        return _TempDir()

    def _workflow(self, temp_dir: str) -> InstallerWorkflow:
        repo_root = Path(temp_dir)
        (repo_root / "openwrt-initramfs-compact.bin").write_bytes(b"data")
        (repo_root / "er605v2_write_initramfs.sh").write_text("#!/bin/sh\n", encoding="utf-8")
        (repo_root / "md5sums").write_text(
            "8d777f385d3dfec8815d20f7496026dc openwrt-initramfs-compact.bin\n",
            encoding="utf-8",
        )
        inputs = Inputs(
            router_ip="192.168.0.1",
            username="admin",
            mac="B8-FB-B3-2C-D7-69",
            host_ip="192.168.0.2",
            firmware_version="2.2.5",
            session_dir=repo_root / ".er605_sessions" / "test",
            dry_run=False,
            skip_openwrt_probe=False,
            wizard_mode=True,
        )
        workflow = InstallerWorkflow(repo_root, SessionStore(inputs.session_dir), inputs)
        workflow._confirm_yes_no = mock.Mock(return_value=True)
        return workflow

    def test_install_requires_verified_backup(self) -> None:
        with self._tempdir() as temp_dir:
            workflow = self._workflow(temp_dir)
            workflow._sync_identity()
            with self.assertRaises(RuntimeError):
                workflow.install_initramfs()

    def test_confirmation_gate_rejects_wrong_phrase(self) -> None:
        with self._tempdir() as temp_dir:
            workflow = self._workflow(temp_dir)
            workflow._sync_identity()
            with mock.patch("builtins.input", return_value="nope"):
                with self.assertRaises(RuntimeError):
                    workflow._typed_flash_confirmation()

    def test_resume_advances_to_backup_when_preflight_done(self) -> None:
        with self._tempdir() as temp_dir:
            workflow = self._workflow(temp_dir)
            workflow._sync_identity()
            workflow.state.checkpoints["preflight_completed"] = True
            workflow.store.save(workflow.state)
            with mock.patch.object(workflow, "backup") as backup_mock:
                workflow.resume()
            backup_mock.assert_called_once()

    def test_resume_runs_steps_in_order_until_complete(self) -> None:
        with self._tempdir() as temp_dir:
            workflow = self._workflow(temp_dir)
            workflow._sync_identity()

            def mark_preflight():
                workflow.state.checkpoints["preflight_completed"] = True
                workflow.store.save(workflow.state)

            def mark_backup():
                workflow.state.checkpoints["backup_verified"] = True
                workflow.store.save(workflow.state)

            def mark_install():
                workflow.state.checkpoints["initramfs_installed"] = True
                workflow.state.checkpoints["openwrt_probe_succeeded"] = True
                workflow.store.save(workflow.state)

            with mock.patch.object(workflow, "preflight", side_effect=mark_preflight) as preflight_mock:
                with mock.patch.object(workflow, "backup", side_effect=mark_backup) as backup_mock:
                    with mock.patch.object(workflow, "install_initramfs", side_effect=mark_install) as install_mock:
                        workflow.resume()

            preflight_mock.assert_called_once()
            backup_mock.assert_called_once()
            install_mock.assert_called_once()

    def test_identity_edit_rebinds_to_router_specific_session(self) -> None:
        with self._tempdir() as temp_dir:
            workflow = self._workflow(temp_dir)
            workflow._sync_identity()
            workflow.state.checkpoints["backup_verified"] = True
            workflow.store.save(workflow.state)

            target_dir = Path(temp_dir) / ".er605_sessions" / "192-168-0-2-aabbccddeeff"
            target_store = SessionStore(target_dir)
            target_state = target_store.load()
            target_state.router_ip = "192.168.0.2"
            target_state.username = "admin"
            target_state.mac = "AA:BB:CC:DD:EE:FF"
            target_state.host_ip = "192.168.0.3"
            target_store.save(target_state)

            with mock.patch.object(workflow, "_confirm_yes_no", return_value=False):
                with mock.patch(
                    "builtins.input",
                    side_effect=["192.168.0.2", "admin", "AA-BB-CC-DD-EE-FF", "", ""],
                ):
                    workflow._confirm_or_edit_identity()

            self.assertEqual(workflow.store.session_dir, target_dir)
            self.assertEqual(workflow.state.router_ip, "192.168.0.2")
            self.assertEqual(workflow.state.mac, "AA:BB:CC:DD:EE:FF")
            self.assertFalse(workflow.state.checkpoints["backup_verified"])

    def test_preflight_subcommand_runs_without_wizard_confirmation(self) -> None:
        with self._tempdir() as temp_dir:
            workflow = self._workflow(temp_dir)
            workflow.inputs.wizard_mode = False

            with mock.patch.object(workflow, "_confirm_step") as confirm_mock:
                workflow.inputs.dry_run = True
                workflow.preflight()

            confirm_mock.assert_not_called()
            self.assertTrue(workflow.state.checkpoints["preflight_completed"] is False)

    def test_run_stock_script_allows_expected_disconnect_after_success_marker(self) -> None:
        with self._tempdir() as temp_dir:
            workflow = self._workflow(temp_dir)
            workflow._sync_identity()
            ssh_result = SSHResult(
                returncode=255,
                stdout="ER605KV flash_status=0\n",
                stderr="Connection to 192.168.0.1 closed by remote host.\n",
                command=["ssh"],
            )
            with mock.patch.object(workflow.ssh, "run_script", return_value=ssh_result):
                output = workflow._run_stock_script(
                    login_password="secret",
                    root_commands="reboot",
                    timeout=5,
                    action_name="flash",
                    allow_disconnect=True,
                    success_marker="ER605KV flash_status=0",
                )
            self.assertIn("ER605KV flash_status=0", output)

    def test_run_stock_script_rejects_nonzero_exit_without_completion_marker(self) -> None:
        with self._tempdir() as temp_dir:
            workflow = self._workflow(temp_dir)
            workflow._sync_identity()
            ssh_result = SSHResult(
                returncode=255,
                stdout="root@ER605:/#\nConnection to 192.168.0.1 closed.\n",
                stderr="",
                command=["ssh"],
            )
            with mock.patch.object(workflow.ssh, "run_script", return_value=ssh_result):
                with self.assertRaises(RuntimeError):
                    workflow._run_stock_script(
                        login_password="secret",
                        root_commands="false",
                        timeout=5,
                        action_name="backup",
                    )

    def test_install_initramfs_hosts_only_transfer_files(self) -> None:
        with self._tempdir() as temp_dir:
            workflow = self._workflow(temp_dir)
            workflow._sync_identity()
            workflow.state.checkpoints["backup_verified"] = True
            workflow.store.save(workflow.state)
            hosted_dirs: list[Path] = []
            fake_transfer_root = Path(temp_dir) / "served-files"
            fake_transfer_root.mkdir()

            class FakeHostedFiles:
                def __init__(self, host: str, directory: Path):
                    hosted_dirs.append(Path(directory))
                    self.port = 8080

                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc, tb):
                    return None

            class FakeTemporaryDirectory:
                def __enter__(self):
                    return fake_transfer_root

                def __exit__(self, exc_type, exc, tb):
                    return None

            transfer_report = "\n".join(
                [
                    "ER605KV remote_md5=8d777f385d3dfec8815d20f7496026dc",
                    "ER605KV remote_size=4",
                    "ER605_SECTION_UBI_BEGIN",
                    "kernel",
                    "kernel.b",
                    "ER605_SECTION_UBI_END",
                ]
            )
            flash_report = "ER605KV flash_status=0\nConnection to 192.168.0.1 closed by remote host.\n"

            with mock.patch("er605_installer.core.workflow.HostedFiles", FakeHostedFiles):
                with mock.patch.object(workflow, "_runtime_dir", return_value=FakeTemporaryDirectory()):
                    with mock.patch.object(workflow, "_prompt_login_password", return_value="secret"):
                        with mock.patch.object(workflow, "_typed_flash_confirmation", return_value=None):
                            with mock.patch.object(workflow, "_handle_openwrt_probe", return_value=None):
                                with mock.patch.object(
                                    workflow,
                                    "_run_stock_script",
                                    side_effect=[transfer_report, flash_report],
                                ):
                                    workflow.install_initramfs()

            self.assertEqual(len(hosted_dirs), 1)
            hosted_files = {path.name for path in hosted_dirs[0].iterdir()}
            self.assertEqual(
                hosted_files,
                {"er605v2_write_initramfs.sh", "openwrt-initramfs-compact.bin"},
            )

    def test_install_initramfs_can_skip_openwrt_probe(self) -> None:
        with self._tempdir() as temp_dir:
            workflow = self._workflow(temp_dir)
            workflow.inputs.skip_openwrt_probe = True
            workflow._sync_identity()
            workflow.state.checkpoints["backup_verified"] = True
            workflow.store.save(workflow.state)

            transfer_report = "\n".join(
                [
                    "ER605KV remote_md5=8d777f385d3dfec8815d20f7496026dc",
                    "ER605KV remote_size=4",
                    "ER605_SECTION_UBI_BEGIN",
                    "kernel",
                    "kernel.b",
                    "ER605_SECTION_UBI_END",
                ]
            )
            flash_report = "ER605KV flash_status=0\nConnection to 192.168.0.1 closed by remote host.\n"

            with mock.patch.object(workflow, "_prompt_login_password", return_value="secret"):
                with mock.patch.object(workflow, "_typed_flash_confirmation", return_value=None):
                    with mock.patch.object(workflow, "_probe_openwrt") as probe_mock:
                        with mock.patch.object(
                            workflow,
                            "_run_stock_script",
                            side_effect=[transfer_report, flash_report],
                        ):
                            with mock.patch("er605_installer.core.workflow.HostedFiles"):
                                with mock.patch.object(workflow, "_runtime_dir"):
                                    with mock.patch("shutil.copy2"):
                                        workflow.install_initramfs()

            probe_mock.assert_not_called()
            self.assertTrue(workflow.state.checkpoints["initramfs_installed"])

    def test_resume_respects_skip_openwrt_probe(self) -> None:
        with self._tempdir() as temp_dir:
            workflow = self._workflow(temp_dir)
            workflow.inputs.skip_openwrt_probe = True
            workflow._sync_identity()
            workflow.state.checkpoints["preflight_completed"] = True
            workflow.state.checkpoints["backup_verified"] = True
            workflow.state.checkpoints["initramfs_installed"] = True
            workflow.store.save(workflow.state)

            with mock.patch.object(workflow, "_probe_openwrt") as probe_mock:
                workflow.resume()

            probe_mock.assert_not_called()

    def test_handle_openwrt_probe_is_non_fatal_when_router_is_not_reachable_yet(self) -> None:
        with self._tempdir() as temp_dir:
            workflow = self._workflow(temp_dir)
            workflow._sync_identity()

            with mock.patch.object(workflow, "_probe_openwrt", return_value=False):
                with mock.patch.object(workflow, "_print") as print_mock:
                    workflow._handle_openwrt_probe()

            self.assertFalse(workflow.state.checkpoints["openwrt_probe_succeeded"])
            printed = "\n".join(call.args[0] for call in print_mock.call_args_list)
            self.assertIn("Flash completed", printed)

    def test_backup_inlines_backup_script_on_router(self) -> None:
        with self._tempdir() as temp_dir:
            workflow = self._workflow(temp_dir)
            workflow._sync_identity()
            workflow.state.checkpoints["preflight_completed"] = True
            workflow.store.save(workflow.state)

            class FakeReceiver:
                def __init__(self, host, output_dir, progress_callback=None, port=0):
                    self.host = host
                    self.output_dir = Path(output_dir)
                    self.port = 9999
                    self.progress_callback = progress_callback
                    self.received = {}

                def start(self):
                    return None

                def join(self, timeout=None):
                    (self.output_dir / "mtd0_Test.backup").write_text("data", encoding="utf-8")
                    (self.output_dir / "md5sums").write_text(
                        "8d777f385d3dfec8815d20f7496026dc mtd0_Test.backup\n",
                        encoding="utf-8",
                    )
                    self.received["mtd0_Test.backup"] = object()
                    return None

                def close(self):
                    return None

            with mock.patch("er605_installer.core.workflow.ManagedBackupReceiver", FakeReceiver):
                with mock.patch.object(workflow, "_prompt_login_password", return_value="secret"):
                    with mock.patch.object(workflow, "_run_stock_script", return_value="done") as run_mock:
                        workflow.backup()

            root_commands = run_mock.call_args.kwargs["root_commands"]
            self.assertIn("printf '%s\\n'", root_commands)
            self.assertIn("./backup.sh", root_commands)

    def test_backup_aborts_when_no_first_file_arrives(self) -> None:
        with self._tempdir() as temp_dir:
            workflow = self._workflow(temp_dir)
            workflow._sync_identity()
            workflow.state.checkpoints["preflight_completed"] = True
            workflow.store.save(workflow.state)

            class FakeReceiver:
                def __init__(self, host, output_dir, progress_callback=None, port=0):
                    self.host = host
                    self.output_dir = Path(output_dir)
                    self.port = 9999
                    self.progress_callback = progress_callback
                    self.received = {}
                    self._error = None

                def start(self):
                    return None

                def join(self, timeout=None):
                    return None

                def close(self):
                    return None

            def slow_run_stock_script(**kwargs):
                time.sleep(1)
                return "done"

            with mock.patch("er605_installer.core.workflow.ManagedBackupReceiver", FakeReceiver):
                with mock.patch("er605_installer.core.workflow.BACKUP_FIRST_FILE_TIMEOUT", 0.01):
                    with mock.patch.object(workflow, "_prompt_login_password", return_value="secret"):
                        with mock.patch.object(workflow, "_run_stock_script", side_effect=slow_run_stock_script):
                            with mock.patch.object(workflow.ssh, "abort_active") as abort_mock:
                                with self.assertRaises(RuntimeError):
                                    workflow.backup()
            abort_mock.assert_called_once()

    def test_backup_script_uses_http_put_and_uploads_before_md5_generation(self) -> None:
        with self._tempdir() as temp_dir:
            workflow = self._workflow(temp_dir)

            script = workflow._build_backup_script(set(), "192.168.0.2", 9999)

            self.assertIn('BACKUP_URL="http://192.168.0.2:9999"', script)
            self.assertIn('curl -f -sS -X PUT -H "Content-Length: $SIZE_BYTES"', script)
            self.assertNotIn("busybox nc", script)
            self.assertLess(script.index("Uploading $FILENAME"), script.index(': > /tmp/md5sums'))

    def test_router_side_curl_downloads_are_silent(self) -> None:
        with self._tempdir() as temp_dir:
            workflow = self._workflow(temp_dir)

            backup_launch = workflow._build_backup_launch_script("#!/bin/sh\necho ok\n")
            transfer_script = workflow._build_transfer_script("192.168.0.2", 8000)

            self.assertNotIn("curl -f -o backup.sh", backup_launch)
            self.assertIn("printf '%s\\n'", backup_launch)
            self.assertIn("curl -f -sS -o er605v2_write_initramfs.sh", transfer_script)
            self.assertIn("curl -f -sS -o openwrt-initramfs-compact.bin", transfer_script)


if __name__ == "__main__":
    unittest.main()
