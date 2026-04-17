import argparse
import json
import shutil
import unittest
import uuid
from pathlib import Path

from er605_installer.cli import build_parser, resolve_cli_session_dir


class CliTests(unittest.TestCase):
    def _tempdir(self):
        root = Path.cwd() / ".test_tmp"
        root.mkdir(exist_ok=True)
        case_dir = root / f"cli-{uuid.uuid4().hex}"
        case_dir.mkdir()

        class _TempDir:
            def __enter__(self_inner):
                return str(case_dir)

            def __exit__(self_inner, exc_type, exc, tb):
                shutil.rmtree(case_dir, ignore_errors=True)

        return _TempDir()

    def _args(self, **overrides):
        values = {
            "config": None,
            "router_ip": None,
            "username": None,
            "mac": None,
            "host_ip": None,
            "firmware_version": None,
            "session_dir": None,
            "dry_run": False,
            "skip_openwrt_probe": False,
            "command": "resume",
        }
        values.update(overrides)
        return argparse.Namespace(**values)

    def test_resume_without_flags_uses_only_saved_session(self) -> None:
        with self._tempdir() as temp_dir:
            repo_root = Path(temp_dir)
            session_dir = repo_root / ".er605_sessions" / "192-168-0-1-b8fbb32cd769"
            session_dir.mkdir(parents=True)
            (session_dir / "session.json").write_text("{}", encoding="utf-8")

            resolved = resolve_cli_session_dir(repo_root, self._args(), {})

            self.assertEqual(resolved, session_dir.resolve())

    def test_resume_without_flags_rejects_ambiguous_sessions(self) -> None:
        with self._tempdir() as temp_dir:
            repo_root = Path(temp_dir)
            first = repo_root / ".er605_sessions" / "first"
            second = repo_root / ".er605_sessions" / "second"
            first.mkdir(parents=True)
            second.mkdir(parents=True)
            (first / "session.json").write_text("{}", encoding="utf-8")
            (second / "session.json").write_text("{}", encoding="utf-8")

            with self.assertRaises(RuntimeError):
                resolve_cli_session_dir(repo_root, self._args(), {})

    def test_router_ip_reuses_matching_saved_session_without_mac(self) -> None:
        with self._tempdir() as temp_dir:
            repo_root = Path(temp_dir)
            session_dir = repo_root / ".er605_sessions" / "192-168-0-1-b8fbb32cd769"
            session_dir.mkdir(parents=True)
            (session_dir / "session.json").write_text(
                json.dumps(
                    {
                        "router_ip": "192.168.0.1",
                        "mac": "B8:FB:B3:2C:D7:69",
                    }
                ),
                encoding="utf-8",
            )

            resolved = resolve_cli_session_dir(repo_root, self._args(router_ip="192.168.0.1"), {})

            self.assertEqual(resolved, session_dir.resolve())

    def test_parser_defaults_to_resume(self) -> None:
        args = build_parser().parse_args([])

        self.assertEqual(args.command, "resume")


if __name__ == "__main__":
    unittest.main()
