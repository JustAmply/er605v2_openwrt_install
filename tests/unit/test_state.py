import unittest
from pathlib import Path
import shutil
import uuid

from er605_installer.core.state import BackupEntry, SessionState, SessionStore


class StateTests(unittest.TestCase):
    def _tempdir(self):
        root = Path.cwd() / ".test_tmp"
        root.mkdir(exist_ok=True)
        case_dir = root / f"state-{uuid.uuid4().hex}"
        case_dir.mkdir()
        class _TempDir:
            def __enter__(self_inner):
                return str(case_dir)
            def __exit__(self_inner, exc_type, exc, tb):
                shutil.rmtree(case_dir, ignore_errors=True)
        return _TempDir()

    def test_session_round_trip_preserves_manifest(self) -> None:
        with self._tempdir() as temp_dir:
            store = SessionStore(Path(temp_dir))
            state = SessionState(router_ip="192.168.0.1", username="justus", mac="AA:BB:CC:DD:EE:FF")
            state.backup_manifest["mtd0.backup"] = BackupEntry(
                filename="mtd0.backup",
                size=4,
                md5="abcd",
                verified=True,
            )
            store.save(state)
            loaded = store.load()
            self.assertEqual(loaded.router_ip, "192.168.0.1")
            self.assertTrue(loaded.backup_manifest["mtd0.backup"].verified)


if __name__ == "__main__":
    unittest.main()
