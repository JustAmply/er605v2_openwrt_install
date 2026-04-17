import http.client
import shutil
import threading
import unittest
import uuid
from pathlib import Path

from er605_installer.core.backup import ManagedBackupReceiver


class BackupReceiverTests(unittest.TestCase):
    def _tempdir(self):
        root = Path.cwd() / ".test_tmp"
        root.mkdir(exist_ok=True)
        case_dir = root / f"backup-{uuid.uuid4().hex}"
        case_dir.mkdir()

        class _TempDir:
            def __enter__(self_inner):
                return str(case_dir)

            def __exit__(self_inner, exc_type, exc, tb):
                shutil.rmtree(case_dir, ignore_errors=True)

        return _TempDir()

    def test_receiver_accepts_http_put_uploads(self) -> None:
        with self._tempdir() as temp_dir:
            output_dir = Path(temp_dir) / "backup"
            progress = []
            receiver = ManagedBackupReceiver("127.0.0.1", output_dir, progress_callback=lambda entry, count: progress.append((entry.filename, count)))
            receiver.start()
            try:
                def upload(name: str, payload: bytes) -> None:
                    conn = http.client.HTTPConnection("127.0.0.1", receiver.port, timeout=5)
                    conn.request(
                        "PUT",
                        f"/{name}",
                        body=payload,
                        headers={"Content-Length": str(len(payload))},
                    )
                    response = conn.getresponse()
                    self.assertEqual(response.status, 200)
                    response.read()
                    conn.close()

                upload("mtd0_Test.backup", b"data")
                upload("md5sums", b"8d777f385d3dfec8815d20f7496026dc\tmtd0_Test.backup\n")
                receiver.join(timeout=5)
            finally:
                receiver.close()

            self.assertEqual((output_dir / "mtd0_Test.backup").read_bytes(), b"data")
            self.assertEqual(progress[-1], ("md5sums", 2))


if __name__ == "__main__":
    unittest.main()
