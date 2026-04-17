from __future__ import annotations

import hashlib
import http.server
import json
import threading
import urllib.parse
from pathlib import Path

from er605_installer.core.state import BackupEntry


def md5_file(path: Path) -> str:
    digest = hashlib.md5()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_md5sums(text: str) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 2:
            raise ValueError(f"invalid md5sums line: {raw_line!r}")
        parsed[parts[-1]] = parts[0]
    return parsed


def verify_backup_dir(backup_dir: Path, md5_path: Path) -> dict[str, BackupEntry]:
    expected = parse_md5sums(md5_path.read_text(encoding="utf-8"))
    manifest: dict[str, BackupEntry] = {}
    missing = []
    mismatches = []
    for filename, expected_md5 in expected.items():
        file_path = backup_dir / filename
        if not file_path.exists():
            missing.append(filename)
            continue
        actual_md5 = md5_file(file_path)
        verified = actual_md5 == expected_md5
        if not verified:
            mismatches.append(filename)
        manifest[filename] = BackupEntry(
            filename=filename,
            size=file_path.stat().st_size,
            md5=actual_md5,
            verified=verified,
        )
    if missing or mismatches:
        problems = {"missing": missing, "mismatches": mismatches}
        raise ValueError(json.dumps(problems, indent=2))
    return manifest


class ManagedBackupReceiver:
    def __init__(self, host: str, output_dir: Path, port: int = 0, progress_callback=None):
        self.host = host
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._done = threading.Event()
        self._error: Exception | None = None
        self.received: dict[str, BackupEntry] = {}
        self.progress_callback = progress_callback
        outer = self

        class BackupUploadHandler(http.server.BaseHTTPRequestHandler):
            def log_message(self, format: str, *args) -> None:  # noqa: A003
                return

            def do_PUT(self) -> None:  # noqa: N802
                try:
                    outer._handle_upload(self)
                except Exception as exc:  # pragma: no cover - surfaced via join()
                    outer._error = exc
                    outer._done.set()
                    self.send_error(500, explain=str(exc))

        self._httpd = http.server.ThreadingHTTPServer((host, port), BackupUploadHandler)
        self.port = int(self._httpd.server_address[1])
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def join(self, timeout: float | None = None) -> None:
        self._done.wait(timeout=timeout)
        if self._error is not None:
            raise self._error

    def close(self) -> None:
        self._done.set()
        self._httpd.shutdown()
        self._httpd.server_close()
        self._thread.join(timeout=5)

    def _recv_file(self, handler: http.server.BaseHTTPRequestHandler, target: Path, size: int) -> BackupEntry:
        digest = hashlib.md5()
        received = 0
        with target.open("wb") as handle:
            while received < size:
                chunk = handler.rfile.read(min(65536, size - received))
                if not chunk:
                    raise ValueError(f"unexpected end of stream for {target.name}")
                handle.write(chunk)
                digest.update(chunk)
                received += len(chunk)
        return BackupEntry(filename=target.name, size=received, md5=digest.hexdigest(), verified=False)

    def _handle_upload(self, handler: http.server.BaseHTTPRequestHandler) -> None:
        filename = urllib.parse.unquote(handler.path.lstrip("/")).strip()
        if not filename or "/" in filename or "\\" in filename:
            handler.send_error(400, explain="invalid upload path")
            return
        content_length = handler.headers.get("Content-Length")
        if content_length is None:
            handler.send_error(411, explain="missing Content-Length")
            return
        try:
            size = int(content_length)
        except ValueError:
            handler.send_error(400, explain="invalid Content-Length")
            return
        entry = self._recv_file(handler, self.output_dir / filename, size)
        self.received[filename] = entry
        if self.progress_callback is not None:
            self.progress_callback(entry, len(self.received))
        if filename == "md5sums":
            self._done.set()
        handler.send_response(200)
        handler.end_headers()
