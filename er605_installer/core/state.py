from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path


def utcnow() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


@dataclass
class BackupEntry:
    filename: str
    size: int
    md5: str
    verified: bool = False


@dataclass
class SessionState:
    schema_version: int = 1
    created_at: str = field(default_factory=utcnow)
    updated_at: str = field(default_factory=utcnow)
    router_ip: str = ""
    username: str = ""
    mac: str = ""
    host_ip: str = ""
    firmware_version: str = ""
    hardware_model: str = ""
    stock_banner: str = ""
    root_password: str = ""
    debug_password: str = ""
    checkpoints: dict[str, bool] = field(
        default_factory=lambda: {
            "preflight_completed": False,
            "backup_verified": False,
            "initramfs_transferred": False,
            "initramfs_installed": False,
            "openwrt_probe_succeeded": False,
        }
    )
    backup_manifest: dict[str, BackupEntry] = field(default_factory=dict)

    def update_timestamp(self) -> None:
        self.updated_at = utcnow()

    @classmethod
    def from_dict(cls, payload: dict) -> "SessionState":
        manifest = {
            name: BackupEntry(**entry)
            for name, entry in payload.get("backup_manifest", {}).items()
        }
        checkpoints = {
            "preflight_completed": False,
            "backup_verified": False,
            "initramfs_transferred": False,
            "initramfs_installed": False,
            "openwrt_probe_succeeded": False,
        }
        checkpoints.update(payload.get("checkpoints", {}))
        return cls(
            schema_version=payload.get("schema_version", 1),
            created_at=payload.get("created_at", utcnow()),
            updated_at=payload.get("updated_at", utcnow()),
            router_ip=payload.get("router_ip", ""),
            username=payload.get("username", ""),
            mac=payload.get("mac", ""),
            host_ip=payload.get("host_ip", ""),
            firmware_version=payload.get("firmware_version", ""),
            hardware_model=payload.get("hardware_model", ""),
            stock_banner=payload.get("stock_banner", ""),
            root_password=payload.get("root_password", ""),
            debug_password=payload.get("debug_password", ""),
            checkpoints=checkpoints,
            backup_manifest=manifest,
        )

    def to_dict(self) -> dict:
        payload = asdict(self)
        payload["backup_manifest"] = {
            name: asdict(entry) for name, entry in self.backup_manifest.items()
        }
        return payload


class SessionStore:
    def __init__(self, session_dir: Path):
        self.session_dir = session_dir
        self.backup_dir = session_dir / "backup"
        self.logs_dir = session_dir / "logs"
        self.state_path = session_dir / "session.json"
        self.manifest_path = session_dir / "backup_manifest.json"
        self.recovery_notes_path = session_dir / "RECOVERY_NOTES.txt"
        self.known_hosts_path = session_dir / "known_hosts"

    def ensure_layout(self) -> None:
        self.session_dir.mkdir(parents=True, exist_ok=True)
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        self.logs_dir.mkdir(parents=True, exist_ok=True)

    def load(self) -> SessionState:
        if not self.state_path.exists():
            return SessionState()
        return SessionState.from_dict(json.loads(self.state_path.read_text(encoding="utf-8")))

    def save(self, state: SessionState) -> None:
        self.ensure_layout()
        state.update_timestamp()
        self.state_path.write_text(
            json.dumps(state.to_dict(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        self.manifest_path.write_text(
            json.dumps(
                {name: asdict(entry) for name, entry in state.backup_manifest.items()},
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )

    def write_transcript(self, action: str, content: str) -> Path:
        self.ensure_layout()
        filename = f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{action}.log"
        target = self.logs_dir / filename
        target.write_text(content, encoding="utf-8")
        return target
