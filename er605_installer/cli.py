from __future__ import annotations

import argparse
from pathlib import Path

from er605_installer.core.state import SessionStore
from er605_installer.core.workflow import Inputs, InstallerWorkflow, load_config, resolve_session_dir


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="er605-installer",
        description="Guarded host-side ER605 v2 OpenWrt installer with sensible defaults",
    )
    parser.add_argument("--config", help="Path to a TOML config file")
    parser.add_argument("--router-ip", help="Stock firmware IP address; defaults to saved or detected router")
    parser.add_argument("--username", help="Stock firmware GUI username; defaults to saved value or prompts with admin")
    parser.add_argument("--mac", help="Router MAC address; defaults to saved or ARP-discovered value")
    parser.add_argument("--host-ip", help="Host IP reachable from the router; defaults to the active local adapter")
    parser.add_argument("--firmware-version", help="Stock firmware version override, e.g. 2.2.5")
    parser.add_argument("--session-dir", help="Directory to store checkpoints and artifacts; defaults to the saved router session")
    parser.add_argument("--dry-run", action="store_true", help="Validate and print actions without changing router state")
    parser.add_argument(
        "--skip-openwrt-probe",
        action="store_true",
        help="Print manual network handoff steps instead of trying the OpenWrt web probe",
    )
    parser.add_argument(
        "command",
        nargs="?",
        default="resume",
        choices=("preflight", "backup", "verify-backup", "install-initramfs", "resume"),
        help="Step to run; defaults to resume, which continues from the saved checkpoint",
    )
    return parser


def merged_option(args: argparse.Namespace, config: dict, key: str) -> str:
    cli_value = getattr(args, key.replace("-", "_"), None)
    if cli_value:
        return str(cli_value)
    return str(config.get(key.replace("-", "_"), "") or "")


def discover_existing_session_dir(repo_root: Path) -> Path | None:
    sessions_root = repo_root / ".er605_sessions"
    if not sessions_root.exists():
        return None
    candidates = [
        path for path in sessions_root.iterdir()
        if path.is_dir() and (path / "session.json").exists()
    ]
    if not candidates:
        return None
    if len(candidates) == 1:
        return candidates[0].resolve()
    raise RuntimeError(
        "multiple saved sessions found; pass --session-dir or the original router identity flags"
    )


def _normalized_identity(value: str) -> str:
    return "".join(ch for ch in value if ch.isalnum()).lower()


def discover_matching_session_dir(repo_root: Path, router_ip: str, mac: str) -> Path | None:
    sessions_root = repo_root / ".er605_sessions"
    if not sessions_root.exists():
        return None
    normalized_mac = _normalized_identity(mac)
    matches: list[Path] = []
    for path in sessions_root.iterdir():
        if not path.is_dir() or not (path / "session.json").exists():
            continue
        state = SessionStore(path).load()
        matches_router = not router_ip or state.router_ip == router_ip
        matches_mac = not normalized_mac or _normalized_identity(state.mac) == normalized_mac
        if matches_router and matches_mac:
            matches.append(path.resolve())
    if not matches:
        return None
    if len(matches) == 1:
        return matches[0]
    raise RuntimeError(
        "multiple saved sessions match the supplied router identity; pass --session-dir to choose one"
    )


def resolve_cli_session_dir(repo_root: Path, args: argparse.Namespace, config: dict) -> Path:
    explicit = args.session_dir or config.get("session_dir")
    router_ip = merged_option(args, config, "router-ip")
    mac = merged_option(args, config, "mac")
    if explicit:
        return Path(explicit).expanduser().resolve()
    discovered_match = discover_matching_session_dir(repo_root, router_ip, mac)
    if discovered_match is not None:
        return discovered_match
    if not router_ip and not mac:
        discovered = discover_existing_session_dir(repo_root)
        if discovered is not None:
            return discovered
    return resolve_session_dir(
        repo_root=repo_root,
        explicit=None,
        router_ip=router_ip,
        mac=mac,
    )


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    repo_root = Path(__file__).resolve().parents[1]
    config_path = Path(args.config).expanduser().resolve() if args.config else None
    config = load_config(config_path)
    session_dir = resolve_cli_session_dir(repo_root, args, config)
    saved_state = SessionStore(session_dir).load()
    inputs = Inputs(
        router_ip=merged_option(args, config, "router-ip") or saved_state.router_ip,
        username=merged_option(args, config, "username") or saved_state.username,
        mac=merged_option(args, config, "mac") or saved_state.mac,
        host_ip=merged_option(args, config, "host-ip") or saved_state.host_ip,
        firmware_version=merged_option(args, config, "firmware-version") or saved_state.firmware_version,
        session_dir=session_dir,
        dry_run=bool(args.dry_run),
        skip_openwrt_probe=bool(args.skip_openwrt_probe),
    )
    workflow = InstallerWorkflow(
        repo_root=repo_root,
        session_store=SessionStore(session_dir),
        inputs=inputs,
    )
    commands = {
        "preflight": workflow.preflight,
        "backup": workflow.backup,
        "verify-backup": workflow.verify_backup,
        "install-initramfs": workflow.install_initramfs,
        "resume": workflow.resume,
    }
    commands[args.command]()
    return 0
