from __future__ import annotations

import hashlib


def normalize_mac(mac: str) -> str:
    compact = "".join(ch for ch in mac if ch.isalnum()).upper()
    if len(compact) != 12 or any(ch not in "0123456789ABCDEF" for ch in compact):
        raise ValueError(f"invalid MAC address: {mac!r}")
    return ":".join(compact[index : index + 2] for index in range(0, 12, 2))


def _md5_prefix(value: str) -> str:
    return hashlib.md5(value.encode("utf-8")).hexdigest()[:16]


def derive_passwords(mac: str, username: str) -> dict[str, str]:
    normalized_mac = normalize_mac(mac)
    return {
        "normalized_mac": normalized_mac,
        "root_password": _md5_prefix(normalized_mac + username),
        "debug_password": _md5_prefix(normalized_mac + "admin" + normalized_mac + "admin"),
    }
