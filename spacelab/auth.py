"""Lab command authentication tags.

The tag is HMAC-SHA256 truncated to 128 bits over a canonical JSON document.
Truncation and the on-disk teaching key are lab choices so a detector can
recompute tags. They are not an implementation of CCSDS 355.0-B (SDLS) and
they are not a recommendation for flight.
"""

from __future__ import annotations

import hashlib
import hmac
import json

from spacelab.disclaimer import LAB_KEY_ID, LAB_MAC_KEY, MAC_ALGORITHM

AUTH_FIELDS = (
    "mission_id",
    "spacecraft_id",
    "apid",
    "sequence_count",
    "timestamp",
    "opcode",
    "mnemonic",
    "parameters",
    "key_id",
)


def canonical_material(command: dict) -> bytes:
    """Bytes covered by the lab MAC. Ground receipt time is intentionally absent."""
    missing = [name for name in AUTH_FIELDS if name not in command]
    if missing:
        raise ValueError(f"command is missing MAC fields: {', '.join(missing)}")
    body = {name: command[name] for name in AUTH_FIELDS}
    encoded = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return encoded.encode("utf-8")


def compute_mac(command: dict, key: bytes = LAB_MAC_KEY) -> str:
    digest = hmac.new(key, canonical_material(command), hashlib.sha256).hexdigest()
    return digest[:32]


def verify_mac(command: dict, key: bytes = LAB_MAC_KEY) -> bool:
    """Return True when key id and tag match the lab teaching key."""
    if command.get("key_id") != LAB_KEY_ID:
        return False
    presented = str(command.get("mac_hex", "")).lower()
    if len(presented) != 32:
        return False
    expected = compute_mac(command, key)
    return hmac.compare_digest(presented, expected)


def mac_metadata() -> dict:
    return {"key_id": LAB_KEY_ID, "mac_algorithm": MAC_ALGORITHM}
