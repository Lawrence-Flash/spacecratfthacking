"""Teaching subset of a CCSDS space-packet primary header.

Field widths match the public primary header: version (3 bits), type (1),
secondary-header flag (1), APID (11), sequence flags (2), sequence count (14),
and packet data length (16). This module does not implement the Space Data
Link Security protocol and is not a flight or conformance product.
"""

from __future__ import annotations

import struct

SEQUENCE_MODULUS = 16384
UNSEGMENTED = 0b11


def build_primary_header(
    *,
    telemetry: bool,
    apid: int,
    sequence_count: int,
    data_length: int,
) -> str:
    """Return the 6-byte primary header as lowercase hex."""
    if not 0 <= apid <= 0x7FF:
        raise ValueError("APID must fit in 11 bits")
    if not 0 <= sequence_count < SEQUENCE_MODULUS:
        raise ValueError("sequence count must fit in 14 bits")
    if not 1 <= data_length <= 65536:
        raise ValueError("packet data length must be 1..65536 bytes")
    type_bit = 0 if telemetry else 1
    word0 = (type_bit << 12) | (1 << 11) | (apid & 0x7FF)
    word1 = (UNSEGMENTED << 14) | (sequence_count & 0x3FFF)
    word2 = (data_length - 1) & 0xFFFF
    return struct.pack(">HHH", word0, word1, word2).hex()


def parse_primary_header(header_hex: str) -> dict:
    """Decode a header produced by :func:`build_primary_header`."""
    raw = bytes.fromhex(header_hex)
    if len(raw) != 6:
        raise ValueError("primary header is 6 bytes")
    word0, word1, word2 = struct.unpack(">HHH", raw)
    type_bit = (word0 >> 12) & 0x1
    return {
        "version": (word0 >> 13) & 0x7,
        "packet_type": "TM" if type_bit == 0 else "TC",
        "secondary_header_flag": bool((word0 >> 11) & 0x1),
        "apid": word0 & 0x7FF,
        "sequence_flags": (word1 >> 14) & 0x3,
        "sequence_count": word1 & 0x3FFF,
        "packet_data_length": word2,
    }
