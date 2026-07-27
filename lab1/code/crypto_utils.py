"""
Bitcoin cryptographic utilities.

Implements the hashing and encoding primitives used by the Bitcoin protocol
so that the parser does not depend on any Bitcoin-specific library.

Every function includes a docstring explaining *why* Bitcoin uses that
particular primitive (design rationale, not just mechanics).
"""

import hashlib
import struct
from typing import Tuple


# ============================================================================
# Hashing
# ============================================================================

def double_sha256(data: bytes) -> bytes:
    """Return SHA-256(SHA-256(data)).

    Bitcoin uses double SHA-256 (often written ``dSHA256``) almost everywhere:
    TxIDs, Block Hashes, Merkle roots, checksums.  Satoshi chose this to
    mitigate length-extension attacks — a single SHA-256 is vulnerable to
    them, and while the risk in Bitcoin's specific constructions is debatable,
    the double hash adds a layer of defence at negligible cost.
    """
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def hash160(data: bytes) -> bytes:
    """Return RIPEMD-160(SHA-256(data)), a.k.a. ``HASH160``.

    Bitcoin uses this to produce 20-byte address payloads from public keys
    (P2PKH, P2SH, P2WPKH).  SHA-256 first (for collision resistance), then
    RIPEMD-160 (for compactness — 20 bytes fits nicely into a 25-byte
    base58-check address with 4-byte checksum).
    """
    return hashlib.new("ripemd160", hashlib.sha256(data).digest()).digest()


# ============================================================================
# Byte wrangling
# ============================================================================

def reverse_bytes(data: bytes) -> bytes:
    """Return the byte-reversed copy of *data*.

    Bitcoin serialises 256-bit hashes in **internal byte order** (little-endian
    by dword), but human-readable explorers show them in **RPC byte order**
    (big-endian).  Converting between the two means reversing the 32 bytes.
    """
    return data[::-1]


def hex_reversed(hex_str: str) -> str:
    """Given a hex string in internal byte order, return RPC (human) order."""
    return reverse_bytes(bytes.fromhex(hex_str)).hex()


def hex_be_to_le(hex_str: str) -> str:
    """Convert a big-endian hex string to little-endian (for TX fields)."""
    b = bytes.fromhex(hex_str)
    return b[::-1].hex()


# ============================================================================
# Compact-size unsigned integer (a.k.a. "varint")
# ============================================================================

def read_varint(data: bytes, offset: int = 0) -> Tuple[int, int]:
    r"""Decode a Bitcoin compact-size integer starting at *offset*.

    Returns ``(value, bytes_consumed)``.

    Encoding (from the protocol spec)::

        < 0xfd       → 1-byte  uint8
        = 0xfd       → 1-byte  marker + 2-byte uint16 LE
        = 0xfe       → 1-byte  marker + 4-byte uint32 LE
        = 0xff       → 1-byte  marker + 8-byte uint64 LE

    Bitcoin uses this to encode counts (input count, output count,
    script length, transaction count in a block) compactly — most
    real-world values fit in a single byte.
    """
    first = data[offset]
    if first < 0xFD:
        return first, 1
    if first == 0xFD:
        return struct.unpack_from("<H", data, offset + 1)[0], 3
    if first == 0xFE:
        return struct.unpack_from("<I", data, offset + 1)[0], 5
    # first == 0xFF
    return struct.unpack_from("<Q", data, offset + 1)[0], 9


def encode_varint(value: int) -> bytes:
    """Encode *value* as a Bitcoin compact-size integer."""
    if value < 0xFD:
        return struct.pack("<B", value)
    if value <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", value)
    if value <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", value)
    return b"\xff" + struct.pack("<Q", value)


# ============================================================================
# Formatting helpers
# ============================================================================

def format_satoshis(sats: int) -> str:
    """Return a human-readable BTC string from a satoshi count."""
    return f"{sats / 100_000_000:,.8f} BTC"


def hex_byte_by_byte(hex_str: str, group: int = 2) -> str:
    """Return *hex_str* with spaces between every *group* hex chars."""
    return " ".join(
        hex_str[i : i + group] for i in range(0, len(hex_str), group)
    )


def describe_bytes(data: bytes, max_len: int = 64) -> str:
    """Return a compact description: hex + ASCII preview for short blobs."""
    if len(data) <= max_len:
        return data.hex()
    return f"{data[:max_len].hex()}… ({len(data)} bytes total)"
