"""
Bitcoin Script decoder.

Decodes scriptSig and scriptPubKey byte sequences into human-readable
descriptions.  This is a simplified decoder — it handles the common
patterns seen in practice (P2PKH, P2SH, P2WPKH, OP_RETURN, multisig)
and falls back to a hex dump with opcode annotations for anything exotic.
"""

from typing import List, Tuple, Optional

from config import OPCODE_NAMES
from crypto_utils import hash160


# ============================================================================
# Byte → opcode helpers
# ============================================================================

def _opcode_name(op: int) -> str:
    """Return a human-readable name for opcode byte *op*."""
    if op in OPCODE_NAMES:
        return OPCODE_NAMES[op]
    if 0x01 <= op <= 0x4b:
        return f"OP_PUSHDATA{op}"  # push op bytes
    return f"OP_UNKNOWN_{op:02x}"


def _parse_script_chunks(script: bytes) -> List[Tuple[str, bytes, int]]:
    r"""Split *script* into ``(mnemonic, data, offset)`` chunks.

    Each chunk is one opcode or one push-data element.
    """
    chunks: List[Tuple[str, bytes, int]] = []
    i = 0
    while i < len(script):
        op = script[i]
        start = i
        if op == 0x00:
            chunks.append(("OP_0", b"", start))
            i += 1
        elif 0x01 <= op <= 0x4b:
            # OP_PUSHDATA<N>: next N bytes are data
            n = op
            data = script[i + 1 : i + 1 + n]
            chunks.append((_opcode_name(op), data, start))
            i += 1 + n
        elif op == 0x4c:  # OP_PUSHDATA1
            n = script[i + 1]
            data = script[i + 2 : i + 2 + n]
            chunks.append(("OP_PUSHDATA1", data, start))
            i += 2 + n
        elif op == 0x4d:  # OP_PUSHDATA2
            n = int.from_bytes(script[i + 1 : i + 3], "little")
            data = script[i + 3 : i + 3 + n]
            chunks.append(("OP_PUSHDATA2", data, start))
            i += 3 + n
        else:
            chunks.append((_opcode_name(op), b"", start))
            i += 1
    return chunks


# ============================================================================
# Script type classification
# ============================================================================

class ScriptInfo:
    """Decoded script information."""

    def __init__(
        self,
        script_hex: str,
        script_type: str,
        description: str,
        addresses: Optional[List[str]] = None,
        chunks: Optional[List[dict]] = None,
    ):
        self.hex = script_hex
        self.type = script_type
        self.description = description
        self.addresses = addresses or []
        self.chunks = chunks or []

    def to_dict(self) -> dict:
        return {
            "hex": self.hex,
            "type": self.type,
            "description": self.description,
            "addresses": self.addresses,
            "asm": " ".join(c["mnemonic"] for c in self.chunks),
        }


def decode_script(script_hex: str) -> ScriptInfo:
    """Decode a serialised Bitcoin script (scriptSig or scriptPubKey).

    Parameters
    ----------
    script_hex : str
        The hex-encoded script bytes.

    Returns
    -------
    ScriptInfo
    """
    if not script_hex:
        return ScriptInfo(script_hex, "empty", "(empty script)", [])

    raw = bytes.fromhex(script_hex)
    chunks = _parse_script_chunks(raw)

    chunk_dicts = [
        {"mnemonic": m, "data_hex": d.hex() if d else "", "offset": o}
        for m, d, o in chunks
    ]

    # --- Classify scriptPubKey patterns ---
    # P2PKH: OP_DUP OP_HASH160 <20-byte pubkey hash> OP_EQUALVERIFY OP_CHECKSIG
    if (
        len(chunks) == 5
        and chunks[0][0] == "OP_DUP"
        and chunks[1][0] == "OP_HASH160"
        and len(chunks[2][1]) == 20
        and chunks[3][0] == "OP_EQUALVERIFY"
        and chunks[4][0] == "OP_CHECKSIG"
    ):
        pkh = chunks[2][1].hex()
        return ScriptInfo(
            script_hex, "P2PKH",
            f"Pay-to-Public-Key-Hash → address {_testnet_p2pkh_address(pkh)}",
            addresses=[_testnet_p2pkh_address(pkh)],
            chunks=chunk_dicts,
        )

    # P2SH: OP_HASH160 <20-byte script hash> OP_EQUAL
    if (
        len(chunks) == 3
        and chunks[0][0] == "OP_HASH160"
        and len(chunks[1][1]) == 20
        and chunks[2][0] == "OP_EQUAL"
    ):
        sh = chunks[1][1].hex()
        return ScriptInfo(
            script_hex, "P2SH",
            f"Pay-to-Script-Hash → address {_testnet_p2sh_address(sh)}",
            addresses=[_testnet_p2sh_address(sh)],
            chunks=chunk_dicts,
        )

    # P2WPKH (v0): OP_0 <20-byte pubkey hash>
    if (
        len(chunks) == 2
        and chunks[0][0] == "OP_0"
        and len(chunks[1][1]) == 20
    ):
        pkh = chunks[1][1].hex()
        return ScriptInfo(
            script_hex, "P2WPKH",
            f"Pay-to-Witness-Public-Key-Hash (native segwit v0) → address {_testnet_bech32_address(pkh, version=0)}",
            addresses=[_testnet_bech32_address(pkh, version=0)],
            chunks=chunk_dicts,
        )

    # P2WSH (v0): OP_0 <32-byte script hash>
    if (
        len(chunks) == 2
        and chunks[0][0] == "OP_0"
        and len(chunks[1][1]) == 32
    ):
        return ScriptInfo(
            script_hex, "P2WSH",
            "Pay-to-Witness-Script-Hash (native segwit v0, 32-byte hash)",
            chunks=chunk_dicts,
        )

    # OP_RETURN
    if chunks and chunks[0][0] == "OP_RETURN":
        payload = b"".join(d for _, d, _ in chunks[1:])
        try:
            msg = payload.decode("utf-8")
        except UnicodeDecodeError:
            msg = payload.hex()
        return ScriptInfo(
            script_hex, "OP_RETURN",
            f"Provably unspendable output (data: {msg})",
            chunks=chunk_dicts,
        )

    # Multisig (heuristic): ends with OP_CHECKMULTISIG
    if chunks and chunks[-1][0] == "OP_CHECKMULTISIG":
        return ScriptInfo(
            script_hex, "multisig",
            "Multi-signature script",
            chunks=chunk_dicts,
        )

    # --- Classify scriptSig patterns ---
    # Typical P2PKH scriptSig: <sig> <pubkey>
    if len(chunks) == 2 and len(chunks[0][1]) > 0 and len(chunks[1][1]) > 0:
        return ScriptInfo(
            script_hex, "scriptSig (P2PKH)",
            "Signature + Public Key (unlocking P2PKH output)",
            chunks=chunk_dicts,
        )

    return ScriptInfo(script_hex, "generic", f"Generic script ({len(raw)} bytes)", chunks=chunk_dicts)


# ============================================================================
# Address derivation (simplified — base58 / bech32 are complex; we cheat
# by using bitcoinlib for the actual encoding, but document the algorithm).
# ============================================================================

def _testnet_p2pkh_address(pubkey_hash_hex: str) -> str:
    """Derive a Testnet P2PKH address from a 20-byte pubkey hash.

    Algorithm: ``base58check(0x6f || pubkey_hash)``
    """
    from bitcoinlib.encoding import pubkeyhash_to_addr_base58
    return pubkeyhash_to_addr_base58(
        bytes.fromhex(pubkey_hash_hex), prefix=b"\x6f"
    )


def _testnet_p2sh_address(script_hash_hex: str) -> str:
    """Derive a Testnet P2SH address from a 20-byte script hash.

    Algorithm: ``base58check(0xc4 || script_hash)``
    """
    from bitcoinlib.encoding import pubkeyhash_to_addr_base58
    return pubkeyhash_to_addr_base58(
        bytes.fromhex(script_hash_hex), prefix=b"\xc4"
    )


def _testnet_bech32_address(pubkey_hash_hex: str, version: int = 0) -> str:
    """Derive a Testnet bech32 address from a pubkey hash."""
    from bitcoinlib.encoding import pubkeyhash_to_addr_bech32
    return pubkeyhash_to_addr_bech32(
        bytes.fromhex(pubkey_hash_hex), prefix="tb", witver=version
    )
