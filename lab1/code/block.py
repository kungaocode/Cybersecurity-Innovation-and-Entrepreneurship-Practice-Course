"""
Bitcoin Block Parser — byte-by-byte.

Parses a raw block hex string (as returned by ``getblock <hash> 0``)
into a structured dict.  Reuses ``TransactionParser`` for each
transaction embedded in the block body.
"""

import io
import struct
import json
from datetime import datetime, timezone
from typing import Optional

from crypto_utils import (
    read_varint,
    reverse_bytes,
    hex_reversed,
    double_sha256,
)
from transaction import TransactionParser


# ============================================================================
# Parser
# ============================================================================

class BlockParser:
    """Parse a raw Bitcoin block hex string.

    Parameters
    ----------
    raw_hex : str
        The raw block as a hex string.
    verbose : bool
        If True, print a detailed field-by-field breakdown during parsing.
    parse_all_txs: bool
        If True (the default), decode every transaction in the block body.
        Set to False when you only need the header (fast path).
    """

    def __init__(
        self,
        raw_hex: str,
        verbose: bool = True,
        parse_all_txs: bool = True,
    ):
        self.raw_hex: str = raw_hex.strip()
        self.raw_bytes: bytes = bytes.fromhex(self.raw_hex)
        self.verbose: bool = verbose
        self.parse_all_txs: bool = parse_all_txs
        self.cursor: int = 0

        self.result: dict = {}
        self.parse()

    # ------------------------------------------------------------------
    # Low-level readers (same pattern as TransactionParser)
    # ------------------------------------------------------------------

    def _read(self, n: int) -> bytes:
        data = self.raw_bytes[self.cursor : self.cursor + n]
        if len(data) < n:
            raise EOFError(
                f"Expected {n} bytes at offset {self.cursor}, "
                f"only {len(data)} available"
            )
        self.cursor += n
        return data

    def _read_le(self, fmt: str, size: int, label: str):
        data = self._read(size)
        value = struct.unpack(f"<{fmt}", data)[0]
        if self.verbose:
            print(f"  [{self.cursor - size:4d}–{self.cursor - 1:4d}]  "
                  f"{label:.<34s}  {data.hex()}  →  {value}")
        return value

    def _read_le_hex(self, size: int, label: str) -> str:
        """Read *size* bytes and return the raw hex (little-endian)."""
        data = self._read(size)
        if self.verbose:
            preview = data.hex() if size <= 32 else f"{data[:16].hex()}… ({size} bytes)"
            print(f"  [{self.cursor - size:4d}–{self.cursor - 1:4d}]  "
                  f"{label:.<34s}  {preview}")
        return data.hex()

    def _read_hash(self, label: str) -> str:
        """Read 32 bytes, reverse, return human-readable hex."""
        raw = self._read(32)
        human = reverse_bytes(raw).hex()
        if self.verbose:
            print(f"  [{self.cursor - 32:4d}–{self.cursor - 1:4d}]  "
                  f"{label:.<34s}  {raw.hex():.64s}… →  {human}")
        return human

    def _read_header_hash(self, label: str) -> str:
        """Read 32 bytes, reverse, return human-readable hex (short version)."""
        raw = self._read(32)
        human = reverse_bytes(raw).hex()
        if self.verbose:
            print(f"  [{self.cursor - 32:4d}–{self.cursor - 1:4d}]  "
                  f"{label:.<34s}  {human}")
        return human

    # ------------------------------------------------------------------
    # Main parser
    # ------------------------------------------------------------------

    def parse(self):
        if self.verbose:
            print("\n" + "=" * 70)
            print("  TASK 4: BYTE-BY-BYTE BLOCK PARSE")
            print("=" * 70)
            print(f"  Raw hex length: {len(self.raw_hex)} chars → {len(self.raw_bytes)} bytes\n")

        # Save the raw 80-byte header for hash verification later
        header_start = self.cursor

        # ---- Block Header (80 bytes) ----
        if self.verbose:
            print("  ── BLOCK HEADER (80 bytes) ──\n")

        version = self._read_le("I", 4, "Version")
        self.result["version"] = version

        prev_hash = self._read_header_hash("Previous Block Hash")
        self.result["previous_block_hash"] = prev_hash

        merkle_root = self._read_header_hash("Merkle Root")
        self.result["merkle_root"] = merkle_root

        timestamp = self._read_le("I", 4, "Timestamp")
        self.result["timestamp"] = timestamp
        ts_human = datetime.fromtimestamp(timestamp, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        if self.verbose:
            print(f"  {'':34s}  {'':34s}  →  {ts_human}")

        bits = self._read_le("I", 4, "Bits (nBits / target)")
        self.result["bits"] = bits
        target = _bits_to_target(bits)
        difficulty = _bits_to_difficulty(bits)
        if self.verbose:
            print(f"  {'':34s}  {'Target':.<34s}  →  0x{target:064x}")
            print(f"  {'':34s}  {'Difficulty':.<34s}  →  {difficulty:.6f}")

        nonce = self._read_le("I", 4, "Nonce")
        self.result["nonce"] = nonce

        # Extract the 80-byte header for hash verification
        header_bytes = self.raw_bytes[header_start : header_start + 80]
        self.result["_header_hex"] = header_bytes.hex()  # raw LE hex for verify.py
        computed_block_hash = reverse_bytes(double_sha256(header_bytes)).hex()
        self.result["_computed_block_hash"] = computed_block_hash  # set by caller after fetch

        if self.verbose:
            print(f"\n  Header done: {self.cursor - header_start} bytes parsed.\n")

        # ---- Transaction Count ----
        tx_count = read_varint(self.raw_bytes, self.cursor)
        if self.verbose:
            raw_varint = self.raw_bytes[self.cursor : self.cursor + (3 if tx_count[1] >= 3 else 1)]
            self.cursor_copy = self.cursor
        value, consumed = tx_count
        data = self._read(consumed)
        self.result["transaction_count"] = value
        if self.verbose:
            print(f"  [{self.cursor - consumed:4d}–{self.cursor - 1:4d}]  "
                  f"{'Transaction count':.<34s}  {data.hex()}  →  {value}\n")

        # ---- Transactions ----
        tx_list = []
        for i in range(value):
            if self.verbose:
                print(f"\n  {'─' * 50}")
                print(f"  TRANSACTION #{i}  (offset {self.cursor})")
                print(f"  {'─' * 50}")
            elif i % 100 == 0:
                print(f"  Parsing transaction {i + 1}/{value}…")

            # Find this transaction's end by parsing it incrementally.
            # We feed the remaining bytes to TransactionParser.
            tx_start = self.cursor
            remaining = self.raw_bytes[tx_start:]

            # Parse this one transaction
            tx_hex = None
            try:
                parser = TransactionParser(remaining.hex(), verbose=self.verbose)
                tx_dict = parser.to_dict()
                tx_dict["_offset"] = tx_start
                # Compute TxID for Merkle tree verification
                tx_dict["txid"] = parser.compute_txid()
                tx_list.append(tx_dict)
                self.cursor = tx_start + parser.cursor  # advance past this tx
            except Exception as e:
                print(f"  ⚠ Failed to parse tx #{i} at offset {tx_start}: {e}")
                # Best-effort: skip
                break

        self.result["transactions"] = tx_list

        if self.verbose:
            print("\n" + "─" * 70)
            print(f"  Parsed {self.cursor} of {len(self.raw_bytes)} bytes")
            if self.cursor == len(self.raw_bytes):
                print("  ✓ All bytes consumed — block parse is consistent.")
            else:
                print(f"  ⚠ {len(self.raw_bytes) - self.cursor} byte(s) remaining.")
            print(f"\n  Summary: version={version}, {len(tx_list)} tx(s), "
                  f"nonce={nonce}")
            print("=" * 70 + "\n")

    # ------------------------------------------------------------------
    # Output
    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        return dict(self.result)

    def to_json(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.result, f, indent=2, ensure_ascii=False)
        print(f"✓ Block parse saved to {path}")

    def generate_latex_tables(self) -> str:
        """Return LaTeX source for the block header fields."""
        from datetime import datetime, timezone

        ts = self.result.get("timestamp", 0)
        ts_human = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        target = _bits_to_target(self.result.get("bits", 0))
        diff = _bits_to_difficulty(self.result.get("bits", 0))

        lines = []
        lines.append("\\subsection*{Block Header}")
        lines.append("\\begin{tabular}{@{}lll@{}} \\toprule")
        lines.append("Field & Bytes & Value \\\\ \\midrule")
        lines.append(f"Version & 4 & {self.result.get('version', '?')} \\\\")
        lines.append(
            f"Previous Block Hash & 32 & \\texttt{{{self.result.get('previous_block_hash', '?')}}} \\\\"
        )
        lines.append(
            f"Merkle Root & 32 & \\texttt{{{self.result.get('merkle_root', '?')}}} \\\\"
        )
        lines.append(f"Timestamp & 4 & {ts} ({ts_human}) \\\\")
        lines.append(
            f"Bits & 4 & {self.result.get('bits', '?')} "
            f"(target: \\texttt{{0x{target:064x}}}) \\\\"
        )
        lines.append(f"Nonce & 4 & {self.result.get('nonce', '?')} \\\\")
        lines.append("\\bottomrule \\end{tabular}")
        lines.append(f"\nDifficulty: {diff:.6f}")
        lines.append(
            f"\nBlock Hash (computed): \\texttt{{{self.result.get('_computed_block_hash', '?')}}}"
        )
        return "\n".join(lines)


# ============================================================================
# Target / Difficulty arithmetic
# ============================================================================

def _bits_to_target(bits: int) -> int:
    """Convert the compact ``nBits`` value to a 256-bit target.

    The first byte of *bits* is the exponent; the remaining three bytes
    are the coefficient (mantissa).
    """
    exponent = (bits >> 24) & 0xFF
    coefficient = bits & 0x00FFFFFF
    if coefficient == 0:
        return 0
    return coefficient << (8 * (exponent - 3))


def _bits_to_difficulty(bits: int) -> float:
    """Return the mining difficulty from the ``nBits`` compact target.

    Difficulty = genesis_target / current_target, where genesis_target
    is the target encoded by ``0x1d00ffff`` (Bitcoin mainnet).
    """
    # Genesis nBits for mainnet (and testnet)
    GENESIS_BITS = 0x1D00FFFF
    genesis_target = _bits_to_target(GENESIS_BITS)
    current_target = _bits_to_target(bits)
    if current_target == 0:
        return float("inf")
    return genesis_target / current_target
