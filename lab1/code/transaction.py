"""
Bitcoin Transaction Parser — byte-by-byte.

Parses a raw transaction hex string into a structured dict, printing a
human-readable breakdown of every field along the way.  All parsing is
done manually — no Bitcoin library is used for the parsing logic.
"""

import io
import struct
import json
from typing import Optional

from crypto_utils import read_varint, reverse_bytes, hex_reversed, format_satoshis
from script import decode_script


# ============================================================================
# Parser
# ============================================================================

class TransactionParser:
    """Parse a raw Bitcoin transaction hex string.

    Parameters
    ----------
    raw_hex : str
        The raw transaction as a hex string (as returned by getrawtransaction).
    verbose : bool
        If True, print a detailed field-by-field breakdown during parsing.
    """

    def __init__(self, raw_hex: str, verbose: bool = True):
        self.raw_hex: str = raw_hex.strip()
        self.raw_bytes: bytes = bytes.fromhex(self.raw_hex)
        self.verbose: bool = verbose
        self.cursor: int = 0

        self.result: dict = {}       # accumulated parsed fields
        self.parse()

    # ------------------------------------------------------------------
    # Low-level readers
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

    def _read_le(self, fmt: str, size: int, label: str) -> int:
        """Read *size* bytes, unpack as little-endian *fmt*, and print."""
        data = self._read(size)
        value = struct.unpack(f"<{fmt}", data)[0]
        if self.verbose:
            print(f"  [{self.cursor - size:4d}–{self.cursor - 1:4d}]  "
                  f"{label:.<30s}  {data.hex()}  →  {value}")
        return value

    def _read_varint(self, label: str) -> int:
        value, consumed = read_varint(self.raw_bytes, self.cursor)
        data = self._read(consumed)
        if self.verbose:
            print(f"  [{self.cursor - consumed:4d}–{self.cursor - 1:4d}]  "
                  f"{label:.<30s}  {data.hex()}  →  {value}")
        return value

    def _read_hash(self, label: str) -> str:
        """Read 32 bytes, reverse, and return as a human-readable hex TxID."""
        raw = self._read(32)
        human = reverse_bytes(raw).hex()
        if self.verbose:
            print(f"  [{self.cursor - 32:4d}–{self.cursor - 1:4d}]  "
                  f"{label:.<30s}  {raw.hex()}  →  {human}")
        return human

    def _read_bytes_hex(self, n: int, label: str) -> str:
        data = self._read(n)
        if self.verbose:
            preview = data.hex() if n <= 32 else f"{data[:16].hex()}… ({n} bytes)"
            print(f"  [{self.cursor - n:4d}–{self.cursor - 1:4d}]  "
                  f"{label:.<30s}  {preview}")
        return data.hex()

    def _read_witness(self):
        """Parse segwit witness stack for each input (if marker present)."""
        if self.verbose:
            print("\n  --- Witness Data (SegWit) ---")

        witness_data = []
        for i in range(self.result["input_count"]):
            n_items = self._read_varint(f"  witness[{i}] stack items")
            items = []
            for j in range(n_items):
                item_len = self._read_varint(f"    item[{j}] length")
                item_data = self._read_bytes_hex(item_len, f"    item[{j}] data")
                items.append({"length": item_len, "data": item_data})
            witness_data.append({"index": i, "stack_items": n_items, "items": items})

        self.result["witness"] = witness_data

    # ------------------------------------------------------------------
    # Main parser
    # ------------------------------------------------------------------

    def parse(self):
        if self.verbose:
            print("\n" + "=" * 70)
            print("  TASK 3: BYTE-BY-BYTE TRANSACTION PARSE")
            print("=" * 70)
            print(f"  Raw hex length: {len(self.raw_hex)} chars → {len(self.raw_bytes)} bytes\n")

        # ---- Version ----
        self.result["version"] = self._read_le("I", 4, "Version")

        # ---- SegWit marker & flag ----
        # If the next two bytes are 0x00 0x01, this is a segwit transaction.
        peek = self.raw_bytes[self.cursor : self.cursor + 2]
        is_segwit = peek == b"\x00\x01"
        if is_segwit:
            marker = self._read(1)
            flag = self._read(1)
            if self.verbose:
                print(f"  [{self.cursor - 2:4d}–{self.cursor - 1:4d}]  "
                      f"{'SegWit marker + flag':.<30s}  {marker.hex()}{flag.hex()}  →  segwit tx")
            self.result["segwit_marker"] = marker.hex()
            self.result["segwit_flag"] = flag.hex()

        # ---- Inputs ----
        input_count = self._read_varint("Input count")
        self.result["input_count"] = input_count
        inputs = []

        for i in range(input_count):
            if self.verbose:
                print(f"\n  ── Input #{i} ──")
            inp = {}

            # Previous Transaction Hash (byte-reversed → human TxID)
            inp["prev_txid"] = self._read_hash(f"  inp[{i}] Prev TxID")

            # Previous output index
            inp["prev_output_index"] = self._read_le("I", 4, f"  inp[{i}] Output index")

            # scriptSig
            script_len = self._read_varint(f"  inp[{i}] scriptSig length")
            inp["scriptSig_len"] = script_len
            script_hex = self._read_bytes_hex(script_len, f"  inp[{i}] scriptSig")
            inp["scriptSig"] = script_hex
            inp["scriptSig_decoded"] = decode_script(script_hex).to_dict()

            # Sequence
            inp["sequence"] = self._read_le("I", 4, f"  inp[{i}] Sequence")
            # Sequence interpretation
            seq_meaning = _interpret_sequence(inp["sequence"])
            if self.verbose and seq_meaning:
                print(f"  {'':34s}  {'':30s}  →  {seq_meaning}")

            inputs.append(inp)

        self.result["inputs"] = inputs

        # ---- Outputs ----
        output_count = self._read_varint("Output count")
        self.result["output_count"] = output_count
        outputs = []

        for i in range(output_count):
            if self.verbose:
                print(f"\n  ── Output #{i} ──")
            out = {}

            # Amount (satoshis, 8-byte little-endian)
            sats = self._read_le("Q", 8, f"  out[{i}] Amount (sat)")
            out["amount_satoshis"] = sats
            if self.verbose:
                print(f"  {'':34s}  {'':30s}  →  {format_satoshis(sats)}")

            # scriptPubKey
            spk_len = self._read_varint(f"  out[{i}] scriptPubKey length")
            out["scriptPubKey_len"] = spk_len
            spk_hex = self._read_bytes_hex(spk_len, f"  out[{i}] scriptPubKey")
            out["scriptPubKey"] = spk_hex
            decoded = decode_script(spk_hex)
            out["scriptPubKey_decoded"] = decoded.to_dict()
            if self.verbose:
                print(f"  {'':34s}  {'Script type':.<30s}  →  {decoded.type}")
                print(f"  {'':34s}  {'Description':.<30s}  →  {decoded.description}")

            outputs.append(out)

        self.result["outputs"] = outputs

        # ---- Witness (segwit only) ----
        if is_segwit:
            self._read_witness()

        # ---- Locktime ----
        self.result["locktime"] = self._read_le("I", 4, "Locktime")
        lt = self.result["locktime"]
        if self.verbose:
            if lt == 0:
                print(f"  {'':34s}  {'':30s}  →  (no locktime)")
            elif lt < 500_000_000:
                print(f"  {'':34s}  {'':30s}  →  block height {lt}")
            else:
                print(f"  {'':34s}  {'':30s}  →  UNIX timestamp {lt}")

        if self.verbose:
            print("\n" + "─" * 70)
            print(f"  Parsed {self.cursor} of {len(self.raw_bytes)} bytes")
            if self.cursor == len(self.raw_bytes):
                print("  ✓ All bytes consumed — parse is consistent.")
            else:
                remaining = len(self.raw_bytes) - self.cursor
                print(f"  ⚠ {remaining} byte(s) remaining (possibly unexpected).")
            print("=" * 70 + "\n")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        return dict(self.result)

    def to_json(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.result, f, indent=2, ensure_ascii=False)
        print(f"✓ Transaction parse saved to {path}")

    def compute_txid(self) -> str:
        """Compute the Bitcoin TxID for this transaction.

        For SegWit transactions the TxID is computed from the transaction
        WITHOUT witness data (the marker, flag, and witness stack are
        excluded).  We reconstruct the non-witness serialisation from the
        parsed fields.
        """
        import struct
        from crypto_utils import encode_varint, double_sha256, reverse_bytes

        parts: list[bytes] = []

        # Version (4 bytes, little-endian)
        parts.append(struct.pack("<I", self.result["version"]))

        # Inputs
        parts.append(encode_varint(self.result["input_count"]))
        for inp in self.result["inputs"]:
            # Previous TxID (32 bytes, reversed to internal order)
            parts.append(reverse_bytes(bytes.fromhex(inp["prev_txid"])))
            # Output index (4 bytes LE)
            parts.append(struct.pack("<I", inp["prev_output_index"]))
            # scriptSig
            sig_bytes = bytes.fromhex(inp["scriptSig"])
            parts.append(encode_varint(len(sig_bytes)))
            parts.append(sig_bytes)
            # Sequence
            parts.append(struct.pack("<I", inp["sequence"]))

        # Outputs
        parts.append(encode_varint(self.result["output_count"]))
        for out in self.result["outputs"]:
            parts.append(struct.pack("<Q", out["amount_satoshis"]))
            spk_bytes = bytes.fromhex(out["scriptPubKey"])
            parts.append(encode_varint(len(spk_bytes)))
            parts.append(spk_bytes)

        # Locktime
        parts.append(struct.pack("<I", self.result["locktime"]))

        raw_no_witness = b"".join(parts)
        txid = reverse_bytes(double_sha256(raw_no_witness)).hex()
        self.result["computed_txid"] = txid
        return txid

    def generate_latex_tables(self) -> str:
        """Return LaTeX source for tables describing this transaction.

        The caller can write this to a .tex snippet and ``\\input`` it.
        """
        lines = []
        lines.append("\\subsection*{Transaction Overview}")
        lines.append("\\begin{tabular}{@{}ll@{}} \\toprule")
        lines.append("Field & Value \\\\ \\midrule")
        lines.append(f"TxID (computed) & \\texttt{{{self.result.get('computed_txid', 'N/A')}}} \\\\")
        lines.append(f"Version & {self.result['version']} \\\\")
        lines.append(f"Input count & {self.result['input_count']} \\\\")
        lines.append(f"Output count & {self.result['output_count']} \\\\")
        lines.append(f"Locktime & {self.result['locktime']} \\\\")
        lines.append("\\bottomrule \\end{tabular}")

        # Inputs table
        lines.append("\n\\subsection*{Transaction Inputs}")
        lines.append("\\begin{longtable}{@{}p{2cm}p{5cm}rr@{}} \\toprule")
        lines.append("Index & Prev TxID & Output & Sequence \\\\ \\midrule")
        for idx, inp in enumerate(self.result["inputs"]):
            txid_short = inp["prev_txid"][:16] + "…" if len(inp["prev_txid"]) > 16 else inp["prev_txid"]
            lines.append(
                f"{idx} & \\texttt{{{txid_short}}} & "
                f"{inp['prev_output_index']} & "
                f"{inp['sequence']} \\\\"
            )
        lines.append("\\bottomrule \\end{longtable}")

        # Outputs table
        lines.append("\n\\subsection*{Transaction Outputs}")
        lines.append("\\begin{longtable}{@{}rrl@{}} \\toprule")
        lines.append("Index & Amount (sat) & Script Type \\\\ \\midrule")
        for idx, out in enumerate(self.result["outputs"]):
            stype = out["scriptPubKey_decoded"].get("type", "?")
            lines.append(f"{idx} & {out['amount_satoshis']:,} & {stype} \\\\")
        lines.append("\\bottomrule \\end{longtable}")

        return "\n".join(lines)


# ============================================================================
# Sequence interpretation
# ============================================================================

def _interpret_sequence(seq: int) -> str:
    """Return a human description of a sequence number."""
    if seq == 0xFFFFFFFF:
        return "final (no replacement, no locktime — standard)"
    if seq == 0xFFFFFFFE:
        return "no replacement, locktime enabled"
    if seq <= 0x0000FFFF:
        return "relative locktime (BIP-68) encoded"
    return ""
