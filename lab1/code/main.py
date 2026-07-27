#!/usr/bin/env python3
"""
Bitcoin Transaction & Block Parsing Project — Main Entry Point.

Orchestrates all five tasks:

  T1  Create Testnet wallet & send a transaction
  T2  Fetch the raw transaction hex from Blockstream
  T3  Parse the raw transaction byte-by-byte
  T4  Fetch & parse the containing block
  T5  Verify TxID, Block Hash & Merkle Root

Usage
-----
  python main.py                        # interactive: create wallet & send tx
  python main.py --txid <txid>          # skip wallet, use existing TxID
"""

import argparse
import os
import sys

from api import (
    get_raw_tx_hex,
    get_tx_info,
    get_block_hash,
    get_block_info,
    get_block_raw,
    get_block_txids,
)
from transaction import TransactionParser
from block import BlockParser
from verify import run_all_verifications


OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "output")


def ensure_output_dir():
    os.makedirs(OUTPUT_DIR, exist_ok=True)


# ======================================================================
# Task 1: Wallet
# ======================================================================

def task1_wallet() -> str | None:
    """Create wallet, fund, send tx.  Returns the TxID or None."""
    from wallet import run_wallet_flow
    return run_wallet_flow()


# ======================================================================
# Task 2: Fetch raw transaction
# ======================================================================

def task2_fetch_raw_tx(txid: str) -> str:
    """Fetch the raw transaction hex from Blockstream and save it."""
    print("\n" + "=" * 60)
    print("  TASK 2: FETCH RAW TRANSACTION")
    print("=" * 60)
    print(f"  TxID: {txid}")

    raw_hex = get_raw_tx_hex(txid)
    print(f"  Fetched {len(raw_hex)} hex chars ({len(raw_hex) // 2} bytes)")

    path = os.path.join(OUTPUT_DIR, f"{txid}_raw.hex")
    with open(path, "w") as f:
        f.write(raw_hex)
    print(f"  Saved to {path}")
    return raw_hex


# ======================================================================
# Task 3: Parse transaction
# ======================================================================

def task3_parse_transaction(raw_hex: str, txid: str) -> TransactionParser:
    """Parse the raw transaction byte-by-byte."""
    parser = TransactionParser(raw_hex, verbose=True)

    # Compute TxID from non-witness serialisation (handles SegWit correctly)
    computed_txid = parser.compute_txid()
    print(f"  Computed TxID: {computed_txid}")

    path = os.path.join(OUTPUT_DIR, f"{txid}_parsed.json")
    parser.to_json(path)

    # Also save LaTeX snippet (predictable name for report)
    latex_path = os.path.join(OUTPUT_DIR, f"{txid}_tables.tex")
    with open(latex_path, "w") as f:
        f.write(parser.generate_latex_tables())
    print(f"  LaTeX tables saved to {latex_path}")
    # Predictable name so report/main.tex can \input it without wildcards
    stable_path = os.path.join(OUTPUT_DIR, "tx_tables.tex")
    with open(stable_path, "w") as f:
        f.write(parser.generate_latex_tables())
    print(f"  LaTeX tables saved to {stable_path}")

    return parser


# ======================================================================
# Task 4: Fetch & parse block
# ======================================================================

def task4_fetch_and_parse_block(txid: str) -> BlockParser:
    """Fetch the block containing *txid* and parse it header-first."""
    print("\n" + "=" * 60)
    print("  TASK 4: FETCH & PARSE BLOCK")
    print("=" * 60)

    # Find block info via the transaction
    tx_info = get_tx_info(txid)
    status = tx_info.get("status", {})
    block_height = status.get("block_height")
    expected_block_hash = status.get("block_hash")

    if not block_height:
        print("  ⚠ Transaction is unconfirmed — cannot fetch block.  Exiting task 4.")
        return None

    print(f"  Block height: {block_height}")
    print(f"  Block hash:   {expected_block_hash}")

    # Fetch raw block
    block_hash_from_height = get_block_hash(block_height)
    print(f"  Verified hash via /block-height/{block_height}: {block_hash_from_height}")

    raw_block_hex = get_block_raw(block_hash_from_height)
    print(f"  Fetched {len(raw_block_hex)} hex chars ({len(raw_block_hex) // 2} bytes)")

    # Save raw block
    raw_path = os.path.join(OUTPUT_DIR, f"block_{block_height}_raw.hex")
    with open(raw_path, "w") as f:
        f.write(raw_block_hex)
    print(f"  Raw block saved to {raw_path}")

    # Parse
    parser = BlockParser(raw_block_hex, verbose=True, parse_all_txs=True)
    parser.result["block_height"] = block_height
    parser.result["expected_block_hash"] = expected_block_hash

    # Save parsed JSON
    json_path = os.path.join(OUTPUT_DIR, f"block_{block_height}_parsed.json")
    # Remove full tx list before saving to keep JSON size manageable
    slim = dict(parser.result)
    slim["transactions"] = [
        {"txid": t.get("computed_txid", ""), "_offset": t.get("_offset", 0)}
        for t in slim["transactions"]
    ]
    import json
    with open(json_path, "w") as f:
        json.dump(slim, f, indent=2)
    print(f"  Slim block JSON saved to {json_path}")

    # Latex snippet
    latex_path = os.path.join(OUTPUT_DIR, f"block_{block_height}_header.tex")
    with open(latex_path, "w") as f:
        f.write(parser.generate_latex_tables())
    print(f"  LaTeX header table saved to {latex_path}")
    # Predictable name for report
    stable_path = os.path.join(OUTPUT_DIR, "block_header.tex")
    with open(stable_path, "w") as f:
        f.write(parser.generate_latex_tables())
    print(f"  LaTeX header table saved to {stable_path}")

    return parser


# ======================================================================
# Task 5: Verification
# ======================================================================

def task5_verify(
    tx_parser: TransactionParser,
    expected_txid: str,
    block_parser: BlockParser,
):
    """Run all three verifications."""
    if block_parser is None:
        print("  ⚠ Skipping verification — no block data.")
        return

    # TxID computed from non-witness serialisation
    computed_txid = tx_parser.result.get("computed_txid", "")

    # Extract the 80-byte block header hex from the parser
    header_hex = block_parser.result.get("_header_hex", "")
    expected_block_hash = block_parser.result.get("expected_block_hash", "")
    expected_merkle_root = block_parser.result.get("merkle_root", "")
    txids_in_block = [
        t["txid"] for t in block_parser.result["transactions"] if "txid" in t
    ]

    run_all_verifications(
        computed_txid=computed_txid,
        expected_txid=expected_txid,
        header_hex=header_hex,
        expected_block_hash=expected_block_hash,
        txids_in_block=txids_in_block,
        expected_merkle_root=expected_merkle_root,
    )


# ======================================================================
# Main
# ======================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Bitcoin Transaction & Block Parsing Project"
    )
    parser.add_argument(
        "--txid",
        help="Use an existing Testnet TxID (skip wallet creation)",
    )
    parser.add_argument(
        "--no-wallet",
        action="store_true",
        help="Skip Task 1 even if no --txid is given",
    )
    args = parser.parse_args()

    ensure_output_dir()

    # ---- Task 1: Wallet ----
    txid = args.txid
    if txid:
        print(f"Using existing TxID: {txid}")
    elif not args.no_wallet:
        txid = task1_wallet()
        if txid is None:
            print("\nNo transaction created yet.  Run again after funding the wallet,")
            print("or use a known TxID with:")
            print("  python main.py --txid <txid>")
            return 1
    else:
        print("Error: --no-wallet requires --txid.  Nothing to do.")
        return 1

    # ---- Task 2: Fetch raw tx ----
    raw_tx_hex = task2_fetch_raw_tx(txid)

    # ---- Task 3: Parse tx ----
    tx_parser = task3_parse_transaction(raw_tx_hex, txid)

    # ---- Task 4: Fetch & parse block ----
    block_parser = task4_fetch_and_parse_block(txid)

    # ---- Task 5: Verify ----
    task5_verify(tx_parser, txid, block_parser)

    print("\n" + "=" * 60)
    print("  ALL TASKS COMPLETE")
    print("=" * 60)
    print(f"\n  Output directory: {OUTPUT_DIR}")
    print(f"  TxID:             {txid}")
    print(f"  Explorer:         https://blockstream.info/testnet/tx/{txid}")
    print("\nTo compile the report:")
    print("  cd report && pdflatex main.tex\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
