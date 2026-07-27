"""
Verification utilities for Bitcoin data structures.

Computes and cross-checks:
- **TxID**         — double SHA-256 of the raw transaction
- **Block Hash**   — double SHA-256 of the 80-byte block header
- **Merkle Root**  — Merkle tree built from all TxIDs in a block
"""

from typing import List

from crypto_utils import double_sha256, reverse_bytes, hex_reversed


# ============================================================================
# TxID — double-SHA256 of the *entire* raw transaction
# ============================================================================

def compute_txid(raw_tx_hex: str) -> str:
    """Compute the Bitcoin TxID from a raw transaction hex string.

    .. math::

        \\text{TxID} = \\text{rev}(\\text{SHA256}(\\text{SHA256}(\\text{raw\\_tx\\_bytes})))

    The result is returned in **RPC byte order** (big-endian hex,
    matching block explorers).  Internally Bitcoin stores it reversed.
    """
    raw = bytes.fromhex(raw_tx_hex)
    return reverse_bytes(double_sha256(raw)).hex()


def verify_txid(raw_tx_hex: str, expected_txid: str) -> bool:
    """Return True if the computed TxID matches *expected_txid*."""
    computed = compute_txid(raw_tx_hex)
    ok = computed == expected_txid
    print(f"\n  TxID verification:")
    print(f"    Computed:  {computed}")
    print(f"    Expected:  {expected_txid}")
    print(f"    Result:    {'✓ PASS' if ok else '✗ FAIL'}")
    return ok


# ============================================================================
# Block Hash — double-SHA256 of the 80-byte block header
# ============================================================================

def compute_block_hash(header_hex: str) -> str:
    """Compute the block hash from an 80-byte block header.

    The header must be the raw 80 bytes as they appear on the wire
    (i.e. little-endian fields).  The result is returned in
    **RPC byte order** (big-endian hex).

    .. math::

        \\text{BlockHash} = \\text{rev}(\\text{SHA256}(\\text{SHA256}(\\text{header\\_80\\_bytes})))
    """
    header = bytes.fromhex(header_hex)
    if len(header) != 80:
        raise ValueError(
            f"Block header must be exactly 80 bytes, got {len(header)}"
        )
    return reverse_bytes(double_sha256(header)).hex()


def verify_block_hash(header_hex: str, expected_hash: str) -> bool:
    """Return True if the computed block hash matches *expected_hash*."""
    computed = compute_block_hash(header_hex)
    ok = computed == expected_hash
    print(f"\n  Block hash verification:")
    print(f"    Computed:  {computed}")
    print(f"    Expected:  {expected_hash}")
    print(f"    Result:    {'✓ PASS' if ok else '✗ FAIL'}")
    return ok


# ============================================================================
# Merkle Root
# ============================================================================

def compute_merkle_root(txids: List[str]) -> str:
    """Build a Merkle tree from a list of TxIDs and return the root.

    Each TxID is a 64-char hex string in **RPC byte order**.  Internally
    we reverse to Bitcoin's internal byte order for hashing, then reverse
    the final root back to RPC order.

    If the list is empty the root is ``00…00`` (32 zero bytes).

    Algorithm
    ---------
    1. Convert each TxID to internal byte order (reverse bytes).
    2. While there is >1 element:
       a. If odd number of elements, duplicate the last one.
       b. Pairwise concatenate and double-SHA256 each pair.
    3. Reverse the final 32-byte root to RPC order.
    """
    if not txids:
        return "0" * 64

    # Convert to internal byte order
    nodes = [reverse_bytes(bytes.fromhex(txid)) for txid in txids]

    while len(nodes) > 1:
        if len(nodes) % 2 == 1:
            nodes.append(nodes[-1])  # duplicate last if odd

        new_nodes = []
        for i in range(0, len(nodes), 2):
            combined = nodes[i] + nodes[i + 1]
            new_nodes.append(double_sha256(combined))
        nodes = new_nodes

    # Convert root back to RPC byte order
    return reverse_bytes(nodes[0]).hex()


def verify_merkle_root(txids: List[str], expected_root: str) -> bool:
    """Return True if the computed Merkle root matches *expected_root*."""
    computed = compute_merkle_root(txids)
    ok = computed == expected_root
    print(f"\n  Merkle root verification:")
    print(f"    TxIDs in tree: {len(txids)}")
    if len(txids) <= 5:
        for t in txids:
            print(f"      {t}")
    else:
        for t in txids[:3]:
            print(f"      {t}")
        print(f"      … and {len(txids) - 3} more")
    print(f"    Computed root:  {computed}")
    print(f"    Expected root:  {expected_root}")
    print(f"    Result:         {'✓ PASS' if ok else '✗ FAIL'}")
    return ok


# ============================================================================
# Composite verification
# ============================================================================

def run_all_verifications(
    computed_txid: str,
    expected_txid: str,
    header_hex: str,
    expected_block_hash: str,
    txids_in_block: List[str],
    expected_merkle_root: str,
) -> dict:
    """Run all three verifications and return a summary dict."""
    results = {}

    print("\n" + "=" * 60)
    print("  TASK 5: VERIFICATION")
    print("=" * 60)

    # TxID: compare computed (from parser, sans witness) with expected
    ok_txid = computed_txid == expected_txid
    print(f"\n  TxID verification:")
    print(f"    Computed:  {computed_txid}")
    print(f"    Expected:  {expected_txid}")
    print(f"    Result:    {'✓ PASS' if ok_txid else '✗ FAIL'}")
    results["txid"] = ok_txid

    results["block_hash"] = verify_block_hash(header_hex, expected_block_hash)
    results["merkle_root"] = verify_merkle_root(txids_in_block, expected_merkle_root)

    all_pass = all(results.values())
    print(f"\n  {'━' * 40}")
    print(f"  OVERALL: {'✓ ALL VERIFICATIONS PASSED' if all_pass else '✗ SOME VERIFICATIONS FAILED'}")
    print(f"  {'━' * 40}\n")

    return results
