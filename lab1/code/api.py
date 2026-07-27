"""
Blockstream Testnet REST API wrapper.

All functions hit the free, public Blockstream.info Testnet API.
No authentication is required.
"""

import requests
from typing import Optional

from config import API_BASE

# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _get(path: str) -> requests.Response:
    url = f"{API_BASE}{path}"
    resp = requests.get(url, timeout=30)
    resp.raise_for_status()
    return resp


# ---------------------------------------------------------------------------
# Transaction endpoints
# ---------------------------------------------------------------------------

def get_raw_tx_hex(txid: str) -> str:
    """Fetch the raw transaction hex for *txid*."""
    return _get(f"/tx/{txid}/hex").text.strip()


def get_tx_info(txid: str) -> dict:
    """Fetch JSON metadata for *txid* (including block_height, confirmed status)."""
    return _get(f"/tx/{txid}").json()


def get_tx_status(txid: str) -> dict:
    """Return confirmed block height & hash (or mempool info) for *txid*."""
    info = get_tx_info(txid)
    status = info.get("status", {})
    return {
        "confirmed": status.get("confirmed", False),
        "block_height": status.get("block_height"),
        "block_hash": status.get("block_hash"),
    }


# ---------------------------------------------------------------------------
# Block endpoints
# ---------------------------------------------------------------------------

def get_block_hash(height: int) -> str:
    """Return the block hash at *height* on Testnet."""
    return _get(f"/block-height/{height}").text.strip()


def get_block_info(block_hash: str) -> dict:
    """Fetch JSON metadata for a block."""
    return _get(f"/block/{block_hash}").json()


def get_block_raw(block_hash: str) -> str:
    """Fetch raw block as hex string.

    The Blockstream endpoint returns binary (application/octet-stream),
    so we convert to hex for the parser.
    """
    return _get(f"/block/{block_hash}/raw").content.hex()


def get_block_txids(block_hash: str) -> list[str]:
    """Fetch the list of TxIDs in a block (paginated)."""
    txids: list[str] = []
    start_index = 0
    while True:
        # Blockstream uses /txs endpoint with pagination
        data = _get(f"/block/{block_hash}/txs/{start_index}").json()
        if not data:
            break
        txids.extend(tx["txid"] for tx in data)
        start_index += len(data)
    return txids


# ---------------------------------------------------------------------------
# Broadcast
# ---------------------------------------------------------------------------

def broadcast_tx(raw_tx_hex: str) -> str:
    """Broadcast a signed raw transaction to the Testnet network.

    Returns the TxID as returned by the node (or Blockstream's relay).
    """
    resp = requests.post(
        f"{API_BASE}/tx",
        data=raw_tx_hex,
        headers={"Content-Type": "text/plain"},
        timeout=30,
    )
    resp.raise_for_status()
    return resp.text.strip()
