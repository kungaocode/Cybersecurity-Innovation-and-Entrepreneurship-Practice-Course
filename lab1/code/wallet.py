"""
Testnet wallet creation and transaction sending.

Uses ``bitcoinlib`` for key management, address derivation, UTXO selection,
transaction construction, signing, and broadcasting.

This is the ONLY module that depends on a Bitcoin library — the parsing
modules (transaction.py, block.py, script.py) do everything from scratch.
"""

import os
import json
import sys
from typing import Optional

from bitcoinlib.wallets import Wallet, wallet_delete_if_exists
from bitcoinlib.transactions import Transaction
from bitcoinlib.keys import Key
from bitcoinlib.services.services import Service

from config import TESTNET_FAUCETS


WALLET_NAME = "bitcoin_parser_lab"
WALLET_PATH = os.path.join(os.path.dirname(__file__), "output", ".wallet")


# ============================================================================
# Wallet creation
# ============================================================================

def create_wallet() -> Wallet:
    """Create a new Testnet wallet (or recreate if it already exists)."""
    try:
        wallet_delete_if_exists(WALLET_NAME)
    except Exception:
        pass

    # Ensure the db path exists
    os.makedirs(WALLET_PATH, exist_ok=True)

    w = Wallet.create(
        WALLET_NAME,
        network="testnet",
        witness_type="segwit",
        db_uri=os.path.join(WALLET_PATH, "wallet.db"),
    )

    # Generate a key and derive an address
    key = w.new_key()
    address = key.address

    print("=" * 60)
    print("  BITCOIN TESTNET WALLET CREATED")
    print("=" * 60)
    print(f"  Address:  {address}")
    print(f"  WIF:      {key.wif}")
    print(f"  Network:  testnet")
    print("=" * 60)
    print()
    _print_faucet_help(address)

    return w


def _print_faucet_help(address: str) -> None:
    """Print instructions for obtaining testnet coins."""
    print("To fund this wallet, visit one of these faucets and paste the address above:")
    for url in TESTNET_FAUCETS:
        print(f"    • {url}")
    print()
    print("After funding, wait 1-2 confirmations (~10-20 min), then re-run this script.")
    print()


# ============================================================================
# Transaction sending
# ============================================================================

def send_transaction(
    wallet: Wallet,
    to_address: Optional[str] = None,
    amount_satoshis: Optional[int] = None,
) -> str:
    """Send coins from *wallet* and return the TxID.

    Parameters
    ----------
    wallet : Wallet
        An unlocked bitcoinlib Wallet with a funded UTXO.
    to_address : str or None
        Destination address.  If None, sends back to the wallet's own address
        (a self-transfer, which is fine for the lab).
    amount_satoshis : int or None
        Amount in satoshis.  If None, sends 10 000 sat (0.0001 tBTC) — enough
        to confirm quickly without wasting faucet funds.
    """
    if to_address is None:
        to_address = wallet.get_key().address

    if amount_satoshis is None:
        amount_satoshis = 10_000  # 0.0001 tBTC

    # Scan UTXOs (bitcoinlib can do this automatically, but we make it explicit)
    wallet.scan()
    wallet.utxos_update()

    utxos = wallet.utxos()
    if not utxos:
        raise RuntimeError(
            "No UTXOs found.  Make sure the wallet has been funded and the "
            "transaction has at least 1 confirmation."
        )

    total = sum(u["value"] for u in utxos)
    print(f"Available: {total:,} sat ({total / 1e8:.8f} tBTC) across {len(utxos)} UTXO(s)")
    print(f"Sending:   {amount_satoshis:,} sat to {to_address}")

    # Estimate fee (simple: 1 sat/vbyte × ~200 vbytes for a typical segwit tx)
    fee = 200
    if total < amount_satoshis + fee:
        raise RuntimeError(
            f"Insufficient funds: have {total} sat, need {amount_satoshis + fee} sat (incl. fee)."
        )

    raw_hex = wallet.send_to(
        to_address,
        amount=amount_satoshis,
        fee=fee,
        broadcast=True,
    )

    # send_to may return a transaction or raw hex depending on version;
    # get the TxID via the wallet's last transaction
    wallet.scan()
    txs = wallet.transactions()
    txid = None
    if txs:
        txid = txs[-1].txid

    print(f"\n✓ Transaction broadcast!")
    print(f"  TxID: {txid}")
    print(f"  Explorer: https://blockstream.info/testnet/tx/{txid}")
    return txid


# ============================================================================
# Entry point
# ============================================================================

def run_wallet_flow() -> Optional[str]:
    """Interactive wallet flow: create wallet, wait for funding, send tx.

    Returns the TxID, or None if the user chose to skip.
    """
    print("\n" + "=" * 60)
    print("  TASK 1: TESTNET WALLET & TRANSACTION")
    print("=" * 60 + "\n")

    # 1. Open or create wallet
    db_path = os.path.join(WALLET_PATH, "wallet.db")
    try:
        w = Wallet(WALLET_NAME, db_uri=db_path)
        print(f"Found existing wallet '{WALLET_NAME}'.")
        addr = w.get_key().address
        print(f"Address: {addr}")
    except Exception:
        w = create_wallet()
        print(
            "\n⚠  Wallet just created — it needs testnet coins before we can send.\n"
            "   Re-run this script after funding and confirmations.\n"
        )
        return None

    # 2. Check balance
    w.scan()
    w.utxos_update()
    utxos = w.utxos()
    total = sum(u["value"] for u in utxos)
    if total == 0:
        addr = w.get_key().address
        print(f"Wallet has 0 balance. Fund this address first:")
        _print_faucet_help(addr)
        return None

    # 3. Send
    txid = send_transaction(w)
    return txid


if __name__ == "__main__":
    run_wallet_flow()
