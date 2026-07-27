"""
Bitcoin Transaction & Block Parsing Project — Configuration.

API endpoints, network constants, and shared settings.
"""

# ---------------------------------------------------------------------------
# Blockstream Testnet API (free, no key required)
# ---------------------------------------------------------------------------
API_BASE = "https://blockstream.info/testnet/api"

# ---------------------------------------------------------------------------
# Bitcoin protocol constants
# ---------------------------------------------------------------------------
# These are not parsed — they are used for decoding script types.
# Mainnet prefixes are listed for reference; we work on Testnet.
TESTNET_P2PKH_PREFIX = b"\x6f"   # 0x6f → addresses start with 'm' or 'n'
TESTNET_P2SH_PREFIX  = b"\xc4"   # 0xc4 → addresses start with '2'
TESTNET_BECH32_HRP   = "tb"      # native segwit (bc1 → tb1)
TESTNET_BECH32_HRP_M = "tltc"    # testnet lightning (unused here)

# Human-readable opcode names (subset — enough for common scripts)
OPCODE_NAMES: dict[int, str] = {
    0x00: "OP_0 / OP_FALSE",
    0x51: "OP_1 / OP_TRUE",
    0x52: "OP_2",
    0x53: "OP_3",
    0x54: "OP_4",
    0x55: "OP_5",
    0x56: "OP_6",
    0x57: "OP_7",
    0x58: "OP_8",
    0x59: "OP_9",
    0x5a: "OP_10",
    0x5b: "OP_11",
    0x5c: "OP_12",
    0x5d: "OP_13",
    0x5e: "OP_14",
    0x5f: "OP_15",
    0x60: "OP_16",
    0x76: "OP_DUP",
    0x87: "OP_EQUAL",
    0x88: "OP_EQUALVERIFY",
    0xa9: "OP_HASH160",
    0xac: "OP_CHECKSIG",
    0xae: "OP_CHECKMULTISIG",
    0x6a: "OP_RETURN",
    0x63: "OP_IF",
    0x67: "OP_ELSE",
    0x68: "OP_ENDIF",
    0x69: "OP_VERIFY",
    0x6b: "OP_TOALTSTACK",
    0x6c: "OP_FROMALTSTACK",
    0x82: "OP_SIZE",
    0x93: "OP_ADD",
    0xa8: "OP_SHA256",
    0xfd: "OP_PUBKEYHASH",
    0xfe: "OP_PUBKEY",
    0xff: "OP_INVALIDOPCODE",
    0x14: "OP_WITHIN",           # also used as push-20 marker
}

# FAUCET URLs (user-facing)
TESTNET_FAUCETS = [
    "https://coinfaucet.eu/en/btc-testnet/",
    "https://bitcoinfaucet.uo1.net/",
    "https://testnet-faucet.mempool.co/",
]
