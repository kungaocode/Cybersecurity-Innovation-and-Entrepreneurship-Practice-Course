#!/usr/bin/env python3
"""
ECDSA on secp256k1 — implemented from scratch for educational purposes.

This module demonstrates the complete ECDSA workflow:
  - Key generation:   d ← random scalar,  P = d·G
  - Signing:          k ← random nonce,  R = k·G,  r = R.x mod n,
                      e = H(m),  s = k⁻¹(e + d·r) mod n
  - Verification:     w = s⁻¹,  R' = w(e·G + r·P),  check R'.x = r

All elliptic-curve arithmetic is implemented manually over the secp256k1
field — no external crypto library is used (except `hashlib` for SHA-256).
"""

import hashlib
import secrets
from typing import Tuple


# ============================================================================
# secp256k1 curve parameters
# ============================================================================

# Field prime:  p = 2²⁵⁶ - 2³² - 977
P = 0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFE_FFFFFC2F

# Curve: y² = x³ + 7  (a = 0, b = 7)
A = 0
B = 7

# Generator point G
Gx = 0x79BE667E_F9DCBBAC_55A06295_CE870B07_029BFCDB_2DCE28D9_59F2815B_16F81798
Gy = 0x483ADA77_26A3C465_5DA4FBFC_0E1108A8_FD17B448_A6855419_9C47D08F_FB10D4B8

# Order of G: n
N = 0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFE_BAAEDCE6_AF48A03B_BFD25E8C_D0364141


# ============================================================================
# Modular arithmetic helpers
# ============================================================================

def mod_inv(a: int, m: int) -> int:
    """Return the modular inverse of `a` modulo `m` using extended Euclid."""
    return pow(a, -1, m)


# ============================================================================
# Elliptic curve point operations over F_p
# ============================================================================

def point_add(p1: Tuple[int, int], p2: Tuple[int, int]) -> Tuple[int, int]:
    """Add two points on y² = x³ + 7 over F_p."""
    x1, y1 = p1
    x2, y2 = p2

    if p1 == (0, 0):     # point at infinity
        return p2
    if p2 == (0, 0):
        return p1

    if x1 == x2:
        if (y1 + y2) % P == 0:
            return (0, 0)  # point at infinity (vertical line)
        # Point doubling
        lam = (3 * x1 * x1 + A) * mod_inv(2 * y1, P) % P
    else:
        # Point addition
        lam = (y2 - y1) * mod_inv(x2 - x1, P) % P

    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)


def point_mul(k: int, pt: Tuple[int, int]) -> Tuple[int, int]:
    """Scalar multiplication k·pt using double-and-add."""
    if k == 0 or k % N == 0:
        return (0, 0)

    result = (0, 0)   # identity
    addend = pt

    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1

    return result


# ============================================================================
# ECDSA primitives
# ============================================================================

G = (Gx, Gy)  # generator as a tuple


def keygen() -> Tuple[int, Tuple[int, int]]:
    """Generate a secp256k1 keypair.

    Returns (private_key, public_key) where:
      - private_key d ∈ [1, n-1]
      - public_key  P = d·G
    """
    d = secrets.randbelow(N - 1) + 1
    P = point_mul(d, G)
    return d, P


def _hash_to_int(message: bytes) -> int:
    """SHA-256(message) → integer mod n."""
    h = hashlib.sha256(message).digest()
    return int.from_bytes(h, "big") % N


def sign(message: bytes, d: int, k: int | None = None) -> Tuple[int, int]:
    """Sign `message` with private key `d`.

    Returns (r, s).

    If `k` is None a cryptographically random nonce is generated.
    For reproducibility in demos, pass an explicit `k`.
    """
    if k is None:
        k = secrets.randbelow(N - 1) + 1

    # R = k·G
    R = point_mul(k, G)
    r = R[0] % N
    assert r != 0, "r == 0 — try a different k"

    # e = H(m)
    e = _hash_to_int(message)

    # s = k⁻¹(e + d·r) mod n
    s = mod_inv(k, N) * (e + d * r) % N
    assert s != 0, "s == 0 — try a different k"

    return (r, s)


def verify(message: bytes, r: int, s: int, P: Tuple[int, int]) -> bool:
    """Verify an ECDSA signature (r, s) against `message` and public key `P`.

    This is the CORRECT verification — it recomputes e = H(message)
    from the original message, which prevents signature forgery.
    """
    if not (1 <= r < N and 1 <= s < N):
        return False

    # e = H(m)  ← THIS is what prevents forgery
    e = _hash_to_int(message)

    # w = s⁻¹ mod n
    w = mod_inv(s, N)

    # R' = w·(e·G + r·P) = (w·e)·G + (w·r)·P
    u1 = (e * w) % N
    u2 = (r * w) % N
    R_prime = point_add(point_mul(u1, G), point_mul(u2, P))

    return R_prime != (0, 0) and (R_prime[0] % N) == r


def verify_hash_only(e: int, r: int, s: int, P: Tuple[int, int]) -> bool:
    """Verify given ONLY the message hash `e` (not the message itself).

    This is the VULNERABLE variant.  An attacker who controls `e`
    can forge a valid signature without knowing the private key.
    """
    if not (1 <= r < N and 1 <= s < N):
        return False

    w = mod_inv(s, N)
    u1 = (e * w) % N
    u2 = (r * w) % N
    R_prime = point_add(point_mul(u1, G), point_mul(u2, P))

    return R_prime != (0, 0) and (R_prime[0] % N) == r


# ============================================================================
# Demo
# ============================================================================

def demo():
    print("=" * 65)
    print("  ECDSA ON secp256k1 — PRIMITIVES DEMO")
    print("=" * 65)

    # 1. Key generation
    print("\n[1] Key generation")
    print("-" * 40)
    d, P = keygen()
    print(f"  Private key d  = {hex(d)[:42]}…")
    print(f"  Public key  Px = {hex(P[0])[:42]}…")
    print(f"              Py = {hex(P[1])[:42]}…")

    # 2. Sign a message
    print("\n[2] Signing")
    print("-" * 40)
    msg = b"Experiment 2: ECDSA signature forgery demo"
    # Use a fixed k for reproducibility
    k = 0x8F3A_1B92_CD47_E605_F329_DA71_B804_29E3_9A67_C12B_45F8_0E36_D712_93AB % N
    r, s = sign(msg, d, k=k)
    e = _hash_to_int(msg)
    print(f"  Message        = {msg.decode()}")
    print(f"  e = H(m) mod n = {hex(e)[:42]}…")
    print(f"  k (nonce)      = {hex(k)[:42]}…")
    print(f"  r = R.x mod n  = {hex(r)[:42]}…")
    print(f"  s              = {hex(s)[:42]}…")

    # 3. Verify (correct: recompute e from message)
    print("\n[3] Verification (correct — recompute e from message)")
    print("-" * 40)
    ok = verify(msg, r, s, P)
    print(f"  Result: {'✓ VALID' if ok else '✗ INVALID'}")

    # 4. Verify with a tampered message
    print("\n[4] Verification with tampered message")
    print("-" * 40)
    ok_tampered = verify(b"tampered message", r, s, P)
    print(f"  Result: {'✓ VALID' if ok_tampered else '✗ INVALID (expected)'}")

    # 5. Show that verify_hash_only is dangerous
    print("\n[5] verify_hash_only(e, r, s, P) — accepts any (e,r,s)")
    print("-" * 40)
    # With the correct e it works
    ok_hash = verify_hash_only(e, r, s, P)
    print(f"  With correct e: {'✓ VALID' if ok_hash else '✗ INVALID'}")
    # But an attacker could provide ANY e and forge matching (r,s)
    fake_e = 12345678901234567890 % N
    # Forging is done in ecdsa_forgery.py
    print(f"  (Forgery demo: see ecdsa_forgery.py)")

    print("\n" + "=" * 65)
    print("  Demo complete.  Run ecdsa_forgery.py for the attack.")
    print("=" * 65)


if __name__ == "__main__":
    demo()
