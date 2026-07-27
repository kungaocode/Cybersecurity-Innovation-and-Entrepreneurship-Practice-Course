#!/usr/bin/env python3
"""
ECDSA Signature Forgery Attack — Demonstration.

This script demonstrates that if an ECDSA verifier only checks the message
HASH (e = H(m)) rather than recomputing it from the original message, an
attacker can forge a valid signature (r', s') for an arbitrary "message hash"
e' WITHOUT knowing the private key.

Mathematical Derivation
-----------------------
Let the victim's public key be P = d·G.

The attacker:
  1. Picks arbitrary scalars u, v ∈ [1, n-1].
  2. Computes  R' = u·G + v·P   (a point on the curve).
  3. Sets      r' = R'.x mod n.
  4. Sets      s' = r'·v⁻¹ mod n.
  5. Sets      e' = r'·u·v⁻¹ mod n.

Verification (vulnerable variant):
  w  = s'⁻¹ mod n
  R″ = w·(e'·G + r'·P)
     = v·(r')⁻¹ · (r'·u·v⁻¹·G + r'·P)
     = v·(r')⁻¹ · r' · (u·v⁻¹·G + P)
     = v·u·v⁻¹·G + v·P
     = u·G + v·P
     = R'                                           ✓

The forgery succeeds because:
  - The verifier accepts e' as a given value (doesn't check H(message)).
  - The attacker can control ALL three inputs (e', r', s') to the
    verification equation, as long as they satisfy the relationship above.

Why this doesn't work against real ECDSA:
  - Real verifiers compute e = H(message) independently from the
    original message.  The attacker would need to find a message m'
    such that H(m') = e', which is infeasible due to SHA-256's
    preimage resistance.
"""

import hashlib
from ecdsa_primitives import (
    P, N, G, Gx, Gy,
    mod_inv, point_add, point_mul, keygen, _hash_to_int,
    verify, verify_hash_only,
)

# ============================================================================
# Forgery attack
# ============================================================================

def forge_signature(Px: int, Py: int, u: int = None, v: int = None):
    """Forge an ECDSA signature (r', s', e') for public key P = (Px, Py).

    The attacker does NOT need the private key.

    Parameters
    ----------
    Px, Py : int
        The victim's public key coordinates.
    u, v : int or None
        Arbitrary scalars chosen by the attacker.  If None, random values
        are generated (still deterministic for the demo via fixed seed).

    Returns
    -------
    (e_prime, r_prime, s_prime) : tuple of ints
        The forged (message_hash, r, s) that will pass verify_hash_only.
    """
    import secrets

    if u is None:
        u = secrets.randbelow(N - 1) + 1
    if v is None:
        v = secrets.randbelow(N - 1) + 1

    P = (Px, Py)

    # Step 1: R' = u·G + v·P
    uG = point_mul(u, G)
    vP = point_mul(v, P)
    R_prime = point_add(uG, vP)

    # Step 2: r' = R'.x mod n
    r_prime = R_prime[0] % N

    # Step 3: s' = r' · v⁻¹ mod n
    v_inv = mod_inv(v, N)
    s_prime = (r_prime * v_inv) % N

    # Step 4: e' = r' · u · v⁻¹ mod n
    e_prime = (r_prime * u % N) * v_inv % N

    return e_prime, r_prime, s_prime, u, v, R_prime


# ============================================================================
# Demo
# ============================================================================

def demo():
    print("=" * 65)
    print("  ECDSA SIGNATURE FORGERY ATTACK — FULL DEMO")
    print("=" * 65)

    # ---- 1. Generate a victim keypair ----
    print("\n" + "─" * 55)
    print("  STEP 1: Victim generates a keypair")
    print("─" * 55)
    d, P = keygen()
    print(f"  Private key d  = {hex(d)}")
    print(f"  Public key  Px = {hex(P[0])}")
    print(f"              Py = {hex(P[1])}")

    # ---- 2. Forge a signature ----
    print("\n" + "─" * 55)
    print("  STEP 2: Attacker forges a signature (e', r', s')")
    print("  WITHOUT knowing the private key d")
    print("─" * 55)

    # Use fixed u, v for reproducibility
    u = 0x3A7B2C1D_9E5F4086_B3D1E7F2_9458AC6B_0D1E3F5A_7B8C9D2E_4F1A6B3C_7D8E9F01 % N
    v = 0x5C4A3B2D_1E9F8070_6B5A4C3D_2E1F9080_7A6B5C4D_3E2F1080_9B7A6C5D_4E3F2108 % N

    e_prime, r_prime, s_prime, u, v, R_prime = forge_signature(P[0], P[1], u, v)

    print(f"  Attacker picks u  = {hex(u)[:42]}…")
    print(f"  Attacker picks v  = {hex(v)[:42]}…")
    print()
    print(f"  Computes R' = u·G + v·P")
    print(f"    R'.x = {hex(R_prime[0])[:42]}…")
    print(f"    R'.y = {hex(R_prime[1])[:42]}…")
    print()
    print(f"  r' = R'.x mod n")
    print(f"    r' = {hex(r_prime)[:42]}…")
    print(f"  s' = r' · v⁻¹ mod n")
    print(f"    s' = {hex(s_prime)[:42]}…")
    print(f"  e' = r' · u · v⁻¹ mod n")
    print(f"    e' = {hex(e_prime)[:42]}…")

    # ---- 3. Verify the FORGED signature ----
    print("\n" + "─" * 55)
    print("  STEP 3: Verification")
    print("─" * 55)

    # 3a. Vulnerable verifier (accepts e' as-is)
    print("\n  [3a] Vulnerable verifier: verify_hash_only(e', r', s', P)")
    ok_vuln = verify_hash_only(e_prime, r_prime, s_prime, P)
    print(f"  Result: {'✓ VALID (forgery succeeds!)' if ok_vuln else '✗ INVALID'}")

    # 3b. Correct verifier (tries to recompute e from a message)
    print("\n  [3b] Correct verifier: needs a message m' where H(m') = e'")
    print(f"  Attacker needs to find m' such that SHA256(m') mod n = e'")
    print(f"  e' = {hex(e_prime)[:42]}…")
    print(f"  This is INFEASIBLE — SHA-256 is preimage-resistant.")
    print(f"  → The correct verifier is SAFE from this attack.")

    # 3c. Try to verify with the correct verifier using an arbitrary message
    print("\n  [3c] Correct verifier with arbitrary message:")
    fake_msg = b"This message does NOT hash to the forged e'"
    ok_real = verify(fake_msg, r_prime, s_prime, P)
    print(f"  Message: {fake_msg.decode()}")
    print(f"  Result:  {'✓ VALID' if ok_real else '✗ INVALID (expected) — attack fails'}")
    print(f"  Because H(message) ≠ e' (the forged hash).")

    # ---- 4. Mathematical verification ----
    print("\n" + "─" * 55)
    print("  STEP 4: Algebraic proof that forgery passes")
    print("─" * 55)
    print("""
    Given:  R' = u·G + v·P,  r' = R'.x,  s' = r'·v⁻¹,  e' = r'·u·v⁻¹

    Verify:
      w = (s')⁻¹ = v·(r')⁻¹
      w·(e'·G + r'·P)
        = v·(r')⁻¹ · (r'·u·v⁻¹·G + r'·P)
        = v·(r')⁻¹·r' · (u·v⁻¹·G + P)
        = v · (u·v⁻¹·G + P)
        = v·u·v⁻¹·G + v·P
        = u·G + v·P
        = R'                                             ∎

    Verification passes because R'.x mod n = r'.

    The ROOT CAUSE: The verifier trusts e' without checking
    that e' = H(message) for some known message.
    """)

    # ---- 5. Summary ----
    print("─" * 55)
    print("  SUMMARY")
    print("─" * 55)
    print(f"""
    ✓ Forgery successful against verify_hash_only():
      (r', s', e') = ({hex(r_prime)[:30]}…,
                      {hex(s_prime)[:30]}…,
                      {hex(e_prime)[:30]}…)

    ✗ Forgery fails against correct verify(message, r, s, P)
      because the verifier independently computes e = H(message).

    LESSON: Always pass the original MESSAGE to the verifier,
    not just its hash.  The verifier MUST recompute e = H(m)
    internally.  This is what Bitcoin Core's secp256k1 API
    enforces — secp256k1_ecdsa_verify() takes the message hash
    but the library's documentation explicitly warns that the
    caller MUST verify the message separately.
    """)

    print("=" * 65)
    print("  DEMO COMPLETE")
    print("=" * 65)


if __name__ == "__main__":
    demo()
