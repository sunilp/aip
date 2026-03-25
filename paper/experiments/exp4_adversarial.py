"""Experiment 4: Adversarial Security Tests with Cross-Paradigm Comparison.

Tests six attack scenarios against AIP's chained delegation model, and
compares with what unsigned (no auth) and plain JWT (no attenuation)
would allow.

Each attack runs 100 iterations.  The output shows per-attack rejection
rates for AIP, unsigned, and JWT-only baselines, highlighting defenses
that are *unique* to AIP's Biscuit-backed chained tokens.
"""

import sys
import os
import json
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'python'))

from aip_core.crypto import KeyPair
from aip_token.claims import AipClaims
from aip_token.compact import CompactToken
from aip_token.error import TokenError

ITERATIONS = 100
CHAINED_AVAILABLE = False

try:
    from aip_token.chained import ChainedToken
    if ChainedToken is not None:
        CHAINED_AVAILABLE = True
except ImportError:
    pass

# Try importing Biscuit directly for tamper test
if CHAINED_AVAILABLE:
    from biscuit_auth import Biscuit


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ts_now() -> int:
    return int(time.time())


def _separator(width: int = 72) -> str:
    return "-" * width


# ---------------------------------------------------------------------------
# Attack 1: Scope Widening
# ---------------------------------------------------------------------------

def attack_scope_widening() -> dict:
    """Agent B holds scope=['tool:search'] but attempts tool:email."""
    aip_rejected = 0
    unsigned_rejected = 0
    jwt_rejected = 0

    for _ in range(ITERATIONS):
        # -- AIP chained mode --
        if CHAINED_AVAILABLE:
            kp = KeyPair.generate()
            authority = ChainedToken.create_authority(
                issuer="aip:web:orchestrator/root",
                scopes=["tool:search"],
                budget_cents=500,
                max_depth=3,
                ttl_seconds=3600,
                keypair=kp,
            )
            delegated = authority.delegate(
                delegator="aip:web:orchestrator/root",
                delegate="aip:web:orchestrator/agentB",
                scopes=["tool:search"],
                budget_cents=500,
                context="search task delegation",
            )
            try:
                delegated.authorize("tool:email", kp.public_key_bytes())
            except Exception:
                aip_rejected += 1

        # -- Unsigned baseline: no auth at all, nothing blocks scope --
        # Unsigned means no token, no verification.  Any tool call goes through.
        # unsigned_rejected stays 0.

        # -- Plain JWT baseline: JWT with scope claim, server checks scope --
        kp_jwt = KeyPair.generate()
        claims = AipClaims(
            iss="aip:web:orchestrator/root",
            sub="aip:web:orchestrator/agentB",
            scope=["tool:search"],
            max_depth=0,
            iat=_ts_now(),
            exp=_ts_now() + 3600,
        )
        token_str = CompactToken.create(claims, kp_jwt)
        verified = CompactToken.verify(token_str, kp_jwt.public_key_bytes())
        # Server-side scope check
        if not verified.has_scope("tool:email"):
            jwt_rejected += 1

    return {
        "name": "scope_widening",
        "description": "Agent attempts to invoke tool:email when only tool:search was delegated",
        "attempts": ITERATIONS,
        "aip_rejected": aip_rejected,
        "aip_rejection_rate": round(aip_rejected / ITERATIONS, 4),
        "unsigned_rejected": unsigned_rejected,
        "unsigned_rejection_rate": round(unsigned_rejected / ITERATIONS, 4),
        "jwt_rejected": jwt_rejected,
        "jwt_rejection_rate": round(jwt_rejected / ITERATIONS, 4),
        "aip_unique_defense": "Chained Datalog checks enforce scope at every delegation hop",
    }


# ---------------------------------------------------------------------------
# Attack 2: Depth Violation
# ---------------------------------------------------------------------------

def attack_depth_violation() -> dict:
    """Authority sets max_depth=1.  After one delegation, a second is attempted."""
    aip_rejected = 0
    unsigned_rejected = 0
    jwt_rejected = 0

    for _ in range(ITERATIONS):
        # -- AIP chained mode --
        if CHAINED_AVAILABLE:
            kp = KeyPair.generate()
            authority = ChainedToken.create_authority(
                issuer="aip:web:orchestrator/root",
                scopes=["tool:search"],
                budget_cents=500,
                max_depth=1,
                ttl_seconds=3600,
                keypair=kp,
            )
            # First delegation (depth 0 -> 1): should succeed
            delegated1 = authority.delegate(
                delegator="aip:web:orchestrator/root",
                delegate="aip:web:orchestrator/agentB",
                scopes=["tool:search"],
                budget_cents=500,
                context="first hop delegation",
            )
            # Second delegation (depth 1 -> 2): should be blocked
            try:
                delegated1.delegate(
                    delegator="aip:web:orchestrator/agentB",
                    delegate="aip:web:orchestrator/agentC",
                    scopes=["tool:search"],
                    budget_cents=500,
                    context="second hop delegation",
                )
            except (TokenError, Exception):
                aip_rejected += 1

        # -- Unsigned: no depth concept, no protection --
        # unsigned_rejected stays 0.

        # -- Plain JWT: JWT has no delegation chain, so no depth enforcement --
        # A JWT can be forwarded arbitrarily; there is no concept of depth.
        # jwt_rejected stays 0.

    return {
        "name": "depth_violation",
        "description": "Second delegation attempted when max_depth=1 (only one hop allowed)",
        "attempts": ITERATIONS,
        "aip_rejected": aip_rejected,
        "aip_rejection_rate": round(aip_rejected / ITERATIONS, 4),
        "unsigned_rejected": unsigned_rejected,
        "unsigned_rejection_rate": round(unsigned_rejected / ITERATIONS, 4),
        "jwt_rejected": jwt_rejected,
        "jwt_rejection_rate": round(jwt_rejected / ITERATIONS, 4),
        "aip_unique_defense": "max_depth in authority block prevents unbounded delegation",
    }


# ---------------------------------------------------------------------------
# Attack 3: Token Replay (expired token)
# ---------------------------------------------------------------------------

def attack_expired_token() -> dict:
    """Create a compact token with exp = now - 60s and attempt verification."""
    aip_rejected = 0
    unsigned_rejected = 0
    jwt_rejected = 0

    for _ in range(ITERATIONS):
        kp = KeyPair.generate()
        now = _ts_now()
        claims = AipClaims(
            iss="aip:web:orchestrator/root",
            sub="aip:web:orchestrator/agentB",
            scope=["tool:search"],
            max_depth=0,
            iat=now - 120,
            exp=now - 60,  # Already expired
        )
        token_str = CompactToken.create(claims, kp)

        # -- AIP compact mode (same JWT layer) --
        try:
            CompactToken.verify(token_str, kp.public_key_bytes())
        except TokenError:
            aip_rejected += 1

        # -- Unsigned: no tokens, no expiry check --
        # unsigned_rejected stays 0.

        # -- Plain JWT: server checks exp claim -> rejected --
        try:
            CompactToken.verify(token_str, kp.public_key_bytes())
        except TokenError:
            jwt_rejected += 1

    return {
        "name": "expired_token_replay",
        "description": "Token created with exp=now-60s is presented for verification",
        "attempts": ITERATIONS,
        "aip_rejected": aip_rejected,
        "aip_rejection_rate": round(aip_rejected / ITERATIONS, 4),
        "unsigned_rejected": unsigned_rejected,
        "unsigned_rejection_rate": round(unsigned_rejected / ITERATIONS, 4),
        "jwt_rejected": jwt_rejected,
        "jwt_rejection_rate": round(jwt_rejected / ITERATIONS, 4),
        "aip_unique_defense": "Both compact (JWT exp) and chained (Datalog time check) enforce expiry",
    }


# ---------------------------------------------------------------------------
# Attack 4: Wrong Key Verification
# ---------------------------------------------------------------------------

def attack_wrong_key() -> dict:
    """Token signed by key A, verification attempted with key B."""
    aip_rejected = 0
    unsigned_rejected = 0
    jwt_rejected = 0

    for _ in range(ITERATIONS):
        kp_a = KeyPair.generate()
        kp_b = KeyPair.generate()
        now = _ts_now()
        claims = AipClaims(
            iss="aip:web:orchestrator/root",
            sub="aip:web:orchestrator/agentB",
            scope=["tool:search"],
            max_depth=0,
            iat=now,
            exp=now + 3600,
        )
        token_str = CompactToken.create(claims, kp_a)

        # -- AIP: verify with wrong key --
        try:
            CompactToken.verify(token_str, kp_b.public_key_bytes())
        except TokenError:
            aip_rejected += 1

        # -- Unsigned: no signatures, no rejection --
        # unsigned_rejected stays 0.

        # -- Plain JWT: signature check also rejects --
        try:
            CompactToken.verify(token_str, kp_b.public_key_bytes())
        except TokenError:
            jwt_rejected += 1

    return {
        "name": "wrong_key_verification",
        "description": "Token signed by key A, verified against unrelated key B",
        "attempts": ITERATIONS,
        "aip_rejected": aip_rejected,
        "aip_rejection_rate": round(aip_rejected / ITERATIONS, 4),
        "unsigned_rejected": unsigned_rejected,
        "unsigned_rejection_rate": round(unsigned_rejected / ITERATIONS, 4),
        "jwt_rejected": jwt_rejected,
        "jwt_rejection_rate": round(jwt_rejected / ITERATIONS, 4),
        "aip_unique_defense": "Ed25519 signature binding at every layer (compact JWT + chained Biscuit)",
    }


# ---------------------------------------------------------------------------
# Attack 5: Empty Context (audit evasion)
# ---------------------------------------------------------------------------

def attack_empty_context() -> dict:
    """Delegation attempted with empty context string to evade audit trail."""
    aip_rejected = 0
    unsigned_rejected = 0
    jwt_rejected = 0

    for _ in range(ITERATIONS):
        # -- AIP chained mode --
        if CHAINED_AVAILABLE:
            kp = KeyPair.generate()
            authority = ChainedToken.create_authority(
                issuer="aip:web:orchestrator/root",
                scopes=["tool:search"],
                budget_cents=500,
                max_depth=3,
                ttl_seconds=3600,
                keypair=kp,
            )
            # Attempt delegation with empty context
            try:
                authority.delegate(
                    delegator="aip:web:orchestrator/root",
                    delegate="aip:web:orchestrator/agentB",
                    scopes=["tool:search"],
                    budget_cents=500,
                    context="",  # Empty -- should be rejected
                )
            except (TokenError, Exception):
                aip_rejected += 1

        # -- Unsigned: no context concept --
        # unsigned_rejected stays 0.

        # -- Plain JWT: no context field in standard JWT claims --
        # jwt_rejected stays 0.

    return {
        "name": "empty_context_audit_evasion",
        "description": "Delegation with empty context string to evade audit trail",
        "attempts": ITERATIONS,
        "aip_rejected": aip_rejected,
        "aip_rejection_rate": round(aip_rejected / ITERATIONS, 4),
        "unsigned_rejected": unsigned_rejected,
        "unsigned_rejection_rate": round(unsigned_rejected / ITERATIONS, 4),
        "jwt_rejected": jwt_rejected,
        "jwt_rejection_rate": round(jwt_rejected / ITERATIONS, 4),
        "aip_unique_defense": "Mandatory non-empty context on every delegation enforces audit provenance",
    }


# ---------------------------------------------------------------------------
# Attack 6: Forged/Tampered Token (chain integrity)
# ---------------------------------------------------------------------------

def attack_tampered_token() -> dict:
    """Create a valid chained token, tamper with its base64, attempt to verify."""
    aip_rejected = 0
    unsigned_rejected = 0
    jwt_rejected = 0

    if not CHAINED_AVAILABLE:
        return {
            "name": "tampered_token_forgery",
            "description": "Base64 token tampered (bit flip) then verified",
            "attempts": ITERATIONS,
            "aip_rejected": 0,
            "aip_rejection_rate": 0.0,
            "unsigned_rejected": 0,
            "unsigned_rejection_rate": 0.0,
            "jwt_rejected": 0,
            "jwt_rejection_rate": 0.0,
            "aip_unique_defense": "Biscuit signature covers every block; any tampering is detected",
            "skipped": True,
            "skip_reason": "biscuit-python not installed",
        }

    for _ in range(ITERATIONS):
        kp = KeyPair.generate()
        authority = ChainedToken.create_authority(
            issuer="aip:web:orchestrator/root",
            scopes=["tool:search"],
            budget_cents=500,
            max_depth=3,
            ttl_seconds=3600,
            keypair=kp,
        )
        delegated = authority.delegate(
            delegator="aip:web:orchestrator/root",
            delegate="aip:web:orchestrator/agentB",
            scopes=["tool:search"],
            budget_cents=500,
            context="legitimate task delegation",
        )

        # First: verify that the untampered chain works
        delegated.authorize("tool:search", kp.public_key_bytes())

        # Serialize to base64 and tamper
        b64 = delegated.to_base64()
        # Flip a character near the middle of the token
        mid = len(b64) // 2
        original_char = b64[mid]
        # Pick a different character for the flip
        flipped = 'A' if original_char != 'A' else 'B'
        tampered_b64 = b64[:mid] + flipped + b64[mid + 1:]

        # Attempt to deserialize and verify the tampered token
        try:
            recovered = ChainedToken.from_base64(tampered_b64, kp.public_key_bytes())
            # If deserialization somehow succeeds, try authorizing
            recovered.authorize("tool:search", kp.public_key_bytes())
        except Exception:
            aip_rejected += 1

        # -- Unsigned: no signatures, tampering not detectable --
        # unsigned_rejected stays 0.

        # -- Plain JWT: signature check also catches bit flips --
        kp_jwt = KeyPair.generate()
        now = _ts_now()
        claims = AipClaims(
            iss="aip:web:orchestrator/root",
            sub="aip:web:orchestrator/agentB",
            scope=["tool:search"],
            max_depth=0,
            iat=now,
            exp=now + 3600,
        )
        jwt_token = CompactToken.create(claims, kp_jwt)
        # Tamper the JWT
        jwt_mid = len(jwt_token) // 2
        jwt_orig = jwt_token[jwt_mid]
        jwt_flip = 'X' if jwt_orig != 'X' else 'Y'
        tampered_jwt = jwt_token[:jwt_mid] + jwt_flip + jwt_token[jwt_mid + 1:]
        try:
            CompactToken.verify(tampered_jwt, kp_jwt.public_key_bytes())
        except (TokenError, Exception):
            jwt_rejected += 1

    return {
        "name": "tampered_token_forgery",
        "description": "Base64 token tampered (character flip) then verified -- tests chain integrity",
        "attempts": ITERATIONS,
        "aip_rejected": aip_rejected,
        "aip_rejection_rate": round(aip_rejected / ITERATIONS, 4),
        "unsigned_rejected": unsigned_rejected,
        "unsigned_rejection_rate": round(unsigned_rejected / ITERATIONS, 4),
        "jwt_rejected": jwt_rejected,
        "jwt_rejection_rate": round(jwt_rejected / ITERATIONS, 4),
        "aip_unique_defense": "Biscuit signature covers every block; any tampering is detected",
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    print("=" * 72)
    print("EXPERIMENT 4: Adversarial Security Tests")
    print("=" * 72)
    print()
    print(f"Iterations per attack:  {ITERATIONS}")
    print(f"Chained mode available: {CHAINED_AVAILABLE}")
    print()

    attacks_fn = [
        attack_scope_widening,
        attack_depth_violation,
        attack_expired_token,
        attack_wrong_key,
        attack_empty_context,
        attack_tampered_token,
    ]

    results = []
    for fn in attacks_fn:
        print(_separator())
        print(f"Running: {fn.__name__}")
        r = fn()
        results.append(r)
        print(f"  Attack:   {r['name']}")
        print(f"  AIP:      {r['aip_rejected']}/{r['attempts']} rejected  "
              f"(rate={r['aip_rejection_rate']})")
        print(f"  Unsigned: {r['unsigned_rejected']}/{r['attempts']} rejected  "
              f"(rate={r['unsigned_rejection_rate']})")
        print(f"  JWT-only: {r['jwt_rejected']}/{r['attempts']} rejected  "
              f"(rate={r['jwt_rejection_rate']})")
        if r.get("skipped"):
            print(f"  ** SKIPPED: {r.get('skip_reason', 'unknown')}")
        print()

    # Identify attacks unique to AIP (caught by AIP but not by JWT or unsigned)
    unique_to_aip = []
    for r in results:
        if r.get("skipped"):
            continue
        jwt_catches = r["jwt_rejection_rate"] >= 0.99
        aip_catches = r["aip_rejection_rate"] >= 0.99
        if aip_catches and not jwt_catches:
            unique_to_aip.append(r["name"])

    total_attacks = sum(r["attempts"] for r in results if not r.get("skipped"))
    aip_total_rejected = sum(r["aip_rejected"] for r in results if not r.get("skipped"))

    summary = {
        "total_attacks": total_attacks,
        "aip_total_rejected": aip_total_rejected,
        "aip_overall_rate": round(aip_total_rejected / total_attacks, 4) if total_attacks else 0.0,
        "unique_to_aip": unique_to_aip,
    }

    output = {
        "experiment": "adversarial_security",
        "iterations_per_attack": ITERATIONS,
        "chained_available": CHAINED_AVAILABLE,
        "attacks": results,
        "summary": summary,
    }

    # Write JSON results
    outdir = os.path.join(os.path.dirname(__file__), 'results')
    os.makedirs(outdir, exist_ok=True)
    outpath = os.path.join(outdir, 'exp4_adversarial.json')
    with open(outpath, 'w') as f:
        json.dump(output, f, indent=2)

    # Print summary table
    print()
    print("=" * 72)
    print("SUMMARY TABLE")
    print("=" * 72)
    print()
    header = f"{'Attack':<30} {'AIP':>8} {'Unsigned':>10} {'JWT-only':>10} {'AIP Unique':>12}"
    print(header)
    print("-" * len(header))
    for r in results:
        skipped_tag = " [skip]" if r.get("skipped") else ""
        is_unique = "*" if r["name"] in unique_to_aip else ""
        print(f"{r['name']:<30} "
              f"{r['aip_rejection_rate']:>7.0%} "
              f"{r['unsigned_rejection_rate']:>9.0%} "
              f"{r['jwt_rejection_rate']:>9.0%} "
              f"{'  yes' if is_unique else '   no':>12}"
              f"{skipped_tag}")
    print("-" * len(header))
    print(f"{'TOTAL':<30} "
          f"{summary['aip_overall_rate']:>7.0%} "
          f"{'--':>9} "
          f"{'--':>9} "
          f"{'':>12}")
    print()
    print(f"Attacks unique to AIP: {unique_to_aip}")
    print(f"Results written to: {outpath}")
    print()


if __name__ == "__main__":
    main()
