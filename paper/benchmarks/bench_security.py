"""Security conformance: verify scope attenuation is enforced."""
import sys, os, json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'python'))

ATTEMPTS = 100
rejected = 0

try:
    from aip_core.crypto import KeyPair
    from aip_token.chained import ChainedToken

    for _ in range(ATTEMPTS):
        kp = KeyPair.generate()
        token = ChainedToken.create_authority(
            issuer="aip:web:security.test/agent",
            scopes=["tool:search"],
            budget_cents=100,
            max_depth=3,
            ttl_seconds=3600,
            keypair=kp,
        )
        try:
            token.authorize("tool:email", kp.public_key_bytes())
        except Exception:
            rejected += 1

    results = {"attempts": ATTEMPTS, "rejected": rejected, "rejection_rate": rejected / ATTEMPTS}
except ImportError:
    results = {"skipped": True, "reason": "biscuit-python not installed"}

print(json.dumps(results, indent=2))
outdir = os.path.join(os.path.dirname(__file__), 'results')
os.makedirs(outdir, exist_ok=True)
with open(os.path.join(outdir, 'security.json'), 'w') as f:
    json.dump(results, f, indent=2)
