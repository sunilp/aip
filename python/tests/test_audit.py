# python/tests/test_audit.py
import time
import pytest
from aip_core.crypto import KeyPair
from aip_token.claims import AipClaims
from aip_token.compact import CompactToken
from aip_token.chained import ChainedToken
from aip_mcp.audit import AuditResult, audit_compact, audit_chained


class TestCompactAudit:
    def setup_method(self):
        self.kp = KeyPair.generate()

    def _make_token(self, ttl=3600, scope=None, budget=1.0):
        claims = AipClaims(
            iss="aip:key:ed25519:" + self.kp.public_key_multibase(),
            sub="aip:web:example.com/tools/search",
            scope=scope if scope is not None else ["tool:search"],
            budget_usd=budget,
            max_depth=0,
            iat=int(time.time()),
            exp=int(time.time()) + ttl,
        )
        return CompactToken.create(claims, self.kp)

    def test_clean_token_passes(self):
        token_str = self._make_token(ttl=1800, scope=["tool:search"])
        verified = CompactToken.verify(token_str, self.kp.public_key_bytes())
        result = audit_compact(verified)
        assert result.passed
        assert len(result.warnings) == 0
        assert len(result.errors) == 0

    def test_long_ttl_warns(self):
        token_str = self._make_token(ttl=7200)  # 2 hours
        verified = CompactToken.verify(token_str, self.kp.public_key_bytes())
        result = audit_compact(verified)
        assert result.passed  # warning, not failure
        assert any("ttl" in w.lower() for w in result.warnings)

    def test_empty_scope_errors(self):
        token_str = self._make_token(scope=[])
        verified = CompactToken.verify(token_str, self.kp.public_key_bytes())
        result = audit_compact(verified)
        assert not result.passed
        assert any("scope" in e.lower() for e in result.errors)

    def test_wildcard_scope_warns(self):
        token_str = self._make_token(scope=["*"])
        verified = CompactToken.verify(token_str, self.kp.public_key_bytes())
        result = audit_compact(verified)
        assert result.passed
        assert any("wildcard" in w.lower() for w in result.warnings)

    def test_high_budget_warns(self):
        token_str = self._make_token(budget=100.0)
        verified = CompactToken.verify(token_str, self.kp.public_key_bytes())
        result = audit_compact(verified)
        assert result.passed
        assert any("budget" in w.lower() for w in result.warnings)


class TestChainedAudit:
    def setup_method(self):
        self.root_kp = KeyPair.generate()

    def _make_chain(self, scopes=None, depth=3, budget=500):
        token = ChainedToken.create_authority(
            issuer="aip:web:example.com/orchestrator",
            scopes=scopes or ["tool:search", "tool:email"],
            budget_cents=budget,
            max_depth=depth,
            ttl_seconds=3600,
            keypair=self.root_kp,
        )
        return token

    def test_clean_chain_passes(self):
        token = self._make_chain()
        result = audit_chained(token)
        assert result.passed
        assert len(result.warnings) == 0

    def test_deep_chain_warns(self):
        token = self._make_chain(depth=10)
        result = audit_chained(token)
        assert result.passed
        assert any("depth" in w.lower() for w in result.warnings)

    def test_delegation_narrows_scope(self):
        root = self._make_chain(scopes=["tool:search", "tool:email"])
        delegated = root.delegate(
            delegator="aip:web:example.com/orchestrator",
            delegate="aip:web:example.com/specialist",
            scopes=["tool:search"],  # narrower -- good
            budget_cents=100,
            context="test",
        )
        result = audit_chained(delegated)
        assert result.passed

    def test_high_budget_chain_warns(self):
        token = self._make_chain(budget=100000)  # $1000
        result = audit_chained(token)
        assert result.passed
        assert any("budget" in w.lower() for w in result.warnings)


class TestAuditResult:
    def test_to_dict(self):
        result = AuditResult(passed=True, warnings=["ttl long"], errors=[])
        d = result.to_dict()
        assert d["passed"] is True
        assert d["warnings"] == ["ttl long"]
        assert d["errors"] == []

    def test_failed_result(self):
        result = AuditResult(passed=False, warnings=[], errors=["empty scope"])
        assert not result.passed
