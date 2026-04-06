# python/tests/test_proxy_config.py
import os
import tempfile
import pytest
from aip_mcp.config import ProxyConfig


class TestProxyConfig:
    def test_defaults(self):
        cfg = ProxyConfig()
        assert cfg.upstream == "http://localhost:3000"
        assert cfg.port == 8080
        assert cfg.host == "127.0.0.1"
        assert cfg.trust_keys == []
        assert cfg.log_file is None
        assert cfg.max_ttl_seconds == 3600
        assert cfg.max_budget_usd == 10.0
        assert cfg.max_depth == 5

    def test_from_dict(self):
        cfg = ProxyConfig.from_dict({
            "upstream": "http://localhost:5000",
            "port": 9090,
            "trust_keys": ["ed25519:z6Mkf..."],
        })
        assert cfg.upstream == "http://localhost:5000"
        assert cfg.port == 9090
        assert cfg.trust_keys == ["ed25519:z6Mkf..."]

    def test_from_toml_file(self):
        content = """
[proxy]
upstream = "http://localhost:4000"
port = 7070
host = "0.0.0.0"
trust_keys = ["ed25519:zABC", "ed25519:zDEF"]

[audit]
max_ttl_seconds = 1800
max_budget_usd = 5.0
max_depth = 3

[logging]
log_file = "/tmp/aip-proxy.log"
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
            f.write(content)
            f.flush()
            cfg = ProxyConfig.from_toml(f.name)

        os.unlink(f.name)
        assert cfg.upstream == "http://localhost:4000"
        assert cfg.port == 7070
        assert cfg.host == "0.0.0.0"
        assert cfg.trust_keys == ["ed25519:zABC", "ed25519:zDEF"]
        assert cfg.max_ttl_seconds == 1800
        assert cfg.max_budget_usd == 5.0
        assert cfg.max_depth == 3
        assert cfg.log_file == "/tmp/aip-proxy.log"

    def test_from_toml_missing_file(self):
        with pytest.raises(FileNotFoundError):
            ProxyConfig.from_toml("/nonexistent/config.toml")

    def test_partial_toml(self):
        content = """
[proxy]
upstream = "http://example.com:3000"
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
            f.write(content)
            f.flush()
            cfg = ProxyConfig.from_toml(f.name)

        os.unlink(f.name)
        assert cfg.upstream == "http://example.com:3000"
        assert cfg.port == 8080  # default
        assert cfg.trust_keys == []  # default
