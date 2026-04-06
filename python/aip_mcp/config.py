# python/aip_mcp/config.py
"""Configuration for the AIP MCP auth proxy."""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:
    try:
        import tomllib
    except ImportError:
        import tomli as tomllib  # type: ignore[no-redef]


@dataclass
class ProxyConfig:
    """Configuration for the AIP MCP proxy."""

    # Proxy settings
    upstream: str = "http://localhost:3000"
    port: int = 8080
    host: str = "127.0.0.1"
    trust_keys: list[str] = field(default_factory=list)

    # Audit thresholds
    max_ttl_seconds: int = 3600
    max_budget_usd: float = 10.0
    max_depth: int = 5

    # Logging
    log_file: str | None = None

    @classmethod
    def from_dict(cls, data: dict) -> ProxyConfig:
        """Create config from a flat dictionary."""
        return cls(
            upstream=data.get("upstream", cls.upstream),
            port=data.get("port", cls.port),
            host=data.get("host", cls.host),
            trust_keys=data.get("trust_keys", []),
            max_ttl_seconds=data.get("max_ttl_seconds", cls.max_ttl_seconds),
            max_budget_usd=data.get("max_budget_usd", cls.max_budget_usd),
            max_depth=data.get("max_depth", cls.max_depth),
            log_file=data.get("log_file"),
        )

    @classmethod
    def from_toml(cls, path: str) -> ProxyConfig:
        """Load config from a TOML file."""
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Config file not found: {path}")

        with open(p, "rb") as f:
            data = tomllib.load(f)

        proxy = data.get("proxy", {})
        audit = data.get("audit", {})
        logging = data.get("logging", {})

        return cls(
            upstream=proxy.get("upstream", cls.upstream),
            port=proxy.get("port", cls.port),
            host=proxy.get("host", cls.host),
            trust_keys=proxy.get("trust_keys", []),
            max_ttl_seconds=audit.get("max_ttl_seconds", cls.max_ttl_seconds),
            max_budget_usd=audit.get("max_budget_usd", cls.max_budget_usd),
            max_depth=audit.get("max_depth", cls.max_depth),
            log_file=logging.get("log_file"),
        )
