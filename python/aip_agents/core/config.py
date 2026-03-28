from dataclasses import dataclass, field


@dataclass
class AIPConfig:
    """Configuration for AIP agent identity and delegation."""

    app_name: str = "aip-app"
    auto_identity: bool = True
    auto_delegation: bool = True
    persist_keys: bool = False
    log_tokens: bool = False
    default_scope: list[str] | None = None
