from aip_agents.core.config import AIPConfig


def test_default_config():
    config = AIPConfig()
    assert config.app_name == "aip-app"
    assert config.auto_identity is True
    assert config.auto_delegation is True
    assert config.persist_keys is False
    assert config.log_tokens is False
    assert config.default_scope is None


def test_custom_config():
    config = AIPConfig(
        app_name="my-crew",
        auto_delegation=False,
        log_tokens=True,
        default_scope=["research", "write"],
    )
    assert config.app_name == "my-crew"
    assert config.auto_delegation is False
    assert config.log_tokens is True
    assert config.default_scope == ["research", "write"]
