from aip_agents.core.logger import AIPLogger


def test_logger_disabled(capsys):
    logger = AIPLogger(enabled=False)
    logger.identity_created("agent-1", "aip:key:ed25519:zABC")
    captured = capsys.readouterr()
    assert captured.out == ""


def test_logger_enabled(capsys):
    logger = AIPLogger(enabled=True)
    logger.identity_created("agent-1", "aip:key:ed25519:zABC")
    captured = capsys.readouterr()
    assert "[AIP] Identity created: agent-1 -> aip:key:ed25519:zABC" in captured.out


def test_delegation_log(capsys):
    logger = AIPLogger(enabled=True)
    logger.delegation("manager", "researcher", ["web_search"], 2)
    captured = capsys.readouterr()
    assert "[AIP] Delegation: manager -> researcher" in captured.out
    assert "web_search" in captured.out
    assert "chain depth: 2" in captured.out


def test_tool_call_log(capsys):
    logger = AIPLogger(enabled=True)
    logger.tool_call("researcher", "web_search", 3)
    captured = capsys.readouterr()
    assert "[AIP] Tool call: researcher -> web_search" in captured.out
    assert "chain depth: 3" in captured.out
