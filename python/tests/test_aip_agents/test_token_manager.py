import pytest
import time

from aip_agents.core.config import AIPConfig
from aip_agents.core.identity_manager import IdentityManager
from aip_agents.core.token_manager import TokenManager
from aip_token.error import TokenError


def _setup():
    config = AIPConfig(app_name="test-crew")
    id_mgr = IdentityManager(config)
    token_mgr = TokenManager(id_mgr, config)
    return id_mgr, token_mgr


def test_issue_compact_token():
    id_mgr, token_mgr = _setup()
    id_mgr.register("researcher")
    token_str = token_mgr.issue("researcher", scope=["web_search", "file_read"])
    assert isinstance(token_str, str)
    assert token_str.startswith("eyJ")


def test_verify_compact_token():
    id_mgr, token_mgr = _setup()
    id_mgr.register("researcher")
    token_str = token_mgr.issue("researcher", scope=["web_search"])
    verified = token_mgr.verify(token_str, required_scope="web_search")
    assert verified is not None


def test_verify_rejects_wrong_scope():
    id_mgr, token_mgr = _setup()
    id_mgr.register("researcher")
    token_str = token_mgr.issue("researcher", scope=["web_search"])
    with pytest.raises(TokenError):
        token_mgr.verify(token_str, required_scope="delete_files")


def test_delegate_creates_chain():
    id_mgr, token_mgr = _setup()
    id_mgr.register("manager")
    id_mgr.register("researcher")
    parent_token = token_mgr.issue_chained(
        "manager",
        scope=["web_search", "file_read", "summarize"],
    )
    child_token = token_mgr.delegate(
        parent_token=parent_token,
        parent_name="manager",
        child_name="researcher",
        attenuated_scope=["web_search"],
        context="Research task: find recent papers on agent identity",
    )
    assert isinstance(child_token, str)


def test_delegate_attenuates_scope():
    id_mgr, token_mgr = _setup()
    id_mgr.register("manager")
    id_mgr.register("researcher")
    parent_token = token_mgr.issue_chained(
        "manager",
        scope=["web_search", "file_read"],
    )
    child_token = token_mgr.delegate(
        parent_token=parent_token,
        parent_name="manager",
        child_name="researcher",
        attenuated_scope=["web_search"],
        context="Research task",
    )
    token_mgr.authorize_chained(child_token, tool="web_search")


def test_delegate_rejects_unauthorized_tool():
    id_mgr, token_mgr = _setup()
    id_mgr.register("manager")
    id_mgr.register("researcher")
    parent_token = token_mgr.issue_chained(
        "manager",
        scope=["web_search"],
    )
    child_token = token_mgr.delegate(
        parent_token=parent_token,
        parent_name="manager",
        child_name="researcher",
        attenuated_scope=["web_search"],
        context="Research task",
    )
    with pytest.raises(Exception):
        token_mgr.authorize_chained(child_token, tool="delete_files")


def test_chain_depth():
    id_mgr, token_mgr = _setup()
    id_mgr.register("root-agent")
    id_mgr.register("sub-agent")
    parent = token_mgr.issue_chained("root-agent", scope=["search"])
    assert token_mgr.chain_depth(parent) == 0
    child = token_mgr.delegate(
        parent, "root-agent", "sub-agent", ["search"], "delegated task"
    )
    assert token_mgr.chain_depth(child) == 1
