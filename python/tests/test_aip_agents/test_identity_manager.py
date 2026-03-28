from aip_agents.core.config import AIPConfig
from aip_agents.core.identity_manager import IdentityManager, AIPIdentity


def test_root_identity():
    mgr = IdentityManager(AIPConfig(app_name="test-crew"))
    root = mgr.root_identity()
    assert root.name == "test-crew"
    assert root.aip_id.startswith("aip:key:ed25519:")
    assert len(root.public_key_bytes) == 32


def test_register_agent():
    mgr = IdentityManager(AIPConfig(app_name="test-crew"))
    identity = mgr.register("researcher")
    assert identity.name == "researcher"
    assert identity.aip_id.startswith("aip:key:ed25519:")


def test_register_same_agent_returns_cached():
    mgr = IdentityManager(AIPConfig(app_name="test-crew"))
    id1 = mgr.register("researcher")
    id2 = mgr.register("researcher")
    assert id1.public_key_bytes == id2.public_key_bytes


def test_get_registered():
    mgr = IdentityManager(AIPConfig(app_name="test-crew"))
    mgr.register("researcher")
    identity = mgr.get("researcher")
    assert identity is not None
    assert identity.name == "researcher"


def test_get_unregistered():
    mgr = IdentityManager(AIPConfig(app_name="test-crew"))
    assert mgr.get("unknown") is None


def test_all_identities():
    mgr = IdentityManager(AIPConfig(app_name="test-crew"))
    mgr.register("agent-a")
    mgr.register("agent-b")
    all_ids = mgr.all()
    names = [i.name for i in all_ids]
    assert "agent-a" in names
    assert "agent-b" in names
