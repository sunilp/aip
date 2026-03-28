import tempfile

from aip_agents.core.key_store import KeyStore


def test_generate_and_retrieve():
    store = KeyStore()
    kp = store.get_or_create("agent-1")
    assert len(kp.public_key_bytes()) == 32
    kp2 = store.get_or_create("agent-1")
    assert kp.public_key_bytes() == kp2.public_key_bytes()


def test_different_agents_different_keys():
    store = KeyStore()
    kp1 = store.get_or_create("agent-1")
    kp2 = store.get_or_create("agent-2")
    assert kp1.public_key_bytes() != kp2.public_key_bytes()


def test_has():
    store = KeyStore()
    assert store.has("agent-1") is False
    store.get_or_create("agent-1")
    assert store.has("agent-1") is True


def test_persist_and_load():
    with tempfile.TemporaryDirectory() as tmpdir:
        store1 = KeyStore(persist_dir=tmpdir)
        kp = store1.get_or_create("agent-1")
        pub_bytes = kp.public_key_bytes()

        store2 = KeyStore(persist_dir=tmpdir)
        kp2 = store2.get_or_create("agent-1")
        assert kp2.public_key_bytes() == pub_bytes
