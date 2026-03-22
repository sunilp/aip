"""Tests for aip_core.crypto module."""

from aip_core.crypto import KeyPair, sign, verify


class TestKeyPairGeneration:
    def test_keypair_generation(self):
        kp = KeyPair.generate()
        pub = kp.public_key_bytes()
        assert isinstance(pub, bytes)
        assert len(pub) == 32

    def test_two_keypairs_are_different(self):
        kp1 = KeyPair.generate()
        kp2 = KeyPair.generate()
        assert kp1.public_key_bytes() != kp2.public_key_bytes()


class TestSignAndVerify:
    def test_sign_and_verify(self):
        kp = KeyPair.generate()
        message = b"hello world"
        sig = kp.sign(message)
        assert isinstance(sig, bytes)
        assert len(sig) == 64
        assert verify(kp.public_key_bytes(), message, sig) is True

    def test_free_function_sign(self):
        kp = KeyPair.generate()
        message = b"test message"
        sig = sign(kp, message)
        assert verify(kp.public_key_bytes(), message, sig) is True

    def test_verify_rejects_tampered(self):
        kp = KeyPair.generate()
        message = b"original"
        sig = kp.sign(message)
        assert verify(kp.public_key_bytes(), b"tampered", sig) is False

    def test_verify_rejects_wrong_key(self):
        kp1 = KeyPair.generate()
        kp2 = KeyPair.generate()
        message = b"hello"
        sig = kp1.sign(message)
        assert verify(kp2.public_key_bytes(), message, sig) is False


class TestMultibase:
    def test_multibase_roundtrip(self):
        kp = KeyPair.generate()
        mb = kp.public_key_multibase()
        assert mb.startswith("z")
        decoded = KeyPair.decode_multibase(mb)
        assert decoded == kp.public_key_bytes()
