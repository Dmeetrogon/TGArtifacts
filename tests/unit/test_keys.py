"""UT-011..018: Key derivation tests."""

import hashlib
import os
import pytest

from tgartifacts.crypto.keys import create_local_key


class TestCreateLocalKey:
    """UT-011..018: create_local_key derivation."""

    def test_ut011_legacy_no_passcode(self):
        """UT-011: Legacy empty passcode → PBKDF2-SHA1, 4 iterations, 136 bytes."""
        salt = os.urandom(32)
        key = create_local_key("", salt, 1000000)
        assert len(key) == 136

    def test_ut012_legacy_with_passcode(self):
        """UT-012: Legacy with passcode → PBKDF2-SHA1, 4000 iterations, 136 bytes."""
        salt = os.urandom(32)
        key = create_local_key("test1234", salt, 1000000)
        assert len(key) == 136

    def test_ut013_modern_no_passcode(self):
        """UT-013: Modern empty passcode → SHA512(salt+salt), PBKDF2-SHA512 1 iter."""
        salt = os.urandom(32)
        key = create_local_key("", salt, 3001014)
        assert len(key) == 136

    def test_ut014_modern_with_passcode(self):
        """UT-014: Modern with passcode → PBKDF2-SHA512, 100k iterations."""
        salt = os.urandom(32)
        key = create_local_key("test1234", salt, 3001014)
        assert len(key) == 136

    def test_ut015_deterministic(self):
        """UT-015: Same salt + passcode → same key."""
        salt = b'\xab' * 32
        k1 = create_local_key("hello", salt, 3001014)
        k2 = create_local_key("hello", salt, 3001014)
        assert k1 == k2

    def test_ut016_different_salt(self):
        """UT-016: Different salt → different key."""
        s1 = b'\x01' * 32
        s2 = b'\x02' * 32
        k1 = create_local_key("hello", s1, 3001014)
        k2 = create_local_key("hello", s2, 3001014)
        assert k1 != k2

    def test_ut017_modern_prehash(self):
        """UT-017: Modern derivation uses SHA512(salt + passcode + salt) as input."""
        salt = b'\xcc' * 32
        passcode = "testpass"
        expected_prehash = hashlib.sha512(
            salt + passcode.encode('utf-8') + salt
        ).digest()
        key = create_local_key(passcode, salt, 3001014)
        reference = hashlib.pbkdf2_hmac('sha512', expected_prehash, salt, 100000, 136)
        assert key == reference

    def test_ut018_key_length_always_136(self):
        """UT-018: Result is always 136 bytes for all combinations."""
        salt = os.urandom(32)
        for version in [1000000, 3001014]:
            for pwd in ["", "short", "a" * 100]:
                key = create_local_key(pwd, salt, version)
                assert len(key) == 136
