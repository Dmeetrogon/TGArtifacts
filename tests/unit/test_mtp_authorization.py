"""UT-035..040: MTPAuthorization tests."""

import hashlib
import os
import pytest

from tgartifacts.models.MTPAuthorization import MTPAuthorization


def _make_auth(dc_id=2, user_id=123456789):
    auth_key = os.urandom(256)
    return MTPAuthorization(
        user_id=user_id,
        dc_id=dc_id,
        auth_keys={dc_id: auth_key},
    )


class TestMTPAuthorization:
    """UT-035..040."""

    def test_ut035_auth_key_id(self):
        """UT-035: auth_key_id = SHA1(auth_key)[-8:]."""
        auth_key = os.urandom(256)
        auth = MTPAuthorization(user_id=1, dc_id=2, auth_keys={2: auth_key})
        key_id = auth.get_auth_key_id(2)
        expected = hashlib.sha1(auth_key).digest()[-8:]
        assert key_id == expected

    def test_ut036_deterministic(self):
        """UT-036: Same auth_key → same auth_key_id."""
        auth_key = os.urandom(256)
        auth = MTPAuthorization(user_id=1, dc_id=2, auth_keys={2: auth_key})
        assert auth.get_auth_key_id(2) == auth.get_auth_key_id(2)

    def test_ut037_hex_512_chars(self):
        """UT-037: get_auth_key_hex returns 512 hex characters."""
        auth = _make_auth()
        hex_key = auth.get_auth_key_hex(2)
        assert len(hex_key) == 512
        int(hex_key, 16)

    def test_ut038_to_from_dict_roundtrip(self):
        """UT-038: to_dict → from_dict round-trip."""
        auth_key = os.urandom(256)
        original = MTPAuthorization(
            user_id=999, dc_id=2,
            auth_keys={2: auth_key},
            keys_to_destroy={},
        )
        d = original.to_dict()
        restored = MTPAuthorization.from_dict({
            'user_id': d['user_id'],
            'dc_id': d['dc_id'],
            'auth_keys': {int(k): bytes.fromhex(v) for k, v in d['auth_keys'].items()},
            'keys_to_destroy': {int(k): bytes.fromhex(v) for k, v in d['keys_to_destroy'].items()},
        })
        assert restored.user_id == original.user_id
        assert restored.dc_id == original.dc_id
        assert restored.auth_keys == original.auth_keys

    def test_ut039_missing_dc(self):
        """UT-039: Non-existent dc_id → None."""
        auth = _make_auth(dc_id=2)
        assert auth.get_auth_key_id(99) is None
        assert auth.get_auth_key_hex(99) is None

    def test_ut040_keys_to_destroy_empty(self):
        """UT-040: keys_to_destroy empty by default."""
        auth = MTPAuthorization(user_id=1, dc_id=2)
        assert auth.keys_to_destroy == {}
