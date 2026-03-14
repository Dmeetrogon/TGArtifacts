"""UT-041..046: Telethon StringSession tests."""

import base64
import os
import struct
import pytest

from tgartifacts.utils.session_validator import parse_string_session


def _build_string_session(dc_id: int = 2, auth_key: bytes = None) -> str:
    if auth_key is None:
        auth_key = os.urandom(256)
    data = struct.pack('>B4sH256s', dc_id, b'\x00' * 4, 443, auth_key)
    return '1' + base64.urlsafe_b64encode(data).decode('ascii'), auth_key


class TestStringSession:
    """UT-041..046."""

    def test_ut041_valid_session_parse(self):
        """UT-041: Valid StringSession parsed correctly."""
        session_str, auth_key = _build_string_session(dc_id=2)
        dc, key = parse_string_session(session_str)
        assert dc == 2
        assert key == auth_key
        assert len(key) == 256

    def test_ut042_session_starts_with_1(self):
        """UT-042: Session must start with '1'."""
        with pytest.raises(ValueError, match="Invalid StringSession"):
            parse_string_session("2AAAAAA")

    def test_ut043_short_data(self):
        """UT-043: Too-short base64 data → ValueError."""
        short = '1' + base64.urlsafe_b64encode(b'\x00' * 10).decode()
        with pytest.raises(ValueError, match="Invalid session data length"):
            parse_string_session(short)

    def test_ut044_auth_key_256_bytes(self):
        """UT-044: Extracted auth_key is exactly 256 bytes."""
        session_str, _ = _build_string_session()
        _, key = parse_string_session(session_str)
        assert len(key) == 256

    def test_ut045_dc_id_range(self):
        """UT-045: DC IDs 1-5 parsed correctly."""
        for dc in range(1, 6):
            session_str, _ = _build_string_session(dc_id=dc)
            parsed_dc, _ = parse_string_session(session_str)
            assert parsed_dc == dc

    def test_ut046_roundtrip(self):
        """UT-046: Build → parse → same auth_key."""
        auth_key = os.urandom(256)
        session_str, _ = _build_string_session(dc_id=2, auth_key=auth_key)
        dc, key = parse_string_session(session_str)
        assert dc == 2
        assert key == auth_key
