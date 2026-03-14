"""UT-001..010: TDF parser and TDataParser tests."""

import hashlib
import struct
import pytest
from pathlib import Path

from tgartifacts.parsers.tdf_reader import read_tdf


def _build_tdf(version: int, payload: bytes) -> bytes:
    magic = b'TDF$'
    ver = struct.pack('<I', version)
    md5 = hashlib.md5(
        payload
        + len(payload).to_bytes(4, 'little')
        + ver
        + magic
    ).digest()
    return magic + ver + payload + md5


class TestReadTdf:
    """UT-001..006: TDF file parsing."""

    def test_ut001_valid_tdf(self, tmp_path):
        """UT-001: Valid TDF file parsed successfully."""
        payload = b'\x00' * 32
        data = _build_tdf(3001014, payload)
        f = tmp_path / "test.tdf"
        f.write_bytes(data)

        result = read_tdf(str(f))
        assert result['md5_valid'] is True
        assert result['version'] == 3001014
        assert result['data'] == payload

    def test_ut002_invalid_magic(self, tmp_path):
        """UT-002: Invalid magic bytes raises ValueError."""
        data = b'XXXX' + b'\x00' * 24
        f = tmp_path / "bad_magic.tdf"
        f.write_bytes(data)

        with pytest.raises(ValueError, match="Invalid magic"):
            read_tdf(str(f))

    def test_ut003_truncated_file(self, tmp_path):
        """UT-003: File < 24 bytes raises ValueError."""
        f = tmp_path / "tiny.tdf"
        f.write_bytes(b'TDF$' + b'\x00' * 10)

        with pytest.raises(ValueError, match="too small"):
            read_tdf(str(f))

    def test_ut004_bad_md5(self, tmp_path):
        """UT-004: Corrupted MD5 checksum raises ValueError."""
        payload = b'\x00' * 32
        data = _build_tdf(3001014, payload)
        corrupted = data[:-1] + bytes([(data[-1] + 1) % 256])
        f = tmp_path / "bad_md5.tdf"
        f.write_bytes(corrupted)

        with pytest.raises(ValueError, match="MD5 checksum mismatch"):
            read_tdf(str(f))

    def test_ut005_legacy_version(self, tmp_path):
        """UT-005: Version < 2001014 is legacy."""
        data = _build_tdf(1000000, b'\x00' * 32)
        f = tmp_path / "legacy.tdf"
        f.write_bytes(data)

        result = read_tdf(str(f))
        assert result['version'] < 2001014

    def test_ut006_modern_version(self, tmp_path):
        """UT-006: Version >= 2001014 is modern."""
        data = _build_tdf(3001014, b'\x00' * 32)
        f = tmp_path / "modern.tdf"
        f.write_bytes(data)

        result = read_tdf(str(f))
        assert result['version'] >= 2001014

    def test_ut005_real_key_datas_legacy_or_modern(self, key_datas_fixture):
        """UT-005/006: Real key_datas file has a valid version."""
        result = read_tdf(str(key_datas_fixture))
        assert result['md5_valid'] is True
        assert isinstance(result['version'], int)
        assert result['version'] > 0


class TestTDataParser:
    """UT-007..010: TDataParser high-level operations."""

    def test_ut007_salt_from_key_datas(self, no_pass_tdata):
        """UT-007: Salt parsed from key_datas is bytes."""
        from tgartifacts.parsers.tdf_reader import read_tdf
        from tgartifacts.parsers.qt_stream import QtDataStreamReader

        result = read_tdf(str(no_pass_tdata / "key_datas"))
        reader = QtDataStreamReader(result['data'])
        salt = reader.read_bytearray()
        assert salt is not None
        assert isinstance(salt, bytes)
        assert len(salt) > 0

    def test_ut008_find_account_dirs(self, no_pass_tdata):
        """UT-008: find_account_dirs returns only 16-char hex dirs."""
        from tgartifacts.parsers.tdata_parser import TDataParser

        parser = TDataParser(str(no_pass_tdata))
        dirs = parser.find_account_dirs()
        assert len(dirs) >= 1
        for d in dirs:
            assert len(d) == 16
            int(d, 16)

    def test_ut009_find_account_dirs_ignores_non_hex(self, no_pass_tdata):
        """UT-009: Non-hex directories are ignored."""
        from tgartifacts.parsers.tdata_parser import TDataParser

        parser = TDataParser(str(no_pass_tdata))
        dirs = parser.find_account_dirs()
        for d in dirs:
            assert d not in ('emoji', 'user_data', 'dictionaries')

    def test_ut010_find_cached_tdef_files(self, no_pass_tdata):
        """UT-010: find_cached_tdef_files returns file paths."""
        from tgartifacts.parsers.tdata_parser import TDataParser

        parser = TDataParser(str(no_pass_tdata))
        files = parser.find_cached_tdef_files()
        assert isinstance(files, list)
        for f in files:
            assert isinstance(f, Path)
            assert f.is_file()
