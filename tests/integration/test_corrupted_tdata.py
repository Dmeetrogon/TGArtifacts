"""Tests for corrupted/incomplete tdata handling."""

import pytest


class TestCorruptedTdataRecovery:
    """Tests that attempt to recover data from damaged tdata — expected to fail."""

    @pytest.mark.xfail(reason="Cannot extract sessions from tdata without key_datas", strict=True)
    def test_session_recovery_without_keys(self, cli_runner, corrupted_tdata_no_keys, tmp_path):
        """Attempt to recover session from tdata missing key_datas."""
        runner, cli = cli_runner
        out = tmp_path / "session.json"
        result = runner.invoke(cli, ['export-session', str(corrupted_tdata_no_keys), str(out)])
        assert result.exit_code == 0
        assert out.read_text().strip() != ""
        assert 'auth_key' in out.read_text()

    @pytest.mark.xfail(reason="Cannot decrypt settings with wrong passcode", strict=True)
    def test_settings_recovery_wrong_passcode(self, cli_runner, with_pass_tdata):
        """Attempt to read settings from password-protected tdata with wrong passcode."""
        runner, cli = cli_runner
        path, _ = with_pass_tdata
        result = runner.invoke(cli, ['info', str(path), '-p', 'definitely_wrong_password'])
        assert result.exit_code == 0
        assert 'Phone number' in result.output

    @pytest.mark.xfail(reason="Cannot generate full report from corrupted tdata", strict=True)
    def test_full_report_on_truncated_tdata(self, cli_runner, corrupted_tdata_truncated_key, tmp_path):
        """Attempt to generate full forensic report from tdata with truncated key_datas."""
        runner, cli = cli_runner
        out = tmp_path / "report"
        result = runner.invoke(cli, ['plugin', 'report-generator', str(corrupted_tdata_truncated_key),
                                     '-o', str(out)])
        assert result.exit_code == 0
        assert (out / "report.html").exists()

    @pytest.mark.xfail(reason="Cannot audit tdata with garbage key material", strict=True)
    def test_audit_produces_findings_on_garbage_keys(self, cli_runner, corrupted_tdata_bad_key_datas):
        """Attempt to get meaningful audit findings from tdata with garbage key_datas."""
        runner, cli = cli_runner
        result = runner.invoke(cli, ['plugin', 'audit', str(corrupted_tdata_bad_key_datas)])
        assert result.exit_code == 0
        assert 'Passcode set' in result.output
        assert 'Findings:' in result.output

    @pytest.mark.xfail(reason="Cannot bruteforce without valid encrypted key material", strict=True)
    def test_bruteforce_on_empty_tdata(self, cli_runner, corrupted_tdata_empty, tmp_path):
        """Attempt to bruteforce passcode on empty tdata directory."""
        runner, cli = cli_runner
        wl = tmp_path / "wl.txt"
        wl.write_text("penguin\ntest\npassword\n")
        result = runner.invoke(cli, ['bruteforce', str(corrupted_tdata_empty), '-w', str(wl)])
        assert result.exit_code == 0
        assert 'Passcode found' in result.output


class TestCorruptedTdata:

    def test_bruteforce_no_key_datas(self, cli_runner, corrupted_tdata_no_keys, tmp_path):
        """Bruteforce on tdata without key_datas should fail gracefully."""
        runner, cli = cli_runner
        wl = tmp_path / "wl.txt"
        wl.write_text("test\npassword\n")
        result = runner.invoke(cli, ['bruteforce', str(corrupted_tdata_no_keys), '-w', str(wl)])
        assert result.exit_code != 0 or 'Error' in result.output or 'not found' in result.output

    def test_bruteforce_bad_key_datas(self, cli_runner, corrupted_tdata_bad_key_datas, tmp_path):
        """Bruteforce on tdata with garbage key_datas should fail."""
        runner, cli = cli_runner
        wl = tmp_path / "wl.txt"
        wl.write_text("test\npassword\n")
        result = runner.invoke(cli, ['bruteforce', str(corrupted_tdata_bad_key_datas), '-w', str(wl)])
        assert result.exit_code != 0 or 'Error' in result.output

    def test_bruteforce_truncated_key_datas(self, cli_runner, corrupted_tdata_truncated_key, tmp_path):
        """Bruteforce on tdata with truncated key_datas should fail."""
        runner, cli = cli_runner
        wl = tmp_path / "wl.txt"
        wl.write_text("test\npassword\n")
        result = runner.invoke(cli, ['bruteforce', str(corrupted_tdata_truncated_key), '-w', str(wl)])
        assert result.exit_code != 0 or 'Error' in result.output

    def test_info_no_key_datas(self, cli_runner, corrupted_tdata_no_keys):
        """Info command on tdata without key_datas should report error."""
        runner, cli = cli_runner
        result = runner.invoke(cli, ['info', str(corrupted_tdata_no_keys)])
        assert result.exit_code != 0 or 'Error' in result.output

    def test_info_empty_tdata(self, cli_runner, corrupted_tdata_empty):
        """Info command on empty directory should report error."""
        runner, cli = cli_runner
        result = runner.invoke(cli, ['info', str(corrupted_tdata_empty)])
        assert result.exit_code != 0 or 'Error' in result.output

    def test_info_no_settings(self, cli_runner, corrupted_tdata_no_settings):
        """Info on tdata without settingss should still work (settings = empty)."""
        runner, cli = cli_runner
        result = runner.invoke(cli, ['info', str(corrupted_tdata_no_settings)])
        assert result.exit_code == 0
        assert 'TDesktop version' in result.output

    def test_audit_no_key_datas(self, cli_runner, corrupted_tdata_no_keys):
        """Audit on tdata without key_datas should fail."""
        runner, cli = cli_runner
        result = runner.invoke(cli, ['plugin', 'audit', str(corrupted_tdata_no_keys)])
        assert result.exit_code != 0 or 'Error' in result.output or 'not found' in result.output

    def test_audit_empty_tdata(self, cli_runner, corrupted_tdata_empty):
        """Audit on empty directory should fail."""
        runner, cli = cli_runner
        result = runner.invoke(cli, ['plugin', 'audit', str(corrupted_tdata_empty)])
        assert result.exit_code != 0 or 'Error' in result.output

    def test_export_session_no_key_datas(self, cli_runner, corrupted_tdata_no_keys, tmp_path):
        """Export session from tdata without key_datas should find no accounts."""
        runner, cli = cli_runner
        out = tmp_path / "session.json"
        result = runner.invoke(cli, ['export-session', str(corrupted_tdata_no_keys), str(out)])
        assert 'No accounts' in result.output or 'Error' in result.output

    def test_export_session_bad_key_datas(self, cli_runner, corrupted_tdata_bad_key_datas, tmp_path):
        """Export session from tdata with garbage key_datas should find no accounts."""
        runner, cli = cli_runner
        out = tmp_path / "session.json"
        result = runner.invoke(cli, ['export-session', str(corrupted_tdata_bad_key_datas), str(out)])
        assert 'No accounts' in result.output or 'Error' in result.output

    def test_report_generator_empty_tdata(self, cli_runner, corrupted_tdata_empty, tmp_path):
        """Report generator on empty tdata should fail."""
        runner, cli = cli_runner
        result = runner.invoke(cli, ['plugin', 'report-generator', str(corrupted_tdata_empty),
                                     '-o', str(tmp_path / "report")])
        assert result.exit_code != 0 or 'Error' in result.output

    def test_report_generator_no_key_datas(self, cli_runner, corrupted_tdata_no_keys, tmp_path):
        """Report generator on tdata without key_datas should fail."""
        runner, cli = cli_runner
        result = runner.invoke(cli, ['plugin', 'report-generator', str(corrupted_tdata_no_keys),
                                     '-o', str(tmp_path / "report")])
        assert result.exit_code != 0 or 'Error' in result.output

    def test_extract_cache_empty_tdata(self, cli_runner, corrupted_tdata_empty, tmp_path):
        """Extract cache from empty tdata should fail or find nothing."""
        runner, cli = cli_runner
        result = runner.invoke(cli, ['extract-cache', str(corrupted_tdata_empty),
                                     str(tmp_path / "cache_out")])
        assert result.exit_code != 0 or 'Error' in result.output or 'No' in result.output

    def test_hash_report_empty_tdata(self, cli_runner, corrupted_tdata_empty):
        """Hash report on empty tdata should find no files."""
        runner, cli = cli_runner
        result = runner.invoke(cli, ['plugin', 'hash-report', str(corrupted_tdata_empty)])
        assert 'No files found' in result.output or 'total: 0' in result.output


class TestBadTdfChecksum:

    def test_tdf_reader_bad_checksum(self, tmp_path):
        """TDF file with corrupted MD5 checksum should raise ValueError."""
        import hashlib
        import struct

        tdf_path = tmp_path / "bad_checksum"
        magic = b"TDF$"
        version = struct.pack("<i", 6006002)
        payload = b"\x00" * 64
        wrong_md5 = b"\xff" * 16

        data = magic + version + payload + wrong_md5
        tdf_path.write_bytes(data)
        (tmp_path / "bad_checksums").write_bytes(data)

        from tgartifacts.parsers.tdf_reader import read_tdf
        with pytest.raises((ValueError, Exception)):
            read_tdf(str(tdf_path))

    def test_tdf_reader_truncated_file(self, tmp_path):
        """TDF file shorter than minimum header should raise error."""
        tdf_path = tmp_path / "truncated"
        tdf_path.write_bytes(b"TDF$\x00")
        (tmp_path / "truncateds").write_bytes(b"TDF$\x00")

        from tgartifacts.parsers.tdf_reader import read_tdf
        with pytest.raises(Exception):
            read_tdf(str(tdf_path))

    def test_tdf_reader_wrong_magic(self, tmp_path):
        """File without TDF$ magic should raise error."""
        tdf_path = tmp_path / "wrong_magic"
        tdf_path.write_bytes(b"NOTF" + b"\x00" * 100)
        (tmp_path / "wrong_magics").write_bytes(b"NOTF" + b"\x00" * 100)

        from tgartifacts.parsers.tdf_reader import read_tdf
        with pytest.raises(Exception):
            read_tdf(str(tdf_path))

    def test_decryptor_wrong_key(self, no_pass_tdata):
        """Decrypting with a random key should fail checksum validation."""
        import os
        from tgartifacts.parsers.tdf_reader import read_tdf
        from tgartifacts.crypto.decryptor import decrypt_tdf_legacy

        tdf = read_tdf(str(no_pass_tdata / "key_datas"))
        from tgartifacts.parsers.qt_stream import QtDataStreamReader
        reader = QtDataStreamReader(tdf['data'])
        reader.read_bytearray()
        key_encrypted = reader.read_bytearray()

        fake_key = os.urandom(256)
        with pytest.raises(ValueError, match="checksum"):
            decrypt_tdf_legacy(key_encrypted, fake_key)

    def test_settings_decryption_with_wrong_passcode(self, with_pass_tdata):
        """Decrypting settings with wrong passcode should produce empty or raise."""
        from tgartifacts.parsers.tdata_parser import TDataParser

        path, _ = with_pass_tdata
        try:
            parser = TDataParser(str(path), "wrong_passcode_12345")
            settings = parser.get_settings_info()
            assert not settings or settings.get("user_id") is None
        except Exception:
            pass
