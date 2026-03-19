"""TC-08..12: export-session command integration tests."""

import json
import pytest


class TestExportSessionJson:
    """TC-08..10: JSON export."""

    def test_tc08_json_export_no_pass(self, cli_runner, no_pass_tdata, output_dir):
        """TC-08: Export session as JSON, no passcode."""
        runner, cli = cli_runner
        out_file = output_dir / "session.json"
        result = runner.invoke(cli, ['export-session', str(no_pass_tdata), str(out_file)])
        assert result.exit_code == 0
        assert out_file.exists()
        data = json.loads(out_file.read_text())
        assert isinstance(data, list)
        assert len(data) >= 1
        assert 'user_id' in data[0]
        assert 'dc_id' in data[0]
        assert 'auth_keys' in data[0]

    def test_tc09_json_export_with_pass(self, cli_runner, with_pass_tdata, output_dir):
        """TC-09: Export session as JSON, with passcode."""
        runner, cli = cli_runner
        path, passcode = with_pass_tdata
        out_file = output_dir / "session.json"
        result = runner.invoke(cli, ['export-session', str(path), str(out_file), '-p', passcode])
        assert result.exit_code == 0
        data = json.loads(out_file.read_text())
        assert len(data) >= 1
        for acc in data:
            for dc_str, key_hex in acc.get('auth_keys', {}).items():
                assert len(key_hex) == 512

    def test_tc10_json_has_auth_key_ids(self, cli_runner, no_pass_tdata, output_dir):
        """TC-10: JSON output includes auth_key_ids."""
        runner, cli = cli_runner
        out_file = output_dir / "session.json"
        runner.invoke(cli, ['export-session', str(no_pass_tdata), str(out_file)])
        data = json.loads(out_file.read_text())
        assert 'auth_key_ids' in data[0]


class TestExportSessionTelethon:
    """TC-11..12: Telethon format export."""

    def test_tc11_telethon_export(self, cli_runner, no_pass_tdata, output_dir):
        """TC-11: Telethon format starts with '1', includes comments."""
        runner, cli = cli_runner
        out_file = output_dir / "session.txt"
        result = runner.invoke(cli, [
            'export-session', str(no_pass_tdata), str(out_file), '-f', 'telethon'
        ])
        assert result.exit_code == 0
        content = out_file.read_text()
        lines = [l for l in content.strip().split('\n') if l.strip()]
        session_lines = [l for l in lines if not l.startswith('#')]
        assert len(session_lines) >= 1
        assert session_lines[0].startswith('1')

    def test_tc12_telethon_multi(self, cli_runner, no_pass_multi_tdata, output_dir):
        """TC-12: Multi-account telethon export → multiple sessions."""
        runner, cli = cli_runner
        out_file = output_dir / "sessions.txt"
        result = runner.invoke(cli, [
            'export-session', str(no_pass_multi_tdata), str(out_file), '-f', 'telethon'
        ])
        assert result.exit_code == 0
        content = out_file.read_text()
        session_lines = [l for l in content.split('\n') if l.strip() and l.startswith('1')]
        assert len(session_lines) >= 2
