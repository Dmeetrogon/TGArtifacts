"""TC-01..07: info command integration tests."""

import pytest


class TestInfoNoPass:
    """TC-01..03: info on no-passcode tdata."""

    def test_tc01_info_single_account(self, cli_runner, no_pass_tdata):
        """TC-01: info shows account, user_id, DC, auth keys."""
        runner, cli = cli_runner
        result = runner.invoke(cli, ['info', str(no_pass_tdata)])
        assert result.exit_code == 0
        assert 'account(s)' in result.output.lower() or 'Account' in result.output
        assert 'User ID:' in result.output
        assert 'DC ID:' in result.output
        assert 'Passcode protected: No' in result.output
        assert 'Auth keys:' in result.output
        assert 'DC(s)' in result.output

    def test_tc02_info_shows_auth_key_ids(self, cli_runner, no_pass_tdata):
        """TC-02: info displays auth_key_id hashes."""
        runner, cli = cli_runner
        result = runner.invoke(cli, ['info', str(no_pass_tdata)])
        assert result.exit_code == 0
        assert 'auth_key_id' in result.output

    def test_tc03_info_show_keys_flag(self, cli_runner, no_pass_tdata):
        """TC-03: --show-keys prints full hex auth keys."""
        runner, cli = cli_runner
        result = runner.invoke(cli, ['info', str(no_pass_tdata), '--show-keys'])
        assert result.exit_code == 0
        lines = result.output.split('\n')
        key_lines = [l.strip() for l in lines if '...' in l and len(l.strip()) > 30]
        assert len(key_lines) > 0


class TestInfoWithPass:
    """TC-04..05: info on passcode-protected tdata."""

    def test_tc04_info_wrong_passcode(self, cli_runner, with_pass_tdata):
        """TC-04: Wrong passcode → per-account error shown."""
        runner, cli = cli_runner
        path, _ = with_pass_tdata
        result = runner.invoke(cli, ['info', str(path), '-p', 'wrongpass'])
        assert result.exit_code == 0
        assert 'Error:' in result.output

    def test_tc05_info_correct_passcode(self, cli_runner, with_pass_tdata):
        """TC-05: Correct passcode → success with account info."""
        runner, cli = cli_runner
        path, passcode = with_pass_tdata
        result = runner.invoke(cli, ['info', str(path), '-p', passcode])
        assert result.exit_code == 0
        assert 'Passcode protected: Yes' in result.output
        assert 'User ID:' in result.output


class TestInfoMulti:
    """TC-06..07: info on multi-account tdata."""

    def test_tc06_multi_no_pass(self, cli_runner, no_pass_multi_tdata):
        """TC-06: Multiple accounts listed."""
        runner, cli = cli_runner
        result = runner.invoke(cli, ['info', str(no_pass_multi_tdata)])
        assert result.exit_code == 0
        assert '2 account(s)' in result.output or result.output.count('Account:') >= 2

    def test_tc07_multi_with_pass(self, cli_runner, with_pass_multi_tdata):
        """TC-07: Multi-account with passcode."""
        runner, cli = cli_runner
        path, passcode = with_pass_multi_tdata
        result = runner.invoke(cli, ['info', str(path), '-p', passcode])
        assert result.exit_code == 0
        assert result.output.count('Account:') >= 2


class TestInfoSettings:
    """TC-08..13: info displays decrypted settings."""

    def test_tc08_info_shows_tdesktop_version(self, cli_runner, no_pass_tdata):
        """TC-08: info shows TDesktop version."""
        runner, cli = cli_runner
        result = runner.invoke(cli, ['info', str(no_pass_tdata)])
        assert result.exit_code == 0
        assert 'TDesktop version:' in result.output

    def test_tc09_info_shows_settings_section(self, cli_runner, no_pass_tdata):
        """TC-09: info shows Settings section with boolean flags."""
        runner, cli = cli_runner
        result = runner.invoke(cli, ['info', str(no_pass_tdata)])
        assert result.exit_code == 0
        assert 'Settings:' in result.output
        assert 'Auto start:' in result.output
        assert 'Auto update:' in result.output

    def test_tc10_info_shows_dc_options(self, cli_runner, no_pass_tdata):
        """TC-10: info shows DC options count."""
        runner, cli = cli_runner
        result = runner.invoke(cli, ['info', str(no_pass_tdata)])
        assert result.exit_code == 0
        assert 'DC options:' in result.output
        assert '5 DCs' in result.output

    def test_tc11_info_shows_theme(self, cli_runner, no_pass_tdata):
        """TC-11: info shows theme mode."""
        runner, cli = cli_runner
        result = runner.invoke(cli, ['info', str(no_pass_tdata)])
        assert result.exit_code == 0
        assert 'Theme mode:' in result.output

    def test_tc12_info_shows_chat_limits(self, cli_runner, no_pass_tdata):
        """TC-12: info shows chat size limits."""
        runner, cli = cli_runner
        result = runner.invoke(cli, ['info', str(no_pass_tdata)])
        assert result.exit_code == 0
        assert 'Chat size max:' in result.output
        assert 'Megagroup size max:' in result.output


class TestInfoOldTdata:
    """TC-14..18: info on old tdata (v4.16.10)."""

    def test_tc14_old_tdata_version(self, cli_runner, old_no_pass_tdata):
        """TC-14: old tdata shows version 4016010."""
        runner, cli = cli_runner
        result = runner.invoke(cli, ['info', str(old_no_pass_tdata)])
        assert result.exit_code == 0
        assert '4016010' in result.output

    def test_tc15_old_tdata_settings(self, cli_runner, old_no_pass_tdata):
        """TC-15: old tdata shows settings section."""
        runner, cli = cli_runner
        result = runner.invoke(cli, ['info', str(old_no_pass_tdata)])
        assert result.exit_code == 0
        assert 'Settings:' in result.output
        assert 'Auto start:' in result.output
        assert 'DC options:' in result.output

    def test_tc16_old_tdata_account(self, cli_runner, old_no_pass_tdata):
        """TC-16: old tdata shows account info."""
        runner, cli = cli_runner
        result = runner.invoke(cli, ['info', str(old_no_pass_tdata)])
        assert result.exit_code == 0
        assert 'User ID:' in result.output
        assert 'Auth keys:' in result.output

    def test_tc17_old_tdata_with_pass(self, cli_runner, old_with_pass_tdata):
        """TC-17: old tdata with password works."""
        runner, cli = cli_runner
        path, passcode = old_with_pass_tdata
        result = runner.invoke(cli, ['info', str(path), '-p', passcode])
        assert result.exit_code == 0
        assert '4016010' in result.output
        assert 'User ID:' in result.output

    def test_tc18_old_tdata_wrong_pass(self, cli_runner, old_with_pass_tdata):
        """TC-18: old tdata with wrong password shows error."""
        runner, cli = cli_runner
        path, _ = old_with_pass_tdata
        result = runner.invoke(cli, ['info', str(path), '-p', 'wrongpass'])
        assert result.exit_code == 0
        assert 'Error:' in result.output
