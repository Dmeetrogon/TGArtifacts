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
        # Full auth key hex lines should be 64 chars long
        lines = result.output.split('\n')
        hex_lines = [l.strip() for l in lines if len(l.strip()) == 64]
        assert len(hex_lines) > 0


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
