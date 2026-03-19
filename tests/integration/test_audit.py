"""TC-22..24: audit command integration tests."""

import pytest


class TestAudit:
    """TC-22..24."""

    def test_tc22_audit_no_pass_tdata(self, cli_runner, no_pass_tdata):
        """TC-22: Audit finds CRITICAL 'No passcode set'."""
        runner, cli = cli_runner
        result = runner.invoke(cli, ['plugin', 'audit', str(no_pass_tdata)])
        assert result.exit_code == 0
        assert 'No passcode set' in result.output
        assert 'CRITICAL' in result.output
        assert 'Version:' in result.output
        assert 'Accounts:' in result.output

    def test_tc23_audit_with_pass_tdata(self, cli_runner, with_pass_tdata):
        """TC-23: Audit on passcode-protected tdata reports 'Passcode is set'."""
        runner, cli = cli_runner
        path, _ = with_pass_tdata
        result = runner.invoke(cli, ['plugin', 'audit', str(path)])
        assert result.exit_code == 0
        assert 'Passcode set: yes' in result.output
        assert 'Findings:' in result.output

    def test_tc24_audit_multi_account(self, cli_runner, no_pass_multi_tdata):
        """TC-24: Multi-account tdata → multiple accounts warning."""
        runner, cli = cli_runner
        result = runner.invoke(cli, ['plugin', 'audit', str(no_pass_multi_tdata)])
        assert result.exit_code == 0
        assert 'Multiple accounts' in result.output or 'Accounts: 2' in result.output

    def test_tc30_audit_shows_recommendations(self, cli_runner, no_pass_tdata):
        """Audit output includes Recommendations section with D3FEND IDs."""
        runner, cli = cli_runner
        result = runner.invoke(cli, ['plugin', 'audit', str(no_pass_tdata)])
        assert result.exit_code == 0
        assert 'Recommendations:' in result.output
        assert 'D3-' in result.output

    def test_tc31_audit_multi_account_exfiltration_warning(self, cli_runner, no_pass_multi_tdata):
        """Multi-account finding warns about exfiltration and maps to T1537."""
        runner, cli = cli_runner
        result = runner.invoke(cli, ['plugin', 'audit', str(no_pass_multi_tdata)])
        assert result.exit_code == 0
        assert 'exfiltration' in result.output

