"""TC-25..26: scan command integration tests."""

import pytest


class TestScan:
    """TC-25..26."""

    def test_tc25_scan_custom_path(self, cli_runner, no_pass_tdata):
        """TC-25: scan --path with known tdata → found."""
        runner, cli = cli_runner
        result = runner.invoke(cli, ['scan', '--path', str(no_pass_tdata)])
        assert result.exit_code == 0
        assert 'tdata location(s)' in result.output or 'VALID' in result.output
        assert 'key_datas: yes' in result.output

    def test_tc26_scan_custom_path_included(self, cli_runner, no_pass_tdata):
        """TC-26: scan includes custom --path in results with source 'custom'."""
        runner, cli = cli_runner
        result = runner.invoke(cli, ['scan', '--path', str(no_pass_tdata)])
        assert result.exit_code == 0
        assert str(no_pass_tdata) in result.output
