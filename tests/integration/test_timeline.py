import pytest


class TestTimeline:

    def test_timeline_output(self, cli_runner, no_pass_tdata):
        runner, cli = cli_runner
        result = runner.invoke(cli, ['plugin', 'timeline', str(no_pass_tdata)])
        assert result.exit_code == 0
        assert 'Timeline:' in result.output
        assert 'Files analyzed:' in result.output

    def test_timeline_shows_activity_tree(self, cli_runner, no_pass_tdata):
        runner, cli = cli_runner
        result = runner.invoke(cli, ['plugin', 'timeline', str(no_pass_tdata)])
        assert result.exit_code == 0
        assert 'Activity tree:' in result.output

    def test_timeline_detects_bulk_copy(self, cli_runner, no_pass_tdata):
        runner, cli = cli_runner
        result = runner.invoke(cli, ['plugin', 'timeline', str(no_pass_tdata)])
        assert result.exit_code == 0
        assert 'Mass file access' in result.output or 'Bulk file access' in result.output

    def test_audit_includes_timeline(self, cli_runner, no_pass_tdata):
        runner, cli = cli_runner
        result = runner.invoke(cli, ['plugin', 'audit', str(no_pass_tdata)])
        assert result.exit_code == 0
        assert 'Files analyzed:' in result.output
        assert 'Timeline anomalies:' in result.output or 'timeline_anomalies' in result.output
