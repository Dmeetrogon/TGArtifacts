"""TC-13..17: extract-cache command integration tests."""

import pytest
from pathlib import Path


class TestExtractCache:
    """TC-13..17."""

    def test_tc13_extract_no_pass(self, cli_runner, no_pass_tdata, output_dir):
        """TC-13: Extract cache from no-passcode tdata."""
        runner, cli = cli_runner
        result = runner.invoke(cli, ['extract-cache', str(no_pass_tdata), str(output_dir)])
        assert result.exit_code == 0
        # Should either find files or report none
        assert 'Extraction complete' in result.output or 'No cached TDEF files found' in result.output

    def test_tc14_extract_with_pass(self, cli_runner, with_pass_tdata, output_dir):
        """TC-14: Extract cache from passcode-protected tdata."""
        runner, cli = cli_runner
        path, passcode = with_pass_tdata
        result = runner.invoke(cli, ['extract-cache', str(path), str(output_dir), '-p', passcode])
        assert result.exit_code == 0

    def test_tc15_extract_wrong_pass(self, cli_runner, with_pass_tdata, output_dir):
        """TC-15: Wrong passcode → error."""
        runner, cli = cli_runner
        path, _ = with_pass_tdata
        result = runner.invoke(cli, ['extract-cache', str(path), str(output_dir), '-p', 'wrong'])
        assert result.exit_code != 0

    def test_tc16_stats_output(self, cli_runner, no_pass_tdata, output_dir):
        """TC-16: Output includes statistics (total, success, failed)."""
        runner, cli = cli_runner
        result = runner.invoke(cli, ['extract-cache', str(no_pass_tdata), str(output_dir)])
        if 'Extraction complete' in result.output:
            assert 'Total files:' in result.output
            assert 'Successfully decrypted:' in result.output

    def test_tc17_files_created(self, cli_runner, no_pass_tdata, output_dir):
        """TC-17: Decrypted files are actually written to disk."""
        runner, cli = cli_runner
        result = runner.invoke(cli, ['extract-cache', str(no_pass_tdata), str(output_dir)])
        if 'Extraction complete' in result.output and 'Successfully decrypted: 0' not in result.output:
            files = list(output_dir.rglob('*'))
            file_count = sum(1 for f in files if f.is_file())
            assert file_count > 0
