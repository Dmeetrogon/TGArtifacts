"""Integration tests for harden plugin."""

import os
import stat
import shutil

import pytest


class TestHarden:

    def test_harden_fixes_permissions(self, cli_runner, no_pass_tdata, tmp_path):
        """Harden plugin fixes world-readable key_datas when user confirms."""
        target = tmp_path / "tdata_copy"
        shutil.copytree(no_pass_tdata, target)
        key_datas = target / "key_datas"
        os.chmod(key_datas, 0o644)

        runner, cli = cli_runner
        result = runner.invoke(cli, ['plugin', 'harden', str(target)], input='y\n' * 10)
        assert result.exit_code == 0
        assert 'FIXED' in result.output
        assert 'Applied:' in result.output
        assert oct(key_datas.stat().st_mode)[-3:] == '600'

    def test_harden_skips_on_deny(self, cli_runner, no_pass_tdata, tmp_path):
        """Harden plugin skips fix when user denies."""
        target = tmp_path / "tdata_copy"
        shutil.copytree(no_pass_tdata, target)
        key_datas = target / "key_datas"
        os.chmod(key_datas, 0o644)

        runner, cli = cli_runner
        result = runner.invoke(cli, ['plugin', 'harden', str(target)], input='n\n' * 10)
        assert result.exit_code == 0
        assert 'SKIPPED' in result.output

    def test_harden_shows_manual_actions(self, cli_runner, no_pass_tdata):
        """Harden reports manual-only actions (passcode, version)."""
        runner, cli = cli_runner
        result = runner.invoke(cli, ['plugin', 'harden', str(no_pass_tdata)], input='n\n' * 10)
        assert result.exit_code == 0
        assert 'MANUAL' in result.output
        assert 'Manual action required:' in result.output
