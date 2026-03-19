"""UT: Hardener — actions, results, analyze and apply logic."""

import os
import pytest
from pathlib import Path

from tgartifacts.plugins.harden.hardener import Hardener, HardenAction, HardenResult
from tgartifacts.plugins.audit.auditor import Finding


class TestHardenAction:

    def test_action_fields(self):
        """HardenAction stores finding reference and fixable flag."""
        f = Finding(severity='CRITICAL', title='t', detail='d', auto_fixable=True)
        action = HardenAction(finding=f, fixable=True)
        assert action.finding is f
        assert action.fixable is True


class TestHardenResult:

    def test_defaults(self):
        """HardenResult initializes with empty applied, skipped, manual lists."""
        r = HardenResult()
        assert r.applied == []
        assert r.skipped == []
        assert r.manual == []


class TestHardener:

    def test_analyze_returns_fixable_and_manual(self, no_pass_tdata):
        """Analyze returns list of HardenActions and list of manual Findings."""
        hardener = Hardener(no_pass_tdata)
        fixable, manual = hardener.analyze()
        assert isinstance(fixable, list)
        assert isinstance(manual, list)
        assert all(isinstance(a, HardenAction) for a in fixable)
        assert all(isinstance(f, Finding) for f in manual)

    def test_analyze_no_pass_has_manual(self, no_pass_tdata):
        """No-passcode tdata produces 'No passcode set' in manual findings."""
        hardener = Hardener(no_pass_tdata)
        _, manual = hardener.analyze()
        titles = [f.title for f in manual]
        assert 'No passcode set' in titles

    def test_apply_chmod(self, tmp_path):
        """Apply fix changes file permissions to 600."""
        target = tmp_path / "key_datas"
        target.write_bytes(b"test")
        os.chmod(target, 0o644)
        finding = Finding(
            severity='CRITICAL', title='test', detail='d',
            remediation=f'Run: chmod 600 {target}',
            auto_fixable=True,
        )
        hardener = Hardener.__new__(Hardener)
        desc = hardener.apply(finding)
        assert '600' in desc
        assert oct(target.stat().st_mode)[-3:] == '600'
