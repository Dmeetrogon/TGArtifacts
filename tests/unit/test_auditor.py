"""UT-062..070: Auditor tests."""

import os
import stat
import pytest
from pathlib import Path

from tgartifacts.plugins.audit.auditor import Auditor, AuditReport, Finding, WEAK_PASSCODES


class TestFinding:
    """UT-062..063."""

    def test_ut062_finding_fields(self):
        """UT-062: Finding dataclass stores severity/title/detail/mitre_id."""
        f = Finding(severity='CRITICAL', title='Test', detail='Details', mitre_id='T1555')
        assert f.severity == 'CRITICAL'
        assert f.title == 'Test'
        assert f.detail == 'Details'
        assert f.mitre_id == 'T1555'

    def test_ut063_finding_optional_mitre(self):
        """UT-063: mitre_id is optional."""
        f = Finding(severity='INFO', title='OK', detail='All good')
        assert f.mitre_id is None

    def test_finding_remediation_fields(self):
        """Finding has remediation, d3fend_id, auto_fixable fields."""
        f = Finding(
            severity='CRITICAL', title='Test', detail='d',
            remediation='Fix it', d3fend_id='D3-FPE', auto_fixable=True,
        )
        assert f.remediation == 'Fix it'
        assert f.d3fend_id == 'D3-FPE'
        assert f.auto_fixable is True

    def test_finding_defaults(self):
        """New Finding fields default to None/False."""
        f = Finding(severity='INFO', title='OK', detail='ok')
        assert f.remediation is None
        assert f.d3fend_id is None
        assert f.auto_fixable is False


class TestAuditReport:
    """UT-064..066."""

    def test_ut064_critical_count(self):
        """UT-064: critical_count counts CRITICAL findings."""
        r = AuditReport(tdata_path=Path('.'))
        r.findings = [
            Finding('CRITICAL', 'A', 'a'),
            Finding('WARNING', 'B', 'b'),
            Finding('CRITICAL', 'C', 'c'),
        ]
        assert r.critical_count == 2

    def test_ut065_warning_count(self):
        """UT-065: warning_count counts WARNING findings."""
        r = AuditReport(tdata_path=Path('.'))
        r.findings = [
            Finding('WARNING', 'A', 'a'),
            Finding('INFO', 'B', 'b'),
        ]
        assert r.warning_count == 1

    def test_ut066_defaults(self):
        """UT-066: Report defaults are sensible."""
        r = AuditReport(tdata_path=Path('.'))
        assert r.passcode_set is False
        assert r.passcode_weak is None
        assert r.file_permissions_ok is True
        assert r.findings == []


class TestAuditor:
    """UT-067..070."""

    def test_ut067_missing_tdata_dir(self, tmp_path):
        """UT-067: Non-existent tdata path → FileNotFoundError."""
        with pytest.raises(FileNotFoundError, match="tdata path"):
            Auditor(tmp_path / "nonexistent")

    def test_ut068_missing_key_datas(self, tmp_path):
        """UT-068: No key_datas file → FileNotFoundError."""
        with pytest.raises(FileNotFoundError, match="key_datas"):
            Auditor(tmp_path)

    def test_ut069_no_passcode_detected(self, no_pass_tdata):
        """UT-069: No-passcode tdata → passcode_set=False, CRITICAL finding with remediation."""
        auditor = Auditor(no_pass_tdata)
        report = auditor.audit()
        assert report.passcode_set is False
        assert report.critical_count >= 1
        titles = [f.title for f in report.findings]
        assert 'No passcode set' in titles
        no_pass_finding = next(f for f in report.findings if f.title == 'No passcode set')
        assert no_pass_finding.remediation is not None
        assert no_pass_finding.d3fend_id == 'D3-MFA'

    def test_ut070_accounts_counted(self, no_pass_tdata):
        """UT-070: Auditor counts account directories."""
        auditor = Auditor(no_pass_tdata)
        report = auditor.audit()
        assert report.accounts_count >= 1

    def test_weak_passcode_list_not_empty(self):
        """WEAK_PASSCODES list exists and has entries."""
        assert len(WEAK_PASSCODES) > 10

    def test_version_check(self, no_pass_tdata):
        """Version check produces a finding with D3FEND mapping."""
        auditor = Auditor(no_pass_tdata)
        report = auditor.audit()
        assert report.version > 0
        version_findings = [f for f in report.findings if 'encryption' in f.title.lower()]
        assert len(version_findings) >= 1
        assert version_findings[0].d3fend_id == 'D3-DENCR'

    def test_all_findings_have_d3fend(self, no_pass_tdata):
        """Every finding from audit has a D3FEND mapping."""
        auditor = Auditor(no_pass_tdata)
        report = auditor.audit()
        for f in report.findings:
            if f.severity != 'INFO' or f.remediation:
                assert f.d3fend_id is not None, f"Finding '{f.title}' missing d3fend_id"

    def test_apply_fix_chmod(self, tmp_path):
        """apply_fix changes file permissions."""
        target = tmp_path / "key_datas"
        target.write_bytes(b"test")
        os.chmod(target, 0o644)
        finding = Finding(
            severity='CRITICAL', title='test', detail='d',
            remediation=f'Run: chmod 600 {target}',
            auto_fixable=True,
        )
        desc = Auditor.apply_fix(finding)
        assert '644 → 600' in desc
        assert oct(target.stat().st_mode)[-3:] == '600'

    def test_apply_fix_rejects_non_fixable(self):
        """apply_fix raises ValueError for non-auto-fixable findings."""
        finding = Finding(severity='INFO', title='ok', detail='d', auto_fixable=False)
        with pytest.raises(ValueError, match="not auto-fixable"):
            Auditor.apply_fix(finding)
