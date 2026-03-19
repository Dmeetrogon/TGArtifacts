import os
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from tgartifacts.parsers.tdf_reader import read_tdf
from tgartifacts.parsers.qt_stream import QtDataStreamReader
from tgartifacts.crypto.keys import create_local_key
from tgartifacts.crypto.decryptor import decrypt_tdf_legacy


@dataclass
class Finding:
    severity: str
    title: str
    detail: str
    mitre_id: Optional[str] = None
    remediation: Optional[str] = None
    d3fend_id: Optional[str] = None
    auto_fixable: bool = False


@dataclass
class AuditReport:
    tdata_path: Path
    findings: List[Finding] = field(default_factory=list)
    passcode_set: bool = False
    passcode_weak: Optional[bool] = None
    weak_passcode: Optional[str] = None
    file_permissions_ok: bool = True
    version: int = 0
    accounts_count: int = 0

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == 'CRITICAL')

    @property
    def warning_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == 'WARNING')


# Top passwords to check (subset of rockyou + common patterns)
WEAK_PASSCODES = [
    '', '0000', '1111', '1234', '12345', '123456', '1234567', '12345678',
    '123456789', '1234567890', 'password', 'password1', 'qwerty', 'abc123',
    'letmein', 'admin', 'welcome', 'monkey', 'master', 'dragon', 'login',
    'princess', 'football', 'shadow', 'sunshine', 'trustno1', 'iloveyou',
    '0000000', '1111111', '7777777', 'charlie', 'donald', 'password123',
    '654321', '666666', '121212', '000000', '112233', 'abcdef', 'abcd1234',
    'qwerty123', 'passw0rd', 'qwertyuiop', 'asdfghjkl', 'zxcvbnm',
    'test', 'test123', 'pass', 'pass123', 'changeme', 'secret',
]


class Auditor:
    def __init__(self, tdata_path: Path):
        self.tdata_path = Path(tdata_path)
        if not self.tdata_path.is_dir():
            raise FileNotFoundError(f"tdata path not found: {tdata_path}")

        key_datas_path = self.tdata_path / 'key_datas'
        if not key_datas_path.is_file():
            raise FileNotFoundError("key_datas not found")

        key_datas_tdf = read_tdf(str(key_datas_path))
        self.version = key_datas_tdf['version']
        reader = QtDataStreamReader(key_datas_tdf['data'])
        self.salt = reader.read_bytearray()
        self.key_encrypted = reader.read_bytearray()

    def _try_passcode(self, passcode: str) -> bool:
        try:
            passcode_key = create_local_key(passcode, self.salt, self.version)
            decrypt_tdf_legacy(self.key_encrypted, passcode_key)
            return True
        except ValueError:
            return False

    def _check_passcode(self, report: AuditReport) -> None:
        if self._try_passcode(''):
            report.passcode_set = False
            report.findings.append(Finding(
                severity='CRITICAL',
                title='No passcode set',
                detail='tdata is not protected by a local passcode. '
                       'Anyone with file access can extract auth keys and sessions.',
                mitre_id='T1555',
                remediation='Set a local passcode in TDesktop: Settings → Privacy and Security → Local passcode',
                d3fend_id='D3-MFA',
            ))
            return

        report.passcode_set = True
        report.findings.append(Finding(
            severity='INFO',
            title='Passcode is set',
            detail='tdata is protected by a local passcode.',
            mitre_id='D3-MFA',
            d3fend_id='D3-MFA',
        ))

        for weak in WEAK_PASSCODES:
            if not weak:
                continue
            if self._try_passcode(weak):
                report.passcode_weak = True
                report.weak_passcode = weak
                report.findings.append(Finding(
                    severity='CRITICAL',
                    title='Weak passcode detected',
                    detail=f'Passcode "{weak}" found in top-50 common passwords. '
                           f'Vulnerable to dictionary attack (T1110.002).',
                    mitre_id='T1110.002',
                    remediation='Change passcode to 12+ characters with mixed case, digits, and symbols',
                    d3fend_id='D3-MFA',
                ))
                return

        report.passcode_weak = False
        report.findings.append(Finding(
            severity='INFO',
            title='Passcode is not in top-50 weak list',
            detail='Passcode was not found in common passwords list. '
                   'Full dictionary attack still possible at ~3 passwords/s per core.',
        ))

    def _check_permissions(self, report: AuditReport) -> None:
        if os.name == 'nt':
            return

        key_datas = self.tdata_path / 'key_datas'
        try:
            st = key_datas.stat()
            mode = st.st_mode
            world_readable = bool(mode & stat.S_IROTH)
            group_readable = bool(mode & stat.S_IRGRP)

            if world_readable:
                report.file_permissions_ok = False
                report.findings.append(Finding(
                    severity='CRITICAL',
                    title='key_datas is world-readable',
                    detail=f'Permissions: {oct(mode)[-3:]}. '
                           f'Any local user can read the encrypted key material.',
                    mitre_id='T1005',
                    remediation=f'Run: chmod 600 {key_datas}',
                    d3fend_id='D3-FPE',
                    auto_fixable=True,
                ))
            elif group_readable:
                report.file_permissions_ok = False
                report.findings.append(Finding(
                    severity='WARNING',
                    title='key_datas is group-readable',
                    detail=f'Permissions: {oct(mode)[-3:]}. '
                           f'Other users in the same group can read key material.',
                    mitre_id='T1005',
                    remediation=f'Run: chmod 600 {key_datas}',
                    d3fend_id='D3-FPE',
                    auto_fixable=True,
                ))
            else:
                report.findings.append(Finding(
                    severity='INFO',
                    title='File permissions OK',
                    detail=f'key_datas permissions: {oct(mode)[-3:]}',
                    d3fend_id='D3-FPE',
                ))
        except OSError:
            pass

    def _check_tdata_parent_permissions(self, report: AuditReport) -> None:
        if os.name == 'nt':
            return

        try:
            st = self.tdata_path.stat()
            mode = st.st_mode
            if bool(mode & stat.S_IROTH) and bool(mode & stat.S_IXOTH):
                report.findings.append(Finding(
                    severity='WARNING',
                    title='tdata directory is world-accessible',
                    detail=f'Permissions: {oct(mode)[-3:]}. '
                           f'Other users can traverse the tdata directory.',
                    mitre_id='T1005',
                    remediation=f'Run: chmod 700 {self.tdata_path}',
                    d3fend_id='D3-FPE',
                    auto_fixable=True,
                ))
        except OSError:
            pass

    def _check_accounts(self, report: AuditReport) -> None:
        count = 0
        for item in self.tdata_path.iterdir():
            if item.is_dir() and len(item.name) == 16:
                try:
                    int(item.name, 16)
                    count += 1
                except ValueError:
                    continue

        report.accounts_count = count
        if count > 1:
            report.findings.append(Finding(
                severity='WARNING',
                title=f'Multiple accounts detected ({count})',
                detail=f'{count} accounts found in one tdata. '
                       'An unauthorized account may be used as a data exfiltration channel.',
                mitre_id='T1537',
                remediation='Verify all accounts are legitimate. Remove unauthorized accounts via TDesktop: Settings → Log Out',
                d3fend_id='D3-AL',
            ))

    def _check_version(self, report: AuditReport) -> None:
        report.version = self.version
        if self.version < 2001014:
            report.findings.append(Finding(
                severity='CRITICAL',
                title='Legacy encryption (weak PBKDF2)',
                detail=f'TDesktop version {self.version} uses SHA1-PBKDF2 with only 4000 iterations. '
                       f'Bruteforce speed: ~1000x faster than modern versions.',
                mitre_id='T1110.002',
                remediation='Update Telegram Desktop to latest version (4.x+)',
                d3fend_id='D3-DENCR',
            ))
        else:
            report.findings.append(Finding(
                severity='INFO',
                title='Modern encryption',
                detail=f'TDesktop version {self.version} uses SHA512-PBKDF2 with 100k iterations.',
                d3fend_id='D3-DENCR',
            ))

    def audit(self) -> AuditReport:
        """Run full security audit on tdata directory."""
        report = AuditReport(tdata_path=self.tdata_path)

        self._check_version(report)
        self._check_passcode(report)
        self._check_permissions(report)
        self._check_tdata_parent_permissions(report)
        self._check_accounts(report)

        return report

    @staticmethod
    def apply_fix(finding: Finding) -> str:
        """Apply a single auto-fixable finding. Returns description of what was done."""
        if not finding.auto_fixable or not finding.remediation:
            raise ValueError("Finding is not auto-fixable")

        rem = finding.remediation
        if rem.startswith('Run: chmod 600 '):
            target = Path(rem[len('Run: chmod 600 '):])
            old_mode = oct(target.stat().st_mode)[-3:]
            os.chmod(target, 0o600)
            return f'chmod 600 {target.name} ({old_mode} → 600)'
        elif rem.startswith('Run: chmod 700 '):
            target = Path(rem[len('Run: chmod 700 '):])
            old_mode = oct(target.stat().st_mode)[-3:]
            os.chmod(target, 0o700)
            return f'chmod 700 {target.name} ({old_mode} → 700)'
        else:
            raise ValueError(f"Unknown remediation: {rem}")
