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
    file_permissions_ok: bool = True
    version: int = 0
    accounts_count: int = 0

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == 'CRITICAL')

    @property
    def warning_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == 'WARNING')




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
            d3fend_id='D3-MFA',
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
                    d3fend_id='D3-LFP',
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
                    d3fend_id='D3-LFP',
                    auto_fixable=True,
                ))
            else:
                report.findings.append(Finding(
                    severity='INFO',
                    title='File permissions OK',
                    detail=f'key_datas permissions: {oct(mode)[-3:]}',
                    d3fend_id='D3-LFP',
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
                    d3fend_id='D3-LFP',
                    auto_fixable=True,
                ))
        except OSError:
            pass

    def _get_settings(self):
        if hasattr(self, '_settings'):
            return self._settings
        try:
            from tgartifacts.parsers.tdata_parser import TDataParser
            parser = TDataParser(str(self.tdata_path))
            self._settings = parser.get_settings_info()
            self._tdesktop_version = parser.tdesktop_version
        except Exception:
            self._settings = {}
            self._tdesktop_version = self.version
        return self._settings

    def _check_auto_lock(self, report: AuditReport) -> None:
        settings = self._get_settings()
        if not settings:
            return
        auto_lock = settings.get("auto_lock")
        if auto_lock is None or auto_lock == 0:
            report.findings.append(Finding(
                severity='WARNING',
                title='Auto-lock not configured',
                detail='No auto-lock timeout set. Physical access to the device '
                       'grants full access to the Telegram session without re-authentication.',
                mitre_id='T1078',
                remediation='Enable auto-lock in TDesktop: Settings → Privacy and Security → Local passcode → Auto-lock',
                d3fend_id='D3-AL',
            ))

    def _check_auto_update(self, report: AuditReport) -> None:
        settings = self._get_settings()
        if not settings:
            return
        if settings.get("auto_update") is False:
            report.findings.append(Finding(
                severity='WARNING',
                title='Auto-update disabled',
                detail='Automatic updates are disabled. The client may miss critical security patches, '
                       'leaving known vulnerabilities exploitable.',
                mitre_id='T1203',
                remediation='Enable auto-updates in TDesktop: Settings → Advanced → Automatic updates',
                d3fend_id='D3-SU',
            ))

    def _check_tdesktop_age(self, report: AuditReport) -> None:
        settings = self._get_settings()
        ver = self._tdesktop_version if hasattr(self, '_tdesktop_version') else self.version
        if ver < 4000000:
            report.findings.append(Finding(
                severity='CRITICAL',
                title=f'Outdated TDesktop version ({ver})',
                detail=f'TDesktop version {ver} is significantly outdated. '
                       'Old versions contain known vulnerabilities (CVEs) and use weaker cryptographic primitives.',
                mitre_id='T1203',
                remediation='Update Telegram Desktop to the latest version from https://desktop.telegram.org',
                d3fend_id='D3-SU',
            ))

    def _check_proxy(self, report: AuditReport) -> None:
        settings = self._get_settings()
        if not settings:
            return
        conn = settings.get("connection")
        if not conn:
            return
        conn_type = conn.get("type", 0)
        if conn_type == 0:
            return
        type_names = {1: "HTTP proxy", 2: "TCP proxy", 3: "MTPROTO proxy"}
        type_name = type_names.get(conn_type, f"unknown ({conn_type})")
        host = conn.get("proxy_host", "")
        port = conn.get("proxy_port", 0)
        detail = f'{type_name} configured'
        if host:
            detail += f': {host}:{port}'
        detail += '. Traffic is routed through a third-party server — verify this is intentional.'
        report.findings.append(Finding(
            severity='INFO',
            title=f'Proxy configured ({type_name})',
            detail=detail,
            mitre_id='T1090',
            d3fend_id='D3-NTA',
        ))

    def _check_auto_start(self, report: AuditReport) -> None:
        settings = self._get_settings()
        if not settings:
            return
        if settings.get("auto_start") is True:
            report.findings.append(Finding(
                severity='INFO',
                title='Auto-start enabled',
                detail='Telegram Desktop starts automatically on system boot. '
                       'If not intentionally configured, this could indicate persistence by a third party.',
                mitre_id='T1547.001',
                d3fend_id='D3-PSA',
            ))

    def _check_phone_number_stored(self, report: AuditReport) -> None:
        settings = self._get_settings()
        if not settings:
            return
        phone = settings.get("phone_number")
        if phone:
            report.findings.append(Finding(
                severity='INFO',
                title='Phone number stored locally',
                detail=f'Phone number ({phone}) is stored in the settings file. '
                       'Compromise of tdata exposes this PII.',
                mitre_id='T1005',
                d3fend_id='D3-LFP',
            ))

    def _check_cache_size(self, report: AuditReport) -> None:
        total = 0
        for cache_dir in ('user_data/cache', 'user_data/media_cache'):
            path = self.tdata_path / cache_dir
            if path.is_dir():
                for f in path.rglob('*'):
                    if f.is_file():
                        total += f.stat().st_size

        gb = total / (1024 ** 3)
        if gb >= 15:
            severity = 'CRITICAL'
        elif gb >= 5:
            severity = 'WARNING'
        else:
            severity = 'INFO'

        if not report.passcode_set and severity != 'CRITICAL':
            severity = 'CRITICAL' if severity == 'WARNING' else 'WARNING'

        report.findings.append(Finding(
            severity=severity,
            title=f'Cache size: {gb:.1f} GB',
            detail=f'{gb:.1f} GB of cached data (media, files, photos) stored locally. '
                   f'Large cache increases data exposure risk on device compromise.',
            mitre_id='T1005',
            remediation='Clear cache in TDesktop: Settings → Advanced → Manage local storage',
            d3fend_id='D3-LFP',
        ))

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
                d3fend_id='D3-CH',
            ))
        else:
            report.findings.append(Finding(
                severity='INFO',
                title='Modern encryption',
                detail=f'TDesktop version {self.version} uses SHA512-PBKDF2 with 100k iterations.',
                d3fend_id='D3-CH',
            ))

    def audit(self) -> AuditReport:
        """Run full security audit on tdata directory."""
        report = AuditReport(tdata_path=self.tdata_path)

        self._check_version(report)
        self._check_tdesktop_age(report)
        self._check_passcode(report)
        self._check_auto_lock(report)
        self._check_auto_update(report)
        self._check_permissions(report)
        self._check_tdata_parent_permissions(report)
        self._check_accounts(report)
        self._check_cache_size(report)
        self._check_proxy(report)
        self._check_auto_start(report)
        self._check_phone_number_stored(report)

        return report

    def apply_fix(self, finding: Finding) -> str:
        """Apply a single auto-fixable finding. Returns description of what was done."""
        if not finding.auto_fixable or not finding.remediation:
            raise ValueError("Finding is not auto-fixable")

        rem = finding.remediation
        if rem.startswith('Run: chmod 600 '):
            target = Path(rem[len('Run: chmod 600 '):]).resolve()
            if not target.is_relative_to(self.tdata_path.resolve()):
                raise ValueError(f"Target path outside tdata: {target}")
            old_mode = oct(target.stat().st_mode)[-3:]
            os.chmod(target, 0o600)
            return f'chmod 600 {target.name} ({old_mode} → 600)'
        elif rem.startswith('Run: chmod 700 '):
            target = Path(rem[len('Run: chmod 700 '):]).resolve()
            if not target.is_relative_to(self.tdata_path.resolve()):
                raise ValueError(f"Target path outside tdata: {target}")
            old_mode = oct(target.stat().st_mode)[-3:]
            os.chmod(target, 0o700)
            return f'chmod 700 {target.name} ({old_mode} → 700)'
        else:
            raise ValueError(f"Unknown remediation: {rem}")
