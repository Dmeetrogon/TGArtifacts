import os
import platform
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional


@dataclass
class TDataLocation:
    path: Path
    source: str  # e.g. "snap", "flatpak", "native", "custom"
    has_key_datas: bool = False
    account_dirs: List[str] = field(default_factory=list)

    @property
    def is_valid(self) -> bool:
        return self.has_key_datas


def _find_account_dirs(tdata_path: Path) -> List[str]:
    dirs = []
    if not tdata_path.is_dir():
        return dirs
    for item in tdata_path.iterdir():
        if item.is_dir() and len(item.name) == 16:
            try:
                int(item.name, 16)
                dirs.append(item.name)
            except ValueError:
                continue
    return dirs


def _check_tdata(path: Path, source: str) -> Optional[TDataLocation]:
    if not path.is_dir():
        return None
    has_key = (path / 'key_datas').is_file()
    accounts = _find_account_dirs(path)
    if not has_key and not accounts:
        return None
    return TDataLocation(
        path=path, source=source,
        has_key_datas=has_key, account_dirs=accounts
    )


def scan_tdata(extra_paths: Optional[List[Path]] = None) -> List[TDataLocation]:
    """Auto-detect all Telegram Desktop tdata directories on the system."""
    results: List[TDataLocation] = []
    home = Path.home()
    system = platform.system()

    candidates: List[tuple[Path, str]] = []

    if system == 'Linux':
        # Native
        candidates.append((
            home / '.local' / 'share' / 'TelegramDesktop' / 'tdata',
            'native'
        ))
        # Snap (multiple revisions)
        snap_base = home / 'snap' / 'telegram-desktop'
        if snap_base.is_dir():
            for rev in snap_base.iterdir():
                if rev.is_dir() and rev.name not in ('common', 'current'):
                    candidates.append((
                        rev / '.local' / 'share' / 'TelegramDesktop' / 'tdata',
                        f'snap/{rev.name}'
                    ))
        # Flatpak
        candidates.append((
            home / '.var' / 'app' / 'org.telegram.desktop' / 'data' / 'TelegramDesktop' / 'tdata',
            'flatpak'
        ))

    elif system == 'Darwin':
        candidates.append((
            home / 'Library' / 'Application Support' / 'Telegram Desktop' / 'tdata',
            'native'
        ))

    elif system == 'Windows':
        appdata = Path(os.environ.get('APPDATA', ''))
        if appdata.is_dir():
            candidates.append((appdata / 'Telegram Desktop' / 'tdata', 'native'))

    if extra_paths:
        for p in extra_paths:
            candidates.append((Path(p), 'custom'))

    seen = set()
    for path, source in candidates:
        resolved = path.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        loc = _check_tdata(path, source)
        if loc is not None:
            results.append(loc)

    return results
