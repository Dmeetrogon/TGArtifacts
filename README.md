# TGArtifacts

CLI forensic tool for Telegram Desktop artifact analysis. Extract and analyze data from Telegram Desktop's `tdata` directory.

> **Disclaimer:** This tool is intended for educational purposes, authorized forensic investigations, and security research only.

## Features

- Auto-detect `tdata` directories (native, Snap, Flatpak)
- Parse `tdata` structure with multi-account support (modern + legacy versions)
- Decrypt and parse TDesktop settings (auto-lock, auto-update, proxy, phone, theme, DC options)
- Extract account information (User ID, DC ID, auth keys)
- Export sessions to JSON or Telethon StringSession format
- Decrypt and extract cached media files (TDEF → images, videos, documents)
- Validate extracted sessions via Telegram API
- Security audit with MITRE ATT&CK / D3FEND mapping (12 checks)
- Hardening with interactive auto-fix for fixable issues
- Forensic timeline analysis with anomaly detection (bulk access, timestomping, key rotation)
- Bruteforce passcode via dictionary attack (multi-threaded)
- HTML + JSON forensic report generation
- SHA-256/MD5 hash integrity reports
- Modular architecture with auto-discovery
- Plugin system for extensions

## Installation

```bash
git clone --depth 1 <repo-url> && cd TGArtifacts
python3 -m venv venv && source venv/bin/activate
pip install .
```

With optional dependencies:

```bash
pip install ".[validate-session]"   # Telethon for session validation
pip install ".[all]"                # all optional deps
pip install -e ".[dev]"             # pytest + coverage (development)
```

### Requirements

- Python 3.10+
- Core: click, tgcrypto, rich, python-magic
- Optional: telethon (for `validate-session`)

## Commands

### `scan` — Auto-detect tdata directories

```bash
tgartifacts scan
tgartifacts scan -p /mnt/backup/tdata
```

Searches native, Snap, and Flatpak locations. Use `--path` / `-p` to add custom paths.

### `info` — Show account information

```bash
tgartifacts info /path/to/tdata
tgartifacts info /path/to/tdata -p "passcode" -k
tgartifacts info /path/to/tdata -k -s
```

Displays TDesktop version, decrypted settings (auto start, auto update, auto lock, phone number, download path, language, theme, window position, proxy/connection type, DC options, chat/megagroup limits), account info (User ID, DC ID, auth key IDs, passcode status), cached TDEF file count.

Flags:
- `--show-keys` / `-k` — show auth key fragments (first/last 16 hex chars)
- `--show-sensitive` / `-s` — unmask sensitive data: full phone number, full auth keys (with `-k`). Without this flag, phone numbers are masked (`1858****35`) and auth keys are truncated.

### `export-session` — Export session data

```bash
tgartifacts export-session /path/to/tdata session.json
tgartifacts export-session /path/to/tdata session.txt -f telethon
tgartifacts export-session /path/to/tdata session.json -p "passcode"
```

Formats: `json` (default) — account data with auth keys and auth_key_ids; `telethon` — Telethon StringSession strings (start with `1`, base64url encoded).

### `extract-cache` — Decrypt cached media

```bash
tgartifacts extract-cache /path/to/tdata ./output
tgartifacts extract-cache /path/to/tdata ./output -p "passcode"
```

Decrypts TDEF files from `user_data/media_cache` and `user_data/cache`. Detects file types via magic bytes and saves with appropriate extensions. Handles streaming cache reassembly.

### `bruteforce` — Passcode bruteforce

```bash
tgartifacts bruteforce /path/to/tdata -w wordlist.txt
tgartifacts bruteforce /path/to/tdata -w wordlist.txt -t 4
```

Dictionary attack against passcode-protected tdata. Found passcode is displayed in stdout. Speed: ~3 passwords/s per thread (limited by PBKDF2 100k iterations on modern versions). Use `--threads` / `-t` to parallelize.

### `validate-session` — Check session via Telegram API

Requires `pip install tgartifacts[validate-session]`

```bash
tgartifacts validate-session "1AgAAAAA..."
```

Connects to Telegram API and returns user info if the session is valid.

### `list-plugins` — Show available plugins

```bash
tgartifacts list-plugins
```

### `plugin` — Run a plugin

```bash
tgartifacts plugin audit /path/to/tdata
tgartifacts plugin harden /path/to/tdata
tgartifacts plugin timeline /path/to/tdata
tgartifacts plugin hash-report /path/to/tdata
tgartifacts plugin report-generator /path/to/tdata -o ./output -p "passcode"
```

Built-in plugins:

| Plugin | Description |
|--------|-------------|
| **audit** | Security audit with MITRE ATT&CK / D3FEND mapping |
| **harden** | Interactive auto-fix for fixable audit findings (permissions) |
| **timeline** | Forensic timeline analysis with anomaly detection |
| **hash-report** | SHA-256 + MD5 hashes for all files, grouped by detected type |
| **report-generator** | Full forensic report (cache, sessions, hashing, timeline) → HTML + JSON |

### Audit checks

| Check | Severity | MITRE ATT&CK | D3FEND |
|-------|----------|---------------|--------|
| No passcode set | CRITICAL | T1555 | D3-MFA |
| Weak passcode (top-50 dictionary) | CRITICAL | T1110.002 | D3-MFA |
| Legacy encryption (weak PBKDF2) | CRITICAL | T1110.002 | D3-DENCR |
| Outdated TDesktop version | CRITICAL | T1212 | D3-SU |
| key_datas world-readable | CRITICAL | T1005 | D3-FPE |
| key_datas group-readable | WARNING | T1005 | D3-FPE |
| tdata directory world-accessible | WARNING | T1005 | D3-FPE |
| Auto-lock not configured | WARNING | T1078.001 | D3-AL |
| Auto-update disabled | WARNING | T1203 | D3-SU |
| Multiple accounts detected | WARNING | T1537 | D3-AL |
| Cache size (>5 GB / >15 GB) | WARNING/CRITICAL | T1005 | D3-FPE |
| Proxy configured | INFO | T1090 | D3-NTA |
| Auto-start enabled | INFO | T1547.001 | D3-PSA |
| Phone number stored locally | INFO | T1005 | D3-DENCR |

### Timeline anomaly detection

| Anomaly | Severity | MITRE ATT&CK |
|---------|----------|---------------|
| Bulk file access (>10 same second) | WARNING | T1005 |
| Mass file access (>50 same second) | CRITICAL | T1005 |
| Future timestamps | WARNING | T1070.006 |
| Round timestamps (timestomping) | WARNING | T1070.006 |
| Key rotation detected (keys_to_destroy) | INFO | T1550.004 |

## Writing a plugin

```
my_plugin/
├── __init__.py      # plugin metadata + delegation
└── answer_cli.py    # CLI output logic
```

```python
# __init__.py
from typing import Any, Dict
from tgartifacts.plugins import BasePlugin, PluginContext

class MyPlugin(BasePlugin):
    name = "my-plugin"
    description = "My custom analyzer"
    version = "0.1.0"

    def run(self, context: PluginContext) -> Dict[str, Any]:
        from .answer_cli import run
        return run(context)
```

```python
# answer_cli.py
import click
from typing import Any, Dict
from tgartifacts.plugins import PluginContext

def run(context: PluginContext) -> Dict[str, Any]:
    click.echo(f"Running on {context.tdata_path}")
    return {"result": "done"}
```

## Writing a module

```
tgartifacts/modules/my_module/
├── __init__.py      # MyModule(BaseModule) instance as `module`
└── answer_cli.py    # click `command` object
```

```python
# __init__.py
from tgartifacts.modules.base import BaseModule

class MyModule(BaseModule):
    @property
    def name(self): return 'my-module'
    @property
    def description(self): return 'My custom module'
    @property
    def help_text(self): return 'Detailed help text with examples.'

module = MyModule()
```

```python
# answer_cli.py
import click

@click.command()
@click.argument('tdata_path', type=click.Path(exists=True))
def command(tdata_path):
    """My module help text."""
    click.echo(f"Running on {tdata_path}")
```

Modules are auto-discovered and registered at startup.

## Testing

```bash
pip install -e ".[dev]"
pytest tests/                      # all 162 tests
pytest tests/unit/                 # unit tests only
pytest tests/integration/          # integration tests only
pytest -m "not slow"               # skip slow bruteforce tests
pytest -m live                     # only real Telegram API tests
```

Test reports are generated at `reports/report.html` (pytest-html).

## tdata locations

| OS | Path |
|----|------|
| Windows | `%APPDATA%\Telegram Desktop\tdata` |
| macOS | `~/Library/Application Support/Telegram Desktop/tdata` |
| Linux (native) | `~/.local/share/TelegramDesktop/tdata` |
| Linux (Snap) | `~/snap/telegram-desktop/<rev>/.local/share/TelegramDesktop/tdata` |
| Linux (Flatpak) | `~/.var/app/org.telegram.desktop/data/TelegramDesktop/tdata` |

## Project structure

```
tgartifacts/
├── cli.py                            # Click entry point
├── __main__.py                       # python -m tgartifacts
├── modules/                          # Auto-discovered CLI modules
│   ├── base.py                       # BaseModule ABC
│   ├── __init__.py                   # discover_modules(), register_modules()
│   ├── info/                         # Account info + settings display
│   ├── bruteforce/                   # Passcode dictionary attack
│   │   └── bruteforcer.py            # Bruteforcer, BruteforceResult
│   ├── export_session/               # Session export (JSON / Telethon)
│   ├── extract_cache/                # TDEF cache extraction
│   ├── scan/                         # tdata auto-detection
│   │   └── scanner.py                # TDataLocation, scan_tdata()
│   ├── validate_session/             # Live session validation
│   ├── plugin/                       # Plugin runner
│   └── list_plugins/                 # Plugin listing
├── crypto/
│   ├── keys.py                       # create_local_key(), get_local_key()
│   └── decryptor.py                  # Decryptor (AES-IGE, AES-CTR), decrypt_tdf_legacy()
├── parsers/
│   ├── tdata_parser.py               # TDataParser (accounts, cache, MTP auth)
│   ├── tdf_reader.py                 # read_tdf() — TDF$ magic, MD5 validation
│   └── qt_stream.py                  # QtDataStreamReader
├── plugins/                          # Plugin system (each: __init__.py + answer_cli.py)
│   ├── base.py                       # BasePlugin, PluginContext
│   ├── manager.py                    # PluginManager (discovery + loading)
│   ├── audit/                        # Security audit (MITRE ATT&CK / D3FEND)
│   │   ├── auditor.py                # Auditor, Finding, AuditReport
│   │   └── answer_cli.py             # CLI output
│   ├── harden/                       # Interactive hardening (auto-fix)
│   │   ├── hardener.py               # Hardener, HardenAction, HardenResult
│   │   └── answer_cli.py             # CLI output
│   ├── timeline/                     # Forensic timeline + anomaly detection
│   │   ├── analyzer.py               # TimelineAnalyzer, TimelineEvent, TimelineAnomaly
│   │   └── answer_cli.py             # CLI output + activity tree
│   ├── hash_report/                  # SHA-256/MD5 hash report
│   │   ├── hasher.py                 # compute_hashes(), detect_type()
│   │   ├── report.py                 # collect_entries(), write_report()
│   │   └── answer_cli.py             # CLI output
│   └── report_generator/             # Full forensic report (HTML + JSON)
│       ├── collector.py              # collect_report_data()
│       ├── html_report/renderer.py   # HTML output
│       ├── json_report/renderer.py   # JSON output
│       └── answer_cli.py             # CLI output
├── models/
│   ├── MTPAuthorization.py           # MTPAuthorization dataclass
│   └── account.py                    # Account dataclass
├── exporters/
│   ├── json_exporter.py              # JSONExporter
│   └── report.py                     # ReportGenerator
└── utils/
    ├── extension_detector.py         # detect_media_extension() via python-magic
    └── session_validator.py          # SessionValidator, parse_string_session()
```

## License

MIT License — see [LICENSE](LICENSE).

##

By Dmeetrogon ^^
