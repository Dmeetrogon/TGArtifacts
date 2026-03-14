# TGArtifacts

CLI forensic tool for Telegram Desktop artifact analysis. Extract and analyze data from Telegram Desktop's `tdata` directory.

> **Disclaimer:** This tool is intended for educational purposes, authorized forensic investigations, and security research only.

## Features

- Auto-detect `tdata` directories (native, Snap, Flatpak)
- Parse `tdata` structure with multi-account support
- Extract account information (User ID, DC ID, auth keys)
- Export sessions to JSON or Telethon StringSession format
- Decrypt and extract cached media files (TDEF → images, videos, documents)
- Validate extracted sessions via Telegram API
- Security audit with MITRE ATT&CK / D3FEND mapping
- Bruteforce passcode via dictionary attack (multi-threaded)
- Modular architecture with auto-discovery
- Plugin system for extensions (hash-report, report-generator built-in)

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
```

Displays User ID, DC ID, auth key IDs, passcode status, cached TDEF file count. Use `--show-keys` / `-k` to print full 512-char hex auth keys.

### `audit` — Security audit

```bash
tgartifacts audit /path/to/tdata
```

Checks: passcode presence, passcode strength (top-50 dictionary), file permissions (world/group-readable), encryption version (legacy vs modern PBKDF2), multi-account exposure. Each finding mapped to MITRE ATT&CK / D3FEND IDs.

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

Dictionary attack against passcode-protected tdata. Speed: ~3 passwords/s per thread (limited by PBKDF2 100k iterations on modern versions). Use `--threads` / `-t` to parallelize.

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
tgartifacts plugin hash-report /path/to/tdata
tgartifacts plugin report-generator /path/to/tdata -o ./output -p "passcode"
tgartifacts plugin my-analyzer /path/to/tdata --plugins-dir ~/my-plugins/
```

Built-in plugins:
- **hash-report** — SHA-256 + MD5 hashes for all files, grouped by detected type
- **report-generator** — Full forensic report (cache extraction, session export, validation, hashing) → HTML + JSON

## Writing a plugin

Create a directory under `tgartifacts/plugins/` (or any custom `--plugins-dir`):

```
my_plugin/
├── __init__.py      # plugin class
└── logic.py         # business logic (keep __init__.py minimal)
```

```python
from tgartifacts.plugins import BasePlugin, PluginContext

class MyPlugin(BasePlugin):
    name = "my-plugin"
    description = "My custom analyzer"
    version = "0.1.0"

    def run(self, context: PluginContext):
        # context.tdata_path, context.passcode, context.output_dir
        return {"result": "done"}
```

## Writing a module

Create a package in `tgartifacts/modules/`:

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
pytest tests/                      # all 102 tests
pytest tests/unit/                 # unit tests only
pytest tests/integration/          # integration tests only
pytest -m "not slow"               # skip slow bruteforce tests
pytest -m live                     # only real Telegram API tests
```

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
│   ├── info/                         # Account info display
│   ├── audit/                        # Security audit (MITRE ATT&CK)
│   │   └── auditor.py               # Auditor, Finding, AuditReport
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
├── plugins/
│   ├── base.py                       # BasePlugin, PluginContext
│   ├── manager.py                    # PluginManager (flat .py + subdirectory loading)
│   ├── hash_report/                  # SHA-256/MD5 hash report plugin
│   │   ├── __init__.py               # HashReportPlugin (minimal)
│   │   ├── hasher.py                 # compute_hashes(), detect_type()
│   │   └── report.py                 # collect_entries(), write_report()
│   └── report_generator/             # Full forensic report plugin
│       ├── __init__.py               # ReportGeneratorPlugin
│       ├── collector.py              # collect_report_data()
│       ├── html_report/renderer.py   # HTML output
│       └── json_report/renderer.py   # JSON output
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
