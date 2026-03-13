# TGArtifacts

CLI forensic tool for Telegram Desktop artifact analysis. Extract and analyze data from Telegram Desktop's `tdata` directory.

> **Disclaimer:** This tool is intended for educational purposes, authorized forensic investigations, and security research only.

## Features

- Auto-detect `tdata` directories (native, Snap, Flatpak)
- Parse `tdata` structure with multi-account support
- Extract account information (User ID, DC ID, auth keys)
- Export sessions to JSON or Telethon StringSession format
- Decrypt and extract cached media files (images, videos, documents)
- Validate extracted sessions via Telegram API
- Security audit with MITRE ATT&CK / D3FEND mapping
- Bruteforce passcode (dictionary attack and precomputed rainbow tables)
- Modular architecture with auto-discovery
- Plugin system for community extensions

## Installation

```bash
git clone --depth 1 https://github.com/Dmeetrogon/TGArtifacts.git && cd TGArtifacts
```

```bash
python3 -m venv venv && source venv/bin/activate
```

```bash
pip install .
```

With optional modules:

```bash
pip install ".[validate-session]"
pip install ".[all]"
```

For development:

```bash
pip install -e ".[dev]"
```

### Requirements

- Python 3.10+
- Core: click, tgcrypto, rich, python-magic
- Optional: telethon (for session validation)

## Usage

### Scan for tdata directories

```bash
tgartifacts scan
tgartifacts scan -p /mnt/backup/tdata
```

### Show account information

```bash
tgartifacts info /path/to/tdata
tgartifacts info /path/to/tdata -p "passcode" -k
```

### Security audit

```bash
tgartifacts audit /path/to/tdata
```

Checks passcode strength, file permissions, encryption version and maps findings to MITRE ATT&CK / D3FEND techniques.

### Export session

```bash
tgartifacts export-session /path/to/tdata session.json
tgartifacts export-session /path/to/tdata session.txt -f telethon
```

### Extract cached media

```bash
tgartifacts extract-cache /path/to/tdata ./output
tgartifacts extract-cache /path/to/tdata ./output -p "passcode"
```

### Bruteforce passcode

```bash
tgartifacts bruteforce /path/to/tdata -w wordlist.txt
tgartifacts bruteforce /path/to/tdata -w wordlist.txt -t 4
```

### Validate session

Requires `pip install tgartifacts[validate-session]`

```bash
tgartifacts validate-session "1AgAAAAA..."
```

### Plugins

```bash
tgartifacts list-plugins
tgartifacts plugin hash-report /path/to/tdata
tgartifacts plugin my-analyzer /path/to/tdata --plugins-dir ~/my-plugins/
```

### Writing a plugin

Create a `.py` file in `plugins/contrib/` or any custom directory:

```python
from tgartifacts.plugins import BasePlugin, PluginContext


class MyPlugin(BasePlugin):
    name = "my-plugin"
    description = "My custom analyzer"
    version = "0.1.0"

    def run(self, context: PluginContext):
        return {"result": "done"}
```

### Writing a module

Create a package in `tgartifacts/modules/`:

```
tgartifacts/modules/my_module/
├── __init__.py      # MyModule(BaseModule) instance
└── answer_cli.py    # click command
```

```python
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

Modules are auto-discovered and registered at startup.

## tdata Location

| OS | Path |
|----|------|
| Windows | `%APPDATA%\Telegram Desktop\tdata` |
| macOS | `~/Library/Application Support/Telegram Desktop/tdata` |
| Linux | `~/.local/share/TelegramDesktop/tdata` |
| Linux (Snap) | `~/snap/telegram-desktop/<rev>/.local/share/TelegramDesktop/tdata` |
| Linux (Flatpak) | `~/.var/app/org.telegram.desktop/data/TelegramDesktop/tdata` |

Or auto-detect:

```bash
tgartifacts scan
```

## Project Structure

```
tgartifacts/
├── cli.py                        # Entry point
├── modules/                      # Auto-discovered modules
│   ├── base.py                   # BaseModule ABC
│   ├── audit/                    # Security audit (MITRE ATT&CK)
│   ├── bruteforce/               # Passcode bruteforce
│   ├── export_session/           # Session export (JSON, Telethon)
│   ├── extract_cache/            # Media cache extraction
│   ├── info/                     # Account information
│   ├── list_plugins/             # Plugin listing
│   ├── plugin/                   # Plugin runner
│   ├── scan/                     # tdata auto-detection
│   └── validate_session/         # Session validation (Telethon)
├── crypto/
│   ├── decryptor.py              # AES-256-IGE (TDF), AES-256-CTR (TDEF)
│   └── keys.py                   # Key derivation (PBKDF2)
├── parsers/
│   ├── tdata_parser.py           # Main tdata parser
│   ├── tdf_reader.py             # TDF file format
│   └── qt_stream.py              # Qt Data Stream
├── plugins/
│   ├── base.py                   # BasePlugin, PluginContext
│   ├── manager.py                # PluginManager
│   └── contrib/                  # Built-in plugins
├── exporters/
│   ├── json_exporter.py          # JSON export
│   └── report.py                 # Report generation
└── utils/
    ├── extension_detector.py     # File type detection (magic bytes)
    └── session_validator.py      # Telethon session validation
```

## License

MIT License - see [LICENSE](LICENSE) file.

## Author

Dmeetrogon
