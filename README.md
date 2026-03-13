# TGArtifacts

CLI forensic tool for Telegram Desktop artifact analysis. Extract and analyze data from Telegram Desktop's `tdata` directory.

> **Disclaimer:** This tool is intended for educational purposes, authorized forensic investigations, and security research only.

## Features

- Parse Telegram Desktop `tdata` directory structure
- Extract account information (User ID, DC ID, auth keys)
- Export sessions to JSON or Telethon StringSession format
- Decrypt and extract cached media files (images, videos, documents)
- Validate extracted sessions via Telegram API
- Support for passcode-protected tdata
- Bruteforce passcode (dictionary attack and precomputed keys)
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

Or for development:

```bash
pip install -e ".[dev]"
```

### Requirements

- Python 3.10+
- Dependencies: click, tgcrypto, rich, python-magic, telethon

## Usage

### Show account information

```bash
tgartifacts info /path/to/tdata
```

With passcode:

```bash
tgartifacts info /path/to/tdata -p "your_passcode"
```

Show full auth keys:

```bash
tgartifacts info /path/to/tdata --show-keys
```

### Export session

Export to JSON:

```bash
tgartifacts export-session /path/to/tdata session.json
```

Export to Telethon StringSession:

```bash
tgartifacts export-session /path/to/tdata session.txt -f telethon
```

### Extract cached media

```bash
tgartifacts extract-cache /path/to/tdata ./output
```

### Validate session

```bash
tgartifacts validate-session "1AgAAAAA..."
```

### Plugins

List available plugins:

```bash
tgartifacts list-plugins
```

Run a plugin:

```bash
tgartifacts plugin hash-report /path/to/tdata
```

Run with custom plugins directory:

```bash
tgartifacts plugin my-analyzer /path/to/tdata --plugins-dir ~/my-plugins/
```

### Writing a plugin

Create a `.py` file in the `plugins/contrib/` directory or any custom directory:

```python
from tgartifacts.plugins import BasePlugin, PluginContext


class MyPlugin(BasePlugin):
    name = "my-plugin"
    description = "My custom analyzer"
    version = "0.1.0"

    def run(self, context: PluginContext):
        # context.tdata_path — path to tdata directory
        # context.accounts — list of parsed accounts
        # context.cache_files — list of cached TDEF file paths
        # context.output_dir — output directory (optional)
        return {"result": "done"}
```

## tdata Location

Default `tdata` paths:

| OS | Path |
|----|------|
| Windows | `%APPDATA%\Telegram Desktop\tdata` |
| macOS | `~/Library/Application Support/Telegram Desktop/tdata` |
| Linux | `~/.local/share/TelegramDesktop/tdata` |

### Finding tdata

Linux / macOS:
```bash
find / -name "tdata" 2>/dev/null
```

Windows:
```bash
dir C:\tdata /s /b /ad 2>nul
```

## Project Structure

```
tgartifacts/
├── cli.py                        # CLI interface (click)
├── crypto/
│   ├── decryptor.py              # AES decryption (TDF, TDEF)
│   └── keys.py                   # Key derivation (PBKDF2, local key)
├── parsers/
│   ├── tdata_parser.py           # Main tdata directory parser
│   ├── tdf_reader.py             # TDF file format reader
│   └── qt_stream.py              # Qt Data Stream parser
├── plugins/
│   ├── base.py                   # BasePlugin, PluginContext
│   ├── manager.py                # PluginManager (discovery, loading)
│   └── contrib/                  # Built-in plugins
│       └── hash_report.py        # SHA-256 hash report
├── models/
│   └── account.py                # Account data models
├── exporters/
│   ├── json_exporter.py          # JSON export
│   └── report.py                 # Report generation
└── utils/
    ├── session_validator.py      # Telethon session validation
    ├── extension_detector.py     # File type detection (magic bytes)
    └── timeline.py               # Timeline generation
```

## License

MIT License - see [LICENSE](LICENSE) file.

## Author

Dmeetrogon
