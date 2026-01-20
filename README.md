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

## Installation

```bash
pip install .
```

Or for development:

```bash
pip install -e ".[dev]"
```

### Requirements

- Python 3.10+
- Dependencies: click, tgcrypto, rich, python-magic

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

Validate an extracted Telethon StringSession:

```bash
tgartifacts validate-session "1AgAAAAA..."
```

Requires `telethon` package:

```bash
pip install telethon
```

## tdata Location

Default `tdata` paths:

| OS | Path |
|----|------|
| Windows | `%APPDATA%\Telegram Desktop\tdata` |
| macOS | `~/Library/Application Support/Telegram Desktop/tdata` |
| Linux | `~/.local/share/TelegramDesktop/tdata` |

## Project Structure

```
tgartifacts/
├── cli.py              # CLI interface
├── crypto/
│   ├── decryptor.py    # AES decryption for tdata files
│   └── keys.py         # Key derivation (PBKDF2, local key)
├── parsers/
│   ├── tdata_parser.py # Main tdata parser
│   ├── tdf_reader.py   # TDF file format reader
│   └── qt_stream.py    # Qt data stream parser
├── models/
│   └── account.py      # Account data models
├── exporters/
│   └── json_exporter.py
└── utils/
    ├── session_validator.py  # Telethon session validation
    ├── extension_detector.py # File type detection
    └── timeline.py
```

## License

MIT License - see [LICENSE](LICENSE) file.

## Author

Dmeetrogon