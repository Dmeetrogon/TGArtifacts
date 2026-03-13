# TGArtifacts — Project Context for AI Agents

## What is this?
CLI forensic tool for Telegram Desktop artifact analysis. Extracts and analyzes data from `tdata` directory.

## Tech Stack
- **Language:** Python 3.10+
- **CLI:** click
- **Crypto:** tgcrypto (AES-256-IGE, AES-256-CTR), PBKDF2-HMAC-SHA512
- **Session:** telethon (StringSession export/validation)
- **Output:** rich (terminal), JSON export

## Project Structure
```
tgartifacts/
├── cli.py              # Entry point, click commands
├── crypto/
│   ├── decryptor.py    # AES-256-IGE (TDF), AES-256-CTR (TDEF) decryption
│   └── keys.py         # Key derivation (PBKDF2, local key extraction)
├── parsers/
│   ├── tdata_parser.py # Main tdata directory parser
│   ├── tdf_reader.py   # TDF file format reader
│   └── qt_stream.py    # Qt Data Stream binary parser
├── plugins/
│   ├── base.py         # BasePlugin abstract class, PluginContext dataclass
│   ├── manager.py      # PluginManager (load from directory, register)
│   └── contrib/        # Built-in plugins
│       └── hash_report.py
├── models/
│   └── account.py      # Account data models
├── exporters/
│   ├── json_exporter.py
│   └── report.py
└── utils/
    ├── session_validator.py  # Telethon StringSession validation
    ├── extension_detector.py # File type detection via magic bytes
    └── timeline.py
```

## Key Concepts

### tdata Directory
Local Telegram Desktop storage containing:
- Account info (user_id, DC ID, auth keys)
- Media cache (images, videos, documents, voice)
- Settings and configurations

### Encryption
- TDF files encrypted with AES-256-IGE (MTProto old scheme)
- TDEF files encrypted with AES-256-CTR (salt-based key derivation)
- Two-stage decryption:
  1. **Passcode key**: PBKDF2-HMAC-SHA512(SHA512(salt + passcode + salt), salt, iterations, 256 bytes)
     - iterations = 1 (no passcode) or 100,000 (with passcode)
  2. **Local key**: decrypt(key_encrypted, passcode_key) from key_datas file

### TDF File Format
```
+----------------+
| "TDF$" (4b)    | Magic bytes
+----------------+
| Version (4b)   | Little-endian uint32
+----------------+
| Data (N bytes) | Encrypted payload
+----------------+
| MD5 (16b)      | MD5(data + len(data) + version + magic)
+----------------+
```

### TDEF File Format
```
+-------------------+
| "TDEF" (4b)       | Magic bytes
+-------------------+
| Salt (64b)        | Random salt for key derivation
+-------------------+
| Encrypted (N bytes)| AES-256-CTR encrypted content
+-------------------+
```

### Decryption Pipeline
1. Read key_datas file (TDF format)
2. Extract: salt (32 bytes), key_encrypted, info_encrypted
3. Generate passcode key: PBKDF2-HMAC-SHA512(pre_hash, salt, iterations, 256)
4. Decrypt key_encrypted → local_key (256 bytes)
5. Read account data file (tdata/{account_dir}s)
6. Decrypt with local_key → settings blocks
7. Parse settings blocks → find dbiMtpAuthorization (0x4B)
8. Extract user_id, dc_id, auth_keys

### tdata Structure
```
tdata/
├── key_datas           # Encrypted localKey
├── settingss           # Application settings (TDF)
├── D877F783D5D3EF8C/   # Account directory
│   ├── maps            # Storage map (TDF)
│   ├── configs         # Account configs
│   └── ...
├── D877F783D5D3EF8Cs   # Account MTP data file (TDF)
└── user_data/
    ├── media_cache/    # Encrypted media files (TDEF)
    └── cache/          # Encrypted cache files (TDEF)
```

## Plugin System

Volatility-inspired plugin architecture:
- `BasePlugin` — abstract class with `name`, `description`, `version`, `run(context)`
- `PluginContext` — dataclass providing access to tdata_path, accounts, cache_files, local_key
- `PluginManager` — scans directories for .py files, discovers BasePlugin subclasses
- Plugins placed in `plugins/contrib/` are loaded automatically
- Custom plugin directories supported via `--plugins-dir` CLI option

## CLI Commands
```bash
tgartifacts info <path> [-p passcode] [--show-keys]
tgartifacts export-session <path> <output> [-p passcode] [-f json|telethon]
tgartifacts extract-cache <path> <output_dir> [-p passcode]
tgartifacts validate-session <string_session>
tgartifacts plugin <plugin_name> <path> [-p passcode] [-o output] [--plugins-dir dir]
tgartifacts list-plugins [--plugins-dir dir]
```

## Current Status
✅ TDF file format parser (magic TDF$, version, encrypted data, MD5)
✅ TDEF file format parser (magic TDEF, AES-256-CTR decryption)
✅ Qt Data Stream parser (uint32, int32, uint64, QByteArray)
✅ Two-stage decryption (passcode_key → local_key)
✅ Account data file parsing ({account_dir}s)
✅ MTP authorization extraction (user_id, dc_id, auth_keys)
✅ Settings blocks parsing (dbiMtpAuthorization 0x4B)
✅ Media cache extraction (TDEF files from user_data/media_cache and cache)
✅ Streaming cache reassembly (multi-part media files)
✅ File type detection via magic bytes
✅ Session export (JSON, Telethon StringSession)
✅ Session validation via Telegram API
✅ Plugin system (BasePlugin, PluginManager, contrib directory)
✅ CLI commands (info, export-session, extract-cache, validate-session, plugin, list-plugins)

## Coding Guidelines
- Type hints everywhere
- No comments unless logic is non-obvious
- Forensic soundness — never modify source files
- Error handling — graceful degradation, informative messages
- Plugins must only access data through PluginContext

## References
- Telegram Desktop source: https://github.com/telegramdesktop/tdesktop
- tdesktop-decrypter: https://github.com/ntqbit/tdesktop-decrypter
- telegram-desktop-decrypt: https://github.com/atilaromero/telegram-desktop-decrypt
