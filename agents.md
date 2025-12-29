# TGArtifacts — Project Context for AI Agents

## What is this?
CLI forensic tool for Telegram Desktop artifact analysis. Extracts and analyzes data from `tdata` directory.

## Tech Stack
- **Language:** Python 3.10+
- **CLI:** click
- **Crypto:** tgcrypto (AES-256-IGE), PBKDF2-HMAC-SHA512
- **Output:** rich (terminal), Jinja2 (HTML reports)

## Project Structure
```
tgartifacts/
├── cli.py              # Entry point, click commands
├── core/
│   ├── tdata_parser.py # Parse tdata structure
│   ├── decryptor.py    # AES-256-IGE decryption
│   ├── parser.py       # Qt Data Stream parser
│   └── bruteforce.py   # Passcode bruteforce
├── utils/
│   ├── crypto.py       # Key derivation, encryption helpers
│   └── tdf.py          # TDF file format parser
└── templates/          # Jinja2 HTML templates (future)
```

## Key Concepts

### tdata Directory
Local Telegram Desktop storage containing:
- Account info (user_id, DC ID, auth keys)
- Media cache (images, videos, documents, voice)
- Settings and configurations

### Encryption (Updated Implementation)
- Files encrypted with AES-256-IGE (MTProto old scheme)
- Two-stage decryption:
  1. **Passcode key**: PBKDF2-HMAC-SHA512(SHA512(salt + passcode + salt), salt, iterations, 256 bytes)
     - iterations = 1 (no passcode) or 100,000 (with passcode)
  2. **Local key**: decrypt(key_encrypted, passcode_key) from key_datas file
- TDF format: magic "TDF$" + version + encrypted data + MD5

### What We Extract
✅ user_id, DC ID from MTP authorization
✅ Account directory enumeration
❌ Phone number (requires additional parsing)
❌ Message history (stored on Telegram servers, not local)

## Technical Implementation

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

### Qt Data Stream Parser
Binary format used by Telegram Desktop for serialization:
- **uint32/int32/uint64**: Big-endian integers
- **QByteArray**: int32 length + raw bytes (length ≤ 0 = empty/null)
- Used to parse decrypted data and settings blocks

### Decryption Pipeline (Corrected)
1. **Read key_datas file** (TDF format)
2. **Extract components**:
   - `salt` (QByteArray, 32 bytes)
   - `key_encrypted` (QByteArray)
   - `info_encrypted` (QByteArray)
3. **Generate passcode key**:
   - Pre-hash: `SHA512(salt + passcode + salt)`
   - `PBKDF2-HMAC-SHA512(pre_hash, salt, iterations, 256)`
   - iterations = 1 (no passcode) or 100,000 (with passcode)
4. **Decrypt key_encrypted** → local_key (256 bytes)
5. **Read account data file** (tdata/{account_dir}s)
6. **Decrypt with local_key** → settings blocks
7. **Parse settings blocks** → find dbiMtpAuthorization (0x4B)
8. **Extract user_id and dc_id**

### Crypto Functions
- **prepare_aes_oldmtp(key, msg_key, send=False)** → Derives AES key/IV using SHA1
  - Offset x = 8 for decryption (send=False)
  - Combines local_key with msg_key via 4x SHA1 operations
  - Returns (aes_key, aes_iv) for IGE mode
- **decrypt_local(encrypted, key)** → AES-256-IGE decryption
  - First 16 bytes = msg_key (SHA1 checksum)
  - Verifies decrypted data integrity: SHA1(decrypted)[:16] == msg_key
  - Returns decrypted data without 4-byte length prefix

### tdata Structure
```
tdata/
├── key_datas           # Encrypted localKey (always exists in new versions)
├── settingss           # Application settings (TDF)
├── D877F783D5D3EF8C/   # Account directory (MD5 hash of "data")
│   ├── maps            # Storage map (TDF)
│   ├── configs         # Account configs
│   └── ...             # Cached data
├── D877F783D5D3EF8Cs   # Account MTP data file (TDF)
└── ...
```

**Important**: Account data is NOT in the maps file inside the directory.
- Account directory name = MD5("data")[:8] reversed hex pairs
- Account data file = {directory_name}s in tdata root
- Contains settings blocks with dbiMtpAuthorization

## Main Commands
```bash
tgartifacts info <path>                    # Quick structure info
tgartifacts analyze <path>                 # Full analysis (no passcode needed if not set)
tgartifacts analyze <path> --passcode "X"  # With passcode
tgartifacts bruteforce <path> -a ACCOUNT   # Bruteforce passcode
```

## Coding Guidelines
- Type hints everywhere
- Docstrings for public methods
- Use EXACT implementations from working tools (ntqbit/tdesktop-decrypter)
- Error handling — graceful degradation
- Forensic soundness — never modify source files

## Current Status
✅ TDF file format parser
✅ Qt Data Stream parser
✅ Two-stage decryption (passcode_key → local_key)
✅ Account data file parsing
✅ MTP authorization extraction
✅ Settings blocks parsing
✅ Bruteforce module
✅ CLI commands (info, analyze, bruteforce)

## References
- Telegram Desktop source: https://github.com/telegramdesktop/tdesktop
- tdesktop-decrypter (WORKING TOOL): https://github.com/ntqbit/tdesktop-decrypter
- telegram-desktop-decrypt: https://github.com/atilaromero/telegram-desktop-decrypt
