"""Key derivation and key_datas file handling."""

import os
import hashlib
from pathlib import Path
from typing import Optional

from ..parsers.qt_stream import QtDataStreamReader
from ..parsers.tdf_reader import read_tdf


def get_key_datas_version(tdata_path: str) -> Optional[int]:
    """Get version from key_datas file.

    Args:
        tdata_path: Path to tdata directory

    Returns:
        Version number or None if file doesn't exist
    """
    key_datas_path = os.path.join(tdata_path, 'key_datas')
    if not os.path.exists(key_datas_path):
        return None

    try:
        data = read_tdf(key_datas_path)
        return data['version']
    except:
        return None


def create_local_key(passcode: str, salt: bytes, tdesktop_version: int) -> bytes:
    """Create local key using PBKDF2.

    Based on verified telegram2john.py from John the Ripper project.
    Supports both old (< 2.1.14) and new (>= 2.1.14) Telegram Desktop versions.

    Args:
        passcode: User passcode (empty string if no password)
        salt: Salt for key derivation (32 bytes)
        tdesktop_version: Telegram Desktop version number (e.g., 2001014 for v2.1.14)

    Returns:
        Derived key bytes (136 bytes) for decrypting key_datas

    References:
        - https://github.com/openwall/john/blob/bleeding-jumbo/run/telegram2john.py
        - https://github.com/openwall/john/issues/4387
    """
    # Constants from official Telegram Desktop
    LocalEncryptIterCount = 4000           # Old versions WITH passcode
    LocalEncryptNoPwdIterCount = 4         # Old versions WITHOUT passcode
    kStrongIterationsCount = 100000        # New versions WITH passcode

    # OLD ALGORITHM (Telegram Desktop < 2.1.14, AppVersion < 2001014)
    if tdesktop_version < 2001014:
        if not passcode:
            # No passcode: PBKDF2-SHA1 with 4 iterations
            return hashlib.pbkdf2_hmac(
                'sha1',
                b'',
                salt,
                LocalEncryptNoPwdIterCount,
                136
            )
        else:
            # With passcode: PBKDF2-SHA1 with 4000 iterations
            return hashlib.pbkdf2_hmac(
                'sha1',
                passcode.encode('utf-8'),
                salt,
                LocalEncryptIterCount,
                136
            )
    # NEW ALGORITHM (Telegram Desktop >= 2.1.14, AppVersion >= 2001014)
    else:
        if not passcode:
            # No passcode: SHA512(salt + salt), then 1 iteration PBKDF2-HMAC-SHA512
            pass_hash = hashlib.sha512(salt + salt).digest()
            return hashlib.pbkdf2_hmac(
                'sha512',
                pass_hash,
                salt,
                1,
                136
            )
        else:
            # With passcode: SHA512(salt + passcode + salt), then 100k iterations
            passcode_bytes = passcode.encode('utf-8')
            pass_hash = hashlib.sha512(salt + passcode_bytes + salt).digest()
            return hashlib.pbkdf2_hmac(
                'sha512',
                pass_hash,
                salt,
                kStrongIterationsCount,
                136
            )


def get_local_key_from_key_datas(tdata_path: str, passcode: Optional[str] = None) -> bytes:
    """Get local encryption key from key_datas file (two-stage decryption).

    Args:
        tdata_path: Path to tdata directory
        passcode: Optional user passcode (None = no password)

    Returns:
        Local encryption key (256 bytes)

    Raises:
        FileNotFoundError: If key_datas file doesn't exist
        ValueError: If key_datas has invalid format or decryption fails
    """
    from .decryptor import decrypt_local_TDF

    # Use empty string if no passcode provided
    if passcode is None:
        passcode = ""

    # Read key_datas file
    key_datas_path = os.path.join(tdata_path, 'key_datas')
    if not os.path.exists(key_datas_path):
        raise FileNotFoundError("key_datas file not found")

    key_datas_tdf = read_tdf(key_datas_path)
    tdesktop_version = key_datas_tdf['version']
    reader = QtDataStreamReader(key_datas_tdf['data'])

    # Extract salt, key_encrypted, info_encrypted
    salt = reader.read_bytearray()
    key_encrypted = reader.read_bytearray()
    info_encrypted = reader.read_bytearray()

    if salt is None or key_encrypted is None:
        raise ValueError("Invalid key_datas format")

    # Stage 1: Create passcode key and decrypt key_encrypted to get local_key
    passcode_key = create_local_key(passcode, salt, tdesktop_version)
    local_key = decrypt_local_TDF(key_encrypted, passcode_key)

    return local_key