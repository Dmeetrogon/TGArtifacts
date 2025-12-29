import os
import hashlib
from typing import Optional, Tuple


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
        from ..utils.tdf import read_tdf
        data = read_tdf(key_datas_path)
        return data['version']
    except:
        return None


def create_local_key(passcode: str, salt: bytes) -> bytes:
    """Create local key using PBKDF2.

    Based on official ntqbit/tdesktop-decrypter implementation.

    Args:
        passcode: User passcode (empty string if no password)
        salt: Salt for key derivation (32 bytes)

    Returns:
        Derived key bytes (256 bytes)
    """
    # Determine iterations based on password presence
    if passcode:
        iterations = 100000  # kStrongIterationsCount
    else:
        iterations = 1

    # Pre-hash: SHA512(salt + passcode + salt)
    passcode_bytes = passcode.encode('utf-8')
    password = hashlib.sha512(salt + passcode_bytes + salt).digest()

    # PBKDF2-HMAC-SHA512, 256 bytes output
    return hashlib.pbkdf2_hmac('sha512', password, salt, iterations, 256)


def get_local_key_from_key_datas(tdata_path: str, passcode: Optional[str] = None) -> bytes:
    """Get local encryption key from key_datas file (two-stage decryption).

    Args:
        tdata_path: Path to tdata directory
        passcode: Optional user passcode (None = no password)

    Returns:
        Local encryption key (256 bytes)
    """
    from ..utils.tdf import read_tdf
    from ..core.decryptor import decrypt_local
    from ..core.parser import QtDataStreamReader

    # Use empty string if no passcode provided
    if passcode is None:
        passcode = ""

    # Read key_datas file
    key_datas_path = os.path.join(tdata_path, 'key_datas')
    if not os.path.exists(key_datas_path):
        raise FileNotFoundError("key_datas file not found")

    key_datas_tdf = read_tdf(key_datas_path)
    reader = QtDataStreamReader(key_datas_tdf['data'])

    # Extract salt, key_encrypted, info_encrypted
    salt = reader.read_bytearray()
    key_encrypted = reader.read_bytearray()
    info_encrypted = reader.read_bytearray()

    if salt is None or key_encrypted is None:
        raise ValueError("Invalid key_datas format")

    # Stage 1: Create passcode key and decrypt key_encrypted to get local_key
    passcode_key = create_local_key(passcode, salt)
    local_key = decrypt_local(key_encrypted, passcode_key)

    return local_key