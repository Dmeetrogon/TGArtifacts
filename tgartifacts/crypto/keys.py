import os
import hashlib
from io import BytesIO
from pathlib import Path
from typing import Optional

from ..parsers.qt_stream import QtDataStreamReader
from ..parsers.tdf_reader import read_tdf


def get_key_datas_version(tdata_path: str) -> Optional[int]:
    key_datas_path = os.path.join(tdata_path, 'key_datas')
    if not os.path.exists(key_datas_path):
        return None
    try:
        data = read_tdf(key_datas_path)
        return data['version']
    except Exception:
        return None


def create_local_key(passcode: str, salt: bytes, tdesktop_version: int) -> bytes:
    LOCAL_ENCRYPT_ITER_COUNT = 4000
    LOCAL_ENCRYPT_NO_PWD_ITER_COUNT = 4
    STRONG_ITERATIONS_COUNT = 100000

    if tdesktop_version < 2001014:
        if not passcode:
            return hashlib.pbkdf2_hmac('sha1', b'', salt, LOCAL_ENCRYPT_NO_PWD_ITER_COUNT, 136)
        else:
            return hashlib.pbkdf2_hmac('sha1', passcode.encode('utf-8'), salt, LOCAL_ENCRYPT_ITER_COUNT, 136)
    else:
        if not passcode:
            pass_hash = hashlib.sha512(salt + salt).digest()
            return hashlib.pbkdf2_hmac('sha512', pass_hash, salt, 1, 136)
        else:
            passcode_bytes = passcode.encode('utf-8')
            pass_hash = hashlib.sha512(salt + passcode_bytes + salt).digest()
            return hashlib.pbkdf2_hmac('sha512', pass_hash, salt, STRONG_ITERATIONS_COUNT, 136)


def create_legacy_local_key(passcode: bytes, salt: bytes) -> bytes:
    iterations = 4000 if passcode else 4
    return hashlib.pbkdf2_hmac('sha1', passcode, salt, iterations, 136)


def decrypt_key_datas_info(tdata_path: Path, local_key: bytes) -> dict:
    from .decryptor import decrypt_tdf_legacy

    key_datas_path = os.path.join(tdata_path, 'key_datas')
    tdf = read_tdf(key_datas_path)
    reader = QtDataStreamReader(tdf['data'])
    reader.read_bytearray()
    reader.read_bytearray()
    info_encrypted = reader.read_bytearray()

    if info_encrypted is None:
        return {'account_indexes': [], 'main_account': 0}

    info = decrypt_tdf_legacy(info_encrypted, local_key)
    stream = BytesIO(info)
    count = int.from_bytes(stream.read(4), 'big', signed=True)
    indexes = [int.from_bytes(stream.read(4), 'big', signed=True) for _ in range(count)]
    main = int.from_bytes(stream.read(4), 'big', signed=True)
    return {'account_indexes': indexes, 'main_account': main}


def get_local_key(tdata_path: Path, passcode: Optional[str] = None) -> bytes:
    from .decryptor import decrypt_tdf_legacy

    if passcode is None:
        passcode = ""

    key_datas_path = os.path.join(tdata_path, 'key_datas')
    if not os.path.exists(key_datas_path):
        raise FileNotFoundError("key_datas file not found")

    key_datas_tdf = read_tdf(key_datas_path)
    tdesktop_version = key_datas_tdf['version']
    reader = QtDataStreamReader(key_datas_tdf['data'])
    salt = reader.read_bytearray()
    key_encrypted = reader.read_bytearray()
    info_encrypted = reader.read_bytearray()

    if salt is None or key_encrypted is None:
        raise ValueError("Invalid key_datas format")

    passcode_key = create_local_key(passcode, salt, tdesktop_version)
    local_key = decrypt_tdf_legacy(key_encrypted, passcode_key)

    return local_key
