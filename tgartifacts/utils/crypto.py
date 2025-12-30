import os
import hashlib
import tgcrypto
from typing import Optional, Tuple

from tgartifacts.core.parser import QtDataStreamReader
from tgartifacts.utils.tdf import read_tdf


def decrypt_TDEF_file(file_path, local_key) -> bytes:
    with open(file_path, 'rb') as file:
        magic_bytes = file.read(4)
        if magic_bytes != b'TDEF':
            raise ValueError(f"Invalid magic bytes. Expected b'TDEF', got {magic_bytes}")
        salt = file.read(64)
        if (len(salt)) != 64:
            raise ValueError(f"Salt too short, expected 64 bytes, got {len(salt)} bytes")
        encrypted_header = file.read(48)
        if (len(encrypted_header)) != 48:
            raise ValueError(f"Encrypted header too short, expected 48 bytes, got {len(encrypted_header)} bytes")
        real_key = hashlib.sha256(
            local_key[:128] + salt[:32]
        ).digest()
        iv = hashlib.sha256(
            local_key[128:] + salt[32:64]
        ).digest()[:16]
        header_decrypted = tgcrypto.ctr256_decrypt(
            encrypted_header,
            real_key,
            iv,
            bytes(1)
        )
        data_part = header_decrypted[:16]
        stored_checksum = header_decrypted[16:48]

        expected_checksum = hashlib.sha256(
            local_key + salt + data_part
        ).digest()

        if stored_checksum != expected_checksum:
            raise ValueError("Checksum mismatch! Wrong key or corrupted file")
        encrypted_data = file.read()
        blocks_processed = len(encrypted_header) // 16
        iv_int = int.from_bytes(iv, byteorder='big')
        new_iv_int = (iv_int + blocks_processed) % (2 ** 128)
        new_iv = new_iv_int.to_bytes(16, byteorder='big')

        decrypted_data = tgcrypto.ctr256_decrypt(
            encrypted_data,
            real_key,
            new_iv,
            bytes(1)
        )

        return decrypted_data