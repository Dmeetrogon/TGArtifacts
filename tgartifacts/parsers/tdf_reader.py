"""TDF file format reader (TDF$ magic bytes)."""

import struct
import hashlib


def read_tdf(filepath: str) -> dict:
    """Read and validate TDF file.

    TDF format:
    - Magic: "TDF$" (4 bytes)
    - Version: uint32 little-endian
    - Data: N bytes (encrypted)
    - MD5: 16 bytes checksum

    Args:
        filepath: Path to TDF file

    Returns:
        Dictionary with 'version', 'data', 'md5_valid' keys

    Raises:
        ValueError: If file is invalid or checksum mismatch
    """
    with open(filepath, 'rb') as file:
        content = file.read()

    if len(content) < 24:
        raise ValueError("File too small")

    magic_bytes = content[0:4]
    if magic_bytes != b'TDF$':
        raise ValueError(f"Invalid magic bytes {magic_bytes}")

    version = struct.unpack('<I', content[4:8])[0]
    encrypted_data = content[8:-16]
    stored_md5 = content[-16:]

    # MD5 = hash(encrypted_data + len(encrypted_data) + version + magic)
    # Based on: https://github.com/ntqbit/tdesktop-decrypter
    calculated_md5 = hashlib.md5(
        encrypted_data +
        len(encrypted_data).to_bytes(4, 'little') +
        version.to_bytes(4, 'little') +
        magic_bytes
    ).digest()

    if calculated_md5 != stored_md5:
        import binascii
        raise ValueError(
            f"MD5 checksum mismatch\n"
            f"File size: {len(content)} bytes\n"
            f"Stored MD5: {binascii.hexlify(stored_md5).decode()}\n"
            f"Calculated MD5: {binascii.hexlify(calculated_md5).decode()}"
        )

    return {
        'version': version,
        'data': encrypted_data,
        'md5_valid': True
    }