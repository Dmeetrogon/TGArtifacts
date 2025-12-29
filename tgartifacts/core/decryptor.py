import hashlib
from typing import Tuple
import tgcrypto


def prepare_aes_oldmtp(auth_key: bytes, msg_key: bytes) -> Tuple[bytes, bytes]:

    msg_key = msg_key[:16]

    # For decryption, use offset x=8 (for send=False)
    x = 8

    sha1_a = hashlib.sha1(msg_key + auth_key[x:x+32]).digest()
    sha1_b = hashlib.sha1(auth_key[x+32:x+48] + msg_key + auth_key[x+48:x+64]).digest()
    sha1_c = hashlib.sha1(auth_key[x+64:x+96] + msg_key).digest()
    sha1_d = hashlib.sha1(msg_key + auth_key[x+96:x+128]).digest()


    aes_key = sha1_a[0:8] + sha1_b[8:20] + sha1_c[4:16]


    aes_iv = sha1_a[8:20] + sha1_b[0:8] + sha1_c[16:20] + sha1_d[0:8]

    return aes_key, aes_iv


def decrypt_local_TDF(encrypted_data: bytes, local_key: bytes) -> bytes:
    """Decrypt local encrypted data.

    Based on ntqbit/tdesktop-decrypter implementation.

    Args:
        encrypted_data: Encrypted data (msg_key + encrypted_payload)
        local_key: Local encryption key (256 bytes)

    Returns:
        Decrypted data (without length prefix)
    """
    if len(encrypted_data) < 16:
        raise ValueError("Encrypted data too small (minimum 16 bytes for msg_key)")

    msg_key = encrypted_data[:16]
    encrypted_payload = encrypted_data[16:]

    # Prepare AES key and IV
    aes_key, aes_iv = prepare_aes_oldmtp(local_key, msg_key)

    # Decrypt
    decrypted = tgcrypto.ige256_decrypt(encrypted_payload, aes_key, aes_iv)

    # Verify checksum
    calculated_checksum = hashlib.sha1(decrypted).digest()[:16]

    if calculated_checksum != msg_key:
        raise ValueError(
            "Decryption checksum mismatch. "
            "Possible reasons: wrong localKey, corrupted data, wrong passcode"
        )

    # Extract actual data (skip 4-byte length prefix)
    length = int.from_bytes(decrypted[:4], 'little')
    if length > len(decrypted):
        raise ValueError(f"Corrupted data. Wrong length: {length}")

    return decrypted[4:length]