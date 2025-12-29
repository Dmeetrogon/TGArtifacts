import hashlib
from typing import Tuple
import tgcrypto
from pathlib import Path

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

def get_TETF_files(path_to_tdata,local_key,output_dir):
    path_to_tdata = Path(path_to_tdata)
    media_cache_path = path_to_tdata / 'user_data' / 'media_cache'

    version_dirs = [d for d in media_cache_path.iterdir() if d.is_dir()]
    if not version_dirs:
        raise FileNotFoundError("No directories found in media_cache")
    cache_dir = version_dirs[0]
    for subfolder in cache_dir.iterdir():
        if not subfolder.is_dir():
            continue
        for file_path in subfolder.iterdir():
            if file_path.is_file():
                try:
                    decrypted_data = decrypt_TDEF_file(file_path,local_key)
                    output_path = Path(output_dir) / file_path.name
                    with open(output_path, 'wb') as out_file:
                        out_file.write(decrypted_data)
                except Exception as e:
                    print(f"Failed to decrypt {file_path}: {e}")
        return {}


def decrypt_TDEF_file(file_path, local_key) -> bytes:
    with open(file_path, 'rb') as file:
        magic_bytes = file.read(4)
        if magic_bytes != b'TDEF':
            raise ValueError(f"Invalid magic bytes. Expected b'TDEF', got {magic_bytes}")
        salt = file.read(64)
        if(len(salt)) != 64:
            raise ValueError(f"Salt too short, expected 64 bytes, got {len(salt)} bytes")
        encrypted_header = file.read(48)
        if(len(encrypted_header)) != 48:
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
        new_iv_int = (iv_int + blocks_processed) % (2**128)
        new_iv = new_iv_int.to_bytes(16, byteorder='big')
        
        decrypted_data = tgcrypto.ctr256_decrypt(
            encrypted_data,
            real_key,
            new_iv,
            bytes(1)
        )

        return decrypted_data
        
