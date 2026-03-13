import hashlib
from typing import Tuple, Dict, Optional, List
from pathlib import Path

import tgcrypto

from ..utils.extension_detector import detect_media_extension


class Decryptor:
    def __init__(self, local_key: bytes):
        if len(local_key) != 256:
            raise ValueError(f"Local key must be 256 bytes, got {len(local_key)}")
        self.local_key = local_key

    @staticmethod
    def prepare_aes_oldmtp(auth_key: bytes, msg_key: bytes) -> Tuple[bytes, bytes]:
        msg_key = msg_key[:16]
        x = 8

        sha1_a = hashlib.sha1(msg_key + auth_key[x:x+32]).digest()
        sha1_b = hashlib.sha1(auth_key[x+32:x+48] + msg_key + auth_key[x+48:x+64]).digest()
        sha1_c = hashlib.sha1(auth_key[x+64:x+96] + msg_key).digest()
        sha1_d = hashlib.sha1(msg_key + auth_key[x+96:x+128]).digest()

        aes_key = sha1_a[0:8] + sha1_b[8:20] + sha1_c[4:16]
        aes_iv = sha1_a[8:20] + sha1_b[0:8] + sha1_c[16:20] + sha1_d[0:8]

        return aes_key, aes_iv

    @staticmethod
    def parse_streaming_cache_data(data: bytes) -> Optional[bytes]:
        if len(data) < 4:
            return None
        count = int.from_bytes(data[:4], 'little')
        if count == 0 or count > 1000:
            return None
        pos = 4
        parts: List[Tuple[int, int, bytes]] = []
        try:
            for _ in range(count):
                if pos + 8 > len(data):
                    return None
                offset = int.from_bytes(data[pos:pos+4], 'little')
                size = int.from_bytes(data[pos+4:pos+8], 'little')
                pos += 8
                if size == 0 or pos + size > len(data):
                    return None
                part_data = data[pos:pos+size]
                parts.append((offset, size, part_data))
                pos += size
        except Exception:
            return None
        if not parts:
            return None
        max_end = max(p[0] + p[1] for p in parts)
        assembled = bytearray(max_end)
        for offset, size, part_data in parts:
            assembled[offset:offset+len(part_data)] = part_data
        return bytes(assembled)

    def decrypt_tdf(self, encrypted_data: bytes) -> bytes:
        if len(encrypted_data) < 16:
            raise ValueError("Encrypted data too small")
        msg_key = encrypted_data[:16]
        encrypted_payload = encrypted_data[16:]
        aes_key, aes_iv = self.prepare_aes_oldmtp(self.local_key, msg_key)
        decrypted = tgcrypto.ige256_decrypt(encrypted_payload, aes_key, aes_iv)
        calculated_checksum = hashlib.sha1(decrypted).digest()[:16]
        if calculated_checksum != msg_key:
            raise ValueError(
                "Decryption checksum mismatch. "
                "Possible reasons: wrong localKey, corrupted data, wrong passcode"
            )
        length = int.from_bytes(decrypted[:4], 'little')
        if length > len(decrypted):
            raise ValueError(f"Corrupted data. Wrong length: {length}")
        return decrypted[4:length]

    def decrypt_tdef(self, file_path: Path) -> bytes:
        with open(file_path, 'rb') as file:
            magic_bytes = file.read(4)
            if magic_bytes != b'TDEF':
                raise ValueError(f"Invalid magic bytes. Expected b'TDEF', got {magic_bytes}")
            salt = file.read(64)
            if len(salt) != 64:
                raise ValueError(f"Salt too short, expected 64 bytes, got {len(salt)} bytes")
            encrypted_content = file.read()
            if len(encrypted_content) < 48:
                raise ValueError("Encrypted content too short")
            real_key = hashlib.sha256(
                self.local_key[:128] + salt[:32]
            ).digest()
            iv = hashlib.sha256(
                self.local_key[128:] + salt[32:64]
            ).digest()[:16]
            decrypted_all = tgcrypto.ctr256_decrypt(
                encrypted_content, real_key, iv, bytes(1)
            )
            header_decrypted = decrypted_all[:48]
            decrypted_data = decrypted_all[48:]
            data_part = header_decrypted[:16]
            stored_checksum = header_decrypted[16:48]
            expected_checksum = hashlib.sha256(
                self.local_key + salt + data_part
            ).digest()
            if stored_checksum != expected_checksum:
                raise ValueError("Checksum mismatch! Wrong key or corrupted file")
            return decrypted_data

    def decrypt_media_cache(self, cache_path: Path, output_dir: Path) -> Dict[str, int]:
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        if not cache_path.exists():
            raise FileNotFoundError(f"Directory not found: {cache_path}")
        version_dirs = [d for d in cache_path.iterdir() if d.is_dir()]
        if not version_dirs:
            raise FileNotFoundError("No directories found in media_cache")
        cache_dir = version_dirs[0]
        stats = {'total': 0, 'success': 0, 'failed': 0, 'streaming': 0}
        for subfolder in cache_dir.iterdir():
            if not subfolder.is_dir():
                continue
            for file_path in subfolder.iterdir():
                if file_path.is_file():
                    stats['total'] += 1
                    try:
                        decrypted_data = self.decrypt_tdef(file_path)
                        assembled_media = self.parse_streaming_cache_data(decrypted_data)
                        if assembled_media is not None:
                            final_data = assembled_media
                            stats['streaming'] += 1
                        else:
                            final_data = decrypted_data
                        ext = detect_media_extension(final_data)
                        output_path = output_dir / f"{file_path.name}{ext}"
                        with open(output_path, 'wb') as out_file:
                            out_file.write(final_data)
                        stats['success'] += 1
                    except Exception as e:
                        print(f"Failed to decrypt {file_path}: {e}")
                        stats['failed'] += 1
        return stats


def decrypt_tdf_legacy(encrypted_data: bytes, auth_key: bytes) -> bytes:
    if len(encrypted_data) < 16:
        raise ValueError("Encrypted data too small")
    msg_key = encrypted_data[:16]
    encrypted_payload = encrypted_data[16:]
    aes_key, aes_iv = Decryptor.prepare_aes_oldmtp(auth_key, msg_key)
    decrypted = tgcrypto.ige256_decrypt(encrypted_payload, aes_key, aes_iv)
    calculated_checksum = hashlib.sha1(decrypted).digest()[:16]
    if calculated_checksum != msg_key:
        raise ValueError(
            "Decryption checksum mismatch. "
            "Possible reasons: wrong auth_key, corrupted data"
        )
    length = int.from_bytes(decrypted[:4], 'little')
    if length > len(decrypted):
        raise ValueError(f"Corrupted data. Wrong length: {length}")
    return decrypted[4:length]
