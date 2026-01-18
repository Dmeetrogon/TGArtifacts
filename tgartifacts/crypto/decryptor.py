import hashlib
from typing import Tuple, Dict, Optional, List
import tgcrypto
from pathlib import Path
import magic


class Decryptor:
    """Decryptor for Telegram Desktop encrypted files.
    Handles decryption of TDF (settings/account data) and TDEF (media cache) files.
    """
    def __init__(self, local_key: bytes):
        """Initialize decryptor with local key.

        Args:
            local_key: Local encryption key (256 bytes) from key_datas
        """
        if len(local_key) != 256:
            raise ValueError(f"Local key must be 256 bytes, got {len(local_key)}")

        self.local_key = local_key
    @staticmethod
    def prepare_aes_oldmtp(auth_key: bytes, msg_key: bytes) -> Tuple[bytes, bytes]:
        """Prepare AES key and IV for MTProto old algorithm.

        Args:
            auth_key: Authorization key (256 bytes)
            msg_key: Message key (16 bytes)

        Returns:
            Tuple of (aes_key, aes_iv)
        """
        msg_key = msg_key[:16]
        x = 8

        sha1_a = hashlib.sha1(msg_key + auth_key[x:x+32]).digest()
        sha1_b = hashlib.sha1(auth_key[x+32:x+48] + msg_key + auth_key[x+48:x+64]).digest()
        sha1_c = hashlib.sha1(auth_key[x+64:x+96] + msg_key).digest()
        sha1_d = hashlib.sha1(msg_key + auth_key[x+96:x+128]).digest()

        aes_key = sha1_a[0:8] + sha1_b[8:20] + sha1_c[4:16]
        aes_iv = sha1_a[8:20] + sha1_b[0:8] + sha1_c[16:20] + sha1_d[0:8]

        return aes_key, aes_iv
    def decrypt_local_TDF(self, encrypted_data: bytes) -> bytes:
        """Decrypt TDF encrypted data (account data, settings).

        Based on ntqbit/tdesktop-decrypter implementation.
        Uses AES-256-IGE with MTProto old algorithm.

        Args:
            encrypted_data: Encrypted data (msg_key + encrypted_payload)

        Returns:
            Decrypted data (without length prefix)

        Raises:
            ValueError: If data is corrupted or checksum mismatch
        """
        if len(encrypted_data) < 16:
            raise ValueError("Encrypted data too small (minimum 16 bytes for msg_key)")

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
    def decrypt_TDEF_file(self, file_path: Path) -> bytes:
        """Decrypt single TDEF file (media cache file).

        Uses AES-256-CTR encryption with salt-based key derivation.
        IMPORTANT: Header and data must be decrypted as one continuous stream
        because CTR mode keystream is position-dependent.

        Args:
            file_path: Path to TDEF file

        Returns:
            Decrypted file data (raw serialized cache data)

        Raises:
            ValueError: If file format is invalid or checksum mismatch
        """
        with open(file_path, 'rb') as file:
            magic_bytes = file.read(4)
            if magic_bytes != b'TDEF':
                raise ValueError(f"Invalid magic bytes. Expected b'TDEF', got {magic_bytes}")
            salt = file.read(64)
            if len(salt) != 64:
                raise ValueError(f"Salt too short, expected 64 bytes, got {len(salt)} bytes")

            # Read all encrypted content (header + data)
            encrypted_content = file.read()
            if len(encrypted_content) < 48:
                raise ValueError(f"Encrypted content too short, expected at least 48 bytes")

            # Derive AES key and IV from local_key and salt
            real_key = hashlib.sha256(
                self.local_key[:128] + salt[:32]
            ).digest()
            iv = hashlib.sha256(
                self.local_key[128:] + salt[32:64]
            ).digest()[:16]

            # Decrypt header and data together as continuous stream
            # This is required because CTR mode keystream is position-dependent
            decrypted_all = tgcrypto.ctr256_decrypt(
                encrypted_content,
                real_key,
                iv,
                bytes(1)
            )

            # Split into header (48 bytes) and data
            header_decrypted = decrypted_all[:48]
            decrypted_data = decrypted_all[48:]

            # Verify header checksum
            data_part = header_decrypted[:16]
            stored_checksum = header_decrypted[16:48]
            expected_checksum = hashlib.sha256(
                self.local_key + salt + data_part
            ).digest()

            if stored_checksum != expected_checksum:
                raise ValueError("Checksum mismatch! Wrong key or corrupted file")

            return decrypted_data

    @staticmethod
    def parse_streaming_cache_data(data: bytes) -> Optional[bytes]:
        """Parse streaming cache serialization format and reassemble media.

        Streaming cache files store media in parts with the format:
        - uint32 count (number of parts)
        - For each part:
          - uint32 offset (position in final media)
          - uint32 size (size of this part)
          - bytes[size] (part data)

        Args:
            data: Raw decrypted cache data

        Returns:
            Reassembled media bytes, or None if not streaming format
        """
        if len(data) < 4:
            return None

        count = int.from_bytes(data[:4], 'little')

        # Sanity check - count should be reasonable
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

        # Reassemble media
        max_end = max(p[0] + p[1] for p in parts)
        assembled = bytearray(max_end)
        for offset, size, part_data in parts:
            assembled[offset:offset+len(part_data)] = part_data

        return bytes(assembled)

    # MIME type to extension mapping
    MIME_TO_EXT = {
        'image/jpeg': '.jpg',
        'image/png': '.png',
        'image/gif': '.gif',
        'image/webp': '.webp',
        'image/bmp': '.bmp',
        'image/tiff': '.tiff',
        'video/mp4': '.mp4',
        'video/webm': '.webm',
        'video/x-matroska': '.mkv',
        'video/quicktime': '.mov',
        'video/x-msvideo': '.avi',
        'audio/ogg': '.ogg',
        'audio/opus': '.opus',
        'audio/mpeg': '.mp3',
        'audio/x-wav': '.wav',
        'audio/flac': '.flac',
        'audio/aac': '.aac',
        'application/gzip': '.tgs',  # Telegram stickers are gzipped
        'application/json': '.json',
        'text/plain': '.txt',
    }

    @staticmethod
    def detect_media_extension(data: bytes) -> str:
        """Detect file extension using libmagic.

        Args:
            data: File data

        Returns:
            File extension (e.g., '.mp4', '.ogg', '.jpg') or '.bin' if unknown
        """
        if len(data) < 12:
            return '.bin'

        try:
            mime = magic.from_buffer(data, mime=True)

            # Check direct mapping
            if mime in Decryptor.MIME_TO_EXT:
                return Decryptor.MIME_TO_EXT[mime]

            # Handle subtypes (e.g., 'video/x-m4v' -> '.mp4')
            if mime.startswith('video/'):
                return '.mp4'
            if mime.startswith('audio/'):
                return '.ogg'
            if mime.startswith('image/'):
                return '.bin'

            return '.bin'
        except Exception:
            return '.bin'

    def decrypt_media_cache_directory(self, tdata_path: Path, output_dir: Path) -> Dict[str, int]:
        """Extract and decrypt all TDEF files from media cache.

        Args:
            tdata_path: Path to tdata directory
            output_dir: Output directory for decrypted files

        Returns:
            Dictionary with stats of decryption: {'total': int, 'success': int, 'failed': int, 'streaming': int}

        Raises:
            FileNotFoundError: If media_cache directory not found
        """
        tdata_path = Path(tdata_path)
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        media_cache_path = tdata_path / 'user_data' / 'media_cache'
        if not media_cache_path.exists():
            raise FileNotFoundError(f"Media cache not found: {media_cache_path}")
        version_dirs = [d for d in media_cache_path.iterdir() if d.is_dir()]
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
                        decrypted_data = self.decrypt_TDEF_file(file_path)

                        # Try to parse as streaming cache format
                        assembled_media = self.parse_streaming_cache_data(decrypted_data)
                        if assembled_media is not None:
                            # Successfully parsed streaming cache
                            final_data = assembled_media
                            stats['streaming'] += 1
                        else:
                            # Not streaming format, use raw data
                            final_data = decrypted_data

                        # Detect extension and save
                        ext = self.detect_media_extension(final_data)
                        output_path = output_dir / f"{file_path.name}{ext}"
                        with open(output_path, 'wb') as out_file:
                            out_file.write(final_data)
                        stats['success'] += 1
                    except Exception as e:
                        print(f"Failed to decrypt {file_path}: {e}")
                        stats['failed'] += 1

        return stats

# used by keys.get_local_key_from_key_datas
def decrypt_local_TDF(encrypted_data: bytes, auth_key: bytes) -> bytes:
    """Legacy/module-level decrypt_local_TDF(auth_key).

    This mirrors the old standalone function behaviour: decrypt `encrypted_data`
    using `auth_key` (passcode-derived key) and return decrypted payload.

    Args:
        encrypted_data: bytes, msg_key + encrypted_payload
        auth_key: bytes, passcode-derived key (the key produced by create_local_key)

    Returns:
        Decrypted payload bytes (without 4-byte length prefix)

    Raises:
        ValueError on checksum/format errors.
    """
    if len(encrypted_data) < 16:
        raise ValueError("Encrypted data too small (minimum 16 bytes for msg_key)")
    msg_key = encrypted_data[:16]
    encrypted_payload = encrypted_data[16:]
    aes_key, aes_iv = Decryptor.prepare_aes_oldmtp(auth_key, msg_key)
    decrypted = tgcrypto.ige256_decrypt(encrypted_payload, aes_key, aes_iv)
    calculated_checksum = hashlib.sha1(decrypted).digest()[:16]
    if calculated_checksum != msg_key:
        raise ValueError(
            "Decryption checksum mismatch. "
            "Possible reasons: wrong auth_key (passcode key), corrupted data"
        )

    length = int.from_bytes(decrypted[:4], 'little')
    if length > len(decrypted):
        raise ValueError(f"Corrupted data. Wrong length: {length}")
    return decrypted[4:length]