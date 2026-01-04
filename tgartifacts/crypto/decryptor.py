import hashlib
from typing import Tuple, Dict
import tgcrypto
from pathlib import Path


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

        Args:
            file_path: Path to TDEF file

        Returns:
            Decrypted file data

        Raises:
            ValueError: If file format is invalid or checksum mismatch
        """
        with open(file_path, 'rb') as file:
            # Read and validate magic bytes
            magic_bytes = file.read(4)
            if magic_bytes != b'TDEF':
                raise ValueError(f"Invalid magic bytes. Expected b'TDEF', got {magic_bytes}")

            # Read salt
            salt = file.read(64)
            if len(salt) != 64:
                raise ValueError(f"Salt too short, expected 64 bytes, got {len(salt)} bytes")

            # Read encrypted header
            encrypted_header = file.read(48)
            if len(encrypted_header) != 48:
                raise ValueError(f"Encrypted header too short, expected 48 bytes, got {len(encrypted_header)} bytes")

            # Derive encryption key and IV from local_key and salt
            real_key = hashlib.sha256(
                self.local_key[:128] + salt[:32]
            ).digest()

            iv = hashlib.sha256(
                self.local_key[128:] + salt[32:64]
            ).digest()[:16]

            # Decrypt header
            header_decrypted = tgcrypto.ctr256_decrypt(
                encrypted_header,
                real_key,
                iv,
                bytes(1)
            )

            # Verify checksum
            data_part = header_decrypted[:16]
            stored_checksum = header_decrypted[16:48]

            expected_checksum = hashlib.sha256(
                self.local_key + salt + data_part
            ).digest()

            if stored_checksum != expected_checksum:
                raise ValueError("Checksum mismatch! Wrong key or corrupted file")

            # Read and decrypt data
            encrypted_data = file.read()

            # Update IV for data decryption (counter mode)
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
    def decrypt_media_cache_directory(self, tdata_path: Path, output_dir: Path) -> Dict[str, int]:
        """Extract and decrypt all TDEF files from media cache.

        Args:
            tdata_path: Path to tdata directory
            output_dir: Output directory for decrypted files

        Returns:
            Dictionary with statistics: {'total': int, 'success': int, 'failed': int}

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
        stats = {'total': 0, 'success': 0, 'failed': 0}

        for subfolder in cache_dir.iterdir():
            if not subfolder.is_dir():
                continue

            for file_path in subfolder.iterdir():
                if file_path.is_file():
                    stats['total'] += 1
                    try:
                        decrypted_data = self.decrypt_TDEF_file(file_path)
                        output_path = output_dir / file_path.name

                        with open(output_path, 'wb') as out_file:
                            out_file.write(decrypted_data)

                        stats['success'] += 1
                    except Exception as e:
                        print(f"Failed to decrypt {file_path}: {e}")
                        stats['failed'] += 1

        return stats

# Module-level helper kept for legacy usage (used by keys.get_local_key_from_key_datas)
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

    # Use the same prepare function as Decryptor (call via the class)
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