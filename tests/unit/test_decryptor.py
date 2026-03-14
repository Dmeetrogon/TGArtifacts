"""UT-019..026: Decryptor tests."""

import hashlib
import os
import struct
import pytest

import tgcrypto

from tgartifacts.crypto.decryptor import Decryptor, decrypt_tdf_legacy


def _encrypt_tdf(data: bytes, auth_key: bytes) -> bytes:
    """Encrypt data using AES-256-IGE (reverse of decrypt_tdf_legacy)."""
    length_prefix = struct.pack('<I', len(data) + 4)
    plaintext = length_prefix + data
    pad_len = (16 - len(plaintext) % 16) % 16
    plaintext += os.urandom(pad_len)

    msg_key = hashlib.sha1(plaintext).digest()[:16]
    aes_key, aes_iv = Decryptor.prepare_aes_oldmtp(auth_key, msg_key)
    encrypted = tgcrypto.ige256_encrypt(plaintext, aes_key, aes_iv)
    return msg_key + encrypted


class TestDecryptor:
    """UT-019..026: AES-IGE decryption."""

    def test_ut019_decrypt_with_correct_key(self):
        """UT-019: AES-256-IGE decryption with correct key succeeds."""
        local_key = os.urandom(256)
        original = b"Hello, Telegram!"
        encrypted = _encrypt_tdf(original, local_key)

        decryptor = Decryptor(local_key)
        result = decryptor.decrypt_tdf(encrypted)
        assert result == original

    def test_ut020_msg_key_verification(self):
        """UT-020: SHA1(decrypted)[:16] == msg_key → no exception."""
        local_key = os.urandom(256)
        original = b"test data for verification"
        encrypted = _encrypt_tdf(original, local_key)

        decryptor = Decryptor(local_key)
        decryptor.decrypt_tdf(encrypted)

    def test_ut021_wrong_key(self):
        """UT-021: Wrong key → msg_key mismatch → ValueError."""
        key1 = os.urandom(256)
        key2 = os.urandom(256)
        encrypted = _encrypt_tdf(b"secret", key1)

        decryptor = Decryptor(key2)
        with pytest.raises(ValueError, match="checksum mismatch"):
            decryptor.decrypt_tdf(encrypted)

    def test_ut022_length_little_endian(self):
        """UT-022: Length extracted as little-endian uint32."""
        local_key = os.urandom(256)
        original = b"A" * 100
        encrypted = _encrypt_tdf(original, local_key)

        decryptor = Decryptor(local_key)
        result = decryptor.decrypt_tdf(encrypted)
        assert len(result) == 100

    def test_ut023_length_exceeds_data(self):
        """UT-023: Length > data size → ValueError."""
        local_key = os.urandom(256)
        bad_length = struct.pack('<I', 99999)
        plaintext = bad_length + b'\x00' * 12
        msg_key = hashlib.sha1(plaintext).digest()[:16]
        aes_key, aes_iv = Decryptor.prepare_aes_oldmtp(local_key, msg_key)
        encrypted = msg_key + tgcrypto.ige256_encrypt(plaintext, aes_key, aes_iv)

        decryptor = Decryptor(local_key)
        with pytest.raises(ValueError, match="Wrong length"):
            decryptor.decrypt_tdf(encrypted)

    def test_ut024_roundtrip(self):
        """UT-024: Encrypt → decrypt → original data."""
        local_key = os.urandom(256)
        for size in [1, 16, 100, 1000]:
            original = os.urandom(size)
            encrypted = _encrypt_tdf(original, local_key)
            decryptor = Decryptor(local_key)
            assert decryptor.decrypt_tdf(encrypted) == original

    def test_ut025_block_aligned(self):
        """UT-025: Data padded to 16-byte boundary works."""
        local_key = os.urandom(256)
        for size in [12, 16, 32, 48]:
            original = os.urandom(size)
            encrypted = _encrypt_tdf(original, local_key)
            decryptor = Decryptor(local_key)
            assert decryptor.decrypt_tdf(encrypted) == original

    def test_ut026_data_too_small(self):
        """UT-026: Data < 16 bytes → ValueError."""
        decryptor = Decryptor(os.urandom(256))
        with pytest.raises(ValueError, match="too small"):
            decryptor.decrypt_tdf(b'\x00' * 10)

    def test_init_wrong_key_size(self):
        """Decryptor rejects key != 256 bytes."""
        with pytest.raises(ValueError, match="256 bytes"):
            Decryptor(b'\x00' * 128)


class TestDecryptTdfLegacy:
    """decrypt_tdf_legacy standalone function."""

    def test_roundtrip(self):
        auth_key = os.urandom(136)
        original = b"legacy data"
        encrypted = _encrypt_tdf(original, auth_key)
        result = decrypt_tdf_legacy(encrypted, auth_key)
        assert result == original
