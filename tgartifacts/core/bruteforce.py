"""Passcode bruteforce module for Telegram Desktop tdata."""
import hashlib
from typing import Optional, Callable, List
from pathlib import Path

from ..utils.tdf import read_tdf
from ..utils.crypto import create_local_key, get_key_datas_version
from ..core.decryptor import decrypt_local
from ..core.parser import QtDataStreamReader


class PasscodeBruteforcer:
    """Bruteforce passcode for encrypted tdata."""

    def __init__(self, tdata_path: str):
        """Initialize bruteforcer.

        Args:
            tdata_path: Path to tdata directory
        """
        self.tdata_path = Path(tdata_path)
        self.attempts = 0

    def try_passcode(self, passcode: str, test_file_path: str, salt: bytes, use_sha512: bool = False) -> bool:
        """Try a passcode against encrypted data.

        Args:
            passcode: Passcode to try
            test_file_path: Path to encrypted file to test
            salt: Salt for key derivation
            use_sha512: Use SHA512 algorithm (for Telegram Desktop 2.1.14+)

        Returns:
            True if passcode is correct
        """
        self.attempts += 1

        try:
            # Generate key with passcode
            local_key = create_local_key(passcode, salt, iterations=100000, use_sha512=use_sha512)

            # Try to decrypt
            tdf_data = read_tdf(test_file_path)
            reader = QtDataStreamReader(tdf_data['data'])

            # Skip salt and legacy_key
            _ = reader.read_bytearray()
            _ = reader.read_bytearray()

            # Read encrypted map
            encrypted = reader.read_bytearray()
            if encrypted is None or len(encrypted) == 0:
                return False

            # Try decryption
            decrypt_local(encrypted, local_key)
            return True

        except Exception:
            return False

    def bruteforce_from_wordlist(
        self,
        wordlist_path: str,
        test_file_path: str,
        salt: bytes,
        max_attempts: Optional[int] = None,
        callback: Optional[Callable[[int, str], None]] = None,
        use_sha512: bool = False
    ) -> Optional[str]:
        """Bruteforce passcode from wordlist file.

        Args:
            wordlist_path: Path to wordlist file (e.g., rockyou.txt)
            test_file_path: Path to encrypted file to test
            salt: Salt for key derivation
            max_attempts: Maximum number of attempts (None = unlimited)
            callback: Optional callback function(attempts, password)
            use_sha512: Use SHA512 algorithm

        Returns:
            Found passcode or None
        """
        wordlist = Path(wordlist_path)
        if not wordlist.exists():
            raise FileNotFoundError(f"Wordlist not found: {wordlist_path}")

        self.attempts = 0

        with open(wordlist, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                passcode = line.strip()
                if not passcode:
                    continue

                if callback:
                    callback(self.attempts, passcode)

                if self.try_passcode(passcode, test_file_path, salt, use_sha512):
                    return passcode

                if max_attempts and self.attempts >= max_attempts:
                    break

        return None

    def bruteforce_numeric(
        self,
        test_file_path: str,
        salt: bytes,
        min_length: int = 4,
        max_length: int = 6,
        callback: Optional[Callable[[int, str], None]] = None,
        use_sha512: bool = False
    ) -> Optional[str]:
        """Bruteforce numeric passcodes (e.g., PINs).

        Args:
            test_file_path: Path to encrypted file to test
            salt: Salt for key derivation
            min_length: Minimum passcode length
            max_length: Maximum passcode length
            callback: Optional callback function(attempts, password)
            use_sha512: Use SHA512 algorithm

        Returns:
            Found passcode or None
        """
        self.attempts = 0

        for length in range(min_length, max_length + 1):
            for num in range(10 ** (length - 1), 10 ** length):
                passcode = str(num)

                if callback:
                    callback(self.attempts, passcode)

                if self.try_passcode(passcode, test_file_path, salt, use_sha512):
                    return passcode

        return None

    def bruteforce_common_patterns(
        self,
        test_file_path: str,
        salt: bytes,
        callback: Optional[Callable[[int, str], None]] = None,
        use_sha512: bool = False
    ) -> Optional[str]:
        """Try common passcode patterns.

        Args:
            test_file_path: Path to encrypted file to test
            salt: Salt for key derivation
            callback: Optional callback function(attempts, password)
            use_sha512: Use SHA512 algorithm

        Returns:
            Found passcode or None
        """
        self.attempts = 0

        # Common patterns
        patterns = [
            # Empty/default
            "",

            # Simple sequences
            "1234", "12345", "123456", "1234567", "12345678",
            "0000", "00000", "000000",
            "1111", "11111", "111111",

            # Common PINs
            "0001", "1001", "2000", "2001", "2002", "2003",
            "1212", "1122", "2112", "1221",

            # Keyboard patterns
            "qwerty", "qwertyui", "asdfgh", "zxcvbn",
            "password", "pass", "admin", "user",

            # Years
            "2020", "2021", "2022", "2023", "2024", "2025",
            "1990", "1991", "1992", "1993", "1994", "1995",
            "2000", "2001", "2002", "2003", "2004", "2005",
        ]

        for passcode in patterns:
            if callback:
                callback(self.attempts, passcode)

            if self.try_passcode(passcode, test_file_path, salt, use_sha512):
                return passcode

        return None

    def get_salt_from_key_datas(self) -> bytes:
        """Extract salt from key_datas file.

        Returns:
            Salt bytes (32 bytes for new format)
        """
        key_datas_path = self.tdata_path / 'key_datas'
        if not key_datas_path.exists():
            return b''

        tdf_data = read_tdf(str(key_datas_path))

        # For new format, salt is first 32 bytes
        version = tdf_data['version']
        if version >= 2001014:
            return tdf_data['data'][0:32]

        # For old format, parse as Qt stream
        reader = QtDataStreamReader(tdf_data['data'])
        salt = reader.read_bytearray()
        return salt if salt is not None else b''

    def get_salt_from_file(self, map_file_path: str) -> bytes:
        """Extract salt from map file.

        Args:
            map_file_path: Path to map/maps file

        Returns:
            Salt bytes (empty if null)
        """
        # For newer versions, get salt from key_datas
        version = get_key_datas_version(str(self.tdata_path))
        if version and version >= 2001014:
            return self.get_salt_from_key_datas()

        # For older versions, get from map file
        tdf_data = read_tdf(map_file_path)
        reader = QtDataStreamReader(tdf_data['data'])

        salt = reader.read_bytearray()
        return salt if salt is not None else b''
