"""Telegram Desktop tdata directory parser."""
from typing import Optional, Dict, Any, List
from pathlib import Path
import os

from ..utils.tdf import read_tdf
from .decryptor import decrypt_local_TDF, get_TDEF_files
from .parser import QtDataStreamReader


class TDataParser:
    """Parser for Telegram Desktop tdata directory structure."""

    def __init__(self, tdata_path: str, passcode: Optional[str] = None):
        """Initialize tdata parser.

        Args:
            tdata_path: Path to tdata directory
            passcode: Optional passcode for encrypted data

        Raises:
            FileNotFoundError: If tdata path doesn't exist
        """
        self.tdata_path = Path(tdata_path)
        if not self.tdata_path.exists():
            raise FileNotFoundError(f"tdata path not found: {tdata_path}")

        self.passcode = passcode
        self._local_key: Optional[bytes] = None

    def find_account_dirs(self) -> List[str]:
        """Find all account directories (16-char hex names).

        Returns:
            List of account directory names
        """
        account_dirs = []
        for item in self.tdata_path.iterdir():
            if item.is_dir() and len(item.name) == 16:
                try:
                    int(item.name, 16)
                    account_dirs.append(item.name)
                except ValueError:
                    continue

        return account_dirs

    def parse_account_data(self, account_dir: str) -> Dict[str, Any]:
        """Parse account data file from tdata directory.

        Args:
            account_dir: Account directory name (e.g., 'D877F783D5D3EF8C')

        Returns:
            Dictionary with parsed account data including MTP authorization

        Raises:
            FileNotFoundError: If account data file not found
            ValueError: If parsing fails
        """
        from ..utils.crypto import get_local_key_from_key_datas

        # Account data file is in tdata directory, named {account_dir}s
        account_data_file = self.tdata_path / f"{account_dir}s"

        if not account_data_file.exists():
            raise FileNotFoundError(f"Account data file not found: {account_data_file}")

        # Get local key from key_datas (two-stage decryption)
        if self._local_key is None:
            self._local_key = get_local_key_from_key_datas(str(self.tdata_path), self.passcode)

        # Read and decrypt account data file
        tdf_data = read_tdf(str(account_data_file))
        reader = QtDataStreamReader(tdf_data['data'])

        # Extract encrypted data (QByteArray)
        encrypted_data = reader.read_bytearray()
        if encrypted_data is None:
            raise ValueError("Invalid account data file: no encrypted data found")

        try:
            decrypted_data = decrypt_local_TDF(encrypted_data, self._local_key)
        except ValueError as e:
            raise ValueError(f"Failed to decrypt account data: {e}")

        # Parse settings blocks to find MTP authorization
        return self._parse_settings_blocks(decrypted_data)

    def _parse_settings_blocks(self, data: bytes) -> Dict[str, Any]:
        """Parse settings blocks to extract MTP authorization.

        Args:
            data: Decrypted settings blocks data

        Returns:
            Dictionary with parsed MTP authorization data
        """
        from io import BytesIO

        stream = BytesIO(data)
        result = {}

        # Constants
        DBI_MTP_AUTHORIZATION = 0x4B

        try:
            while True:
                # Read block ID
                block_id_bytes = stream.read(4)
                if len(block_id_bytes) != 4:
                    break

                block_id = int.from_bytes(block_id_bytes, 'big', signed=True)

                if block_id == DBI_MTP_AUTHORIZATION:
                    # Read QByteArray length
                    length_bytes = stream.read(4)
                    if len(length_bytes) != 4:
                        break

                    length = int.from_bytes(length_bytes, 'big', signed=True)
                    if length <= 0:
                        break

                    # Read MTP authorization data
                    mtp_auth_data = stream.read(length)
                    mtp_auth = self._parse_mtp_authorization(mtp_auth_data)
                    result.update(mtp_auth)
                    break
                else:
                    # Skip unknown block by reading a QByteArray
                    length_bytes = stream.read(4)
                    if len(length_bytes) != 4:
                        break

                    length = int.from_bytes(length_bytes, 'big', signed=True)
                    if length > 0:
                        stream.read(length)
        except Exception:
            pass

        return result

    def _parse_mtp_authorization(self, data: bytes) -> Dict[str, Any]:
        """Parse MTP authorization data.

        Args:
            data: MTP authorization bytes

        Returns:
            Dictionary with user_id, dc_id, and auth keys
        """
        from io import BytesIO

        stream = BytesIO(data)

        # Read legacy IDs first
        legacy_user_id = int.from_bytes(stream.read(4), 'big', signed=True)
        legacy_main_dc_id = int.from_bytes(stream.read(4), 'big', signed=True)

        # Check if this is new format
        if legacy_user_id == -1 and legacy_main_dc_id == -1:
            # New format: read uint64 user_id and int32 dc_id
            user_id = int.from_bytes(stream.read(8), 'big', signed=False)
            main_dc_id = int.from_bytes(stream.read(4), 'big', signed=True)
        else:
            # Legacy format
            user_id = legacy_user_id
            main_dc_id = legacy_main_dc_id

        return {
            'user_id': user_id,
            'dc_id': main_dc_id
        }

    def get_account_info(self, account_dir: str) -> Dict[str, Any]:
        """Get comprehensive account information.

        Args:
            account_dir: Account directory name

        Returns:
            Dictionary with account information
        """
        try:
            account_data = self.parse_account_data(account_dir)

            result = {
                'account_dir': account_dir,
                'success': True,
                'has_passcode': self.passcode is not None
            }
            result.update(account_data)

            return result

        except Exception as e:
            return {
                'account_dir': account_dir,
                'success': False,
                'error': str(e)
            }

    def get_all_accounts_info(self) -> List[Dict[str, Any]]:
        """Get information for all accounts in tdata.

        Returns:
            List of account information dictionaries
        """
        accounts = self.find_account_dirs()
        results = []

        for account_dir in accounts:
            info = self.get_account_info(account_dir)
            results.append(info)

        return results

    def find_cached_tdef_files(self) -> List[Path]:
        """Find all cached TDEF files in media_cache directory.

        Returns:
            List of TDEF file paths
        """
        media_cache_path = self.tdata_path / 'user_data' / 'media_cache'

        if not media_cache_path.exists():
            return []

        tdef_files = []
        version_dirs = [d for d in media_cache_path.iterdir() if d.is_dir()]
        if not version_dirs:
            return []

        cache_dir = version_dirs[0]
        for subfolder in cache_dir.iterdir():
            if not subfolder.is_dir():
                continue
            for file_path in subfolder.iterdir():
                if file_path.is_file():
                    tdef_files.append(file_path)

        return tdef_files

    def extract_cached_tdef_files(self, output_dir: str) -> Dict[str, Any]:
        """Extract and decrypt cached TDEF files.

        Args:
            output_dir: Output directory for decrypted files

        Returns:
            Dictionary with extraction statistics

        Raises:
            ValueError: If local key is not available
        """
        if self._local_key is None:
            # Try to get local key
            from ..utils.crypto import get_local_key_from_key_datas
            self._local_key = get_local_key_from_key_datas(str(self.tdata_path), self.passcode)

        # Create output directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)

        # Extract TDEF files
        stats = get_TDEF_files(str(self.tdata_path), self._local_key, output_dir)

        return stats
