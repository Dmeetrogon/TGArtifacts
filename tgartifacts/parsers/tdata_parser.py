"""Telegram Desktop tdata directory parser."""
from typing import Optional, Dict, Any, List
from pathlib import Path
import os

from .tdf_reader import read_tdf
from ..crypto.decryptor import Decryptor
from .qt_stream import QtDataStreamReader


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
        from ..crypto.keys import get_local_key_from_key_datas

        # Account data file is in tdata directory, named {account_dir}s
        account_data_file = self.tdata_path / f"{account_dir}s"

        if not account_data_file.exists():
            raise FileNotFoundError(f"Account data file not found: {account_data_file}")

        # Get local key from key_datas (two-stage decryption)
        if self._local_key is None:
            self._local_key = get_local_key_from_key_datas(self.tdata_path, self.passcode)


        tdf_data = read_tdf(str(account_data_file))
        reader = QtDataStreamReader(tdf_data['data'])


        encrypted_data = reader.read_bytearray()
        if encrypted_data is None:
            raise ValueError("Invalid account data file: no encrypted data found")

        try:
            decryptor = Decryptor(self._local_key)
            decrypted_data = decryptor.decrypt_TDF_file(encrypted_data)
        except ValueError as e:
            raise ValueError(f"Failed to decrypt account data: {e}")

        # Parse settings blocks to find MTP authorization
        return self._parse_settings_blocks(decrypted_data)

    def _parse_settings_blocks(self, data: bytes) -> Dict[str, Any]:
        """Parse settings blocks to extract MTP authorization and other data.

        Args:
            data: Decrypted settings blocks data

        Returns:
            Dictionary with parsed account data including MTP authorization
        """
        from io import BytesIO

        stream = BytesIO(data)
        result = {
            'auth_keys': {},
            'keys_to_destroy': {}
        }

        # DBI constants from Telegram Desktop
        DBI_KEY = 0x00
        DBI_USER = 0x01
        DBI_MTP_AUTHORIZATION = 0x4B

        try:
            while True:
                block_id_bytes = stream.read(4)
                if len(block_id_bytes) != 4:
                    break

                block_id = int.from_bytes(block_id_bytes, 'big', signed=True)

                if block_id == DBI_MTP_AUTHORIZATION:
                    # MTP Authorization block - contains user_id, dc_id, and auth keys
                    length_bytes = stream.read(4)
                    if len(length_bytes) != 4:
                        break

                    length = int.from_bytes(length_bytes, 'big', signed=True)
                    if length <= 0:
                        continue
                    mtp_auth_data = stream.read(length)
                    mtp_auth = self._parse_mtp_authorization(mtp_auth_data)
                    result.update(mtp_auth)

                elif block_id == DBI_USER:
                    # Legacy user block - qint32 userId, quint32 dcId
                    user_id = int.from_bytes(stream.read(4), 'big', signed=True)
                    dc_id = int.from_bytes(stream.read(4), 'big', signed=False)
                    if 'user_id' not in result or result['user_id'] == 0:
                        result['user_id'] = user_id
                    if 'dc_id' not in result or result['dc_id'] == 0:
                        result['dc_id'] = dc_id

                elif block_id == DBI_KEY:
                    # Legacy key block - qint32 dcId, 256 bytes auth key
                    dc_id = int.from_bytes(stream.read(4), 'big', signed=True)
                    auth_key = stream.read(256)
                    if len(auth_key) == 256:
                        result['auth_keys'][dc_id] = auth_key

                else:
                    # Skip unknown blocks
                    length_bytes = stream.read(4)
                    if len(length_bytes) != 4:
                        break

                    length = int.from_bytes(length_bytes, 'big', signed=True)
                    if length > 0:
                        stream.read(length)
                    elif length < 0:
                        # Invalid length, stop parsing
                        break

        except Exception:
            pass

        return result

    def _parse_mtp_authorization(self, data: bytes) -> Dict[str, Any]:
        """Parse MTP authorization data including auth keys.

        Args:
            data: MTP authorization bytes

        Returns:
            Dictionary with user_id, dc_id, auth_keys, and keys_to_destroy
        """
        from io import BytesIO

        stream = BytesIO(data)

        legacy_user_id = int.from_bytes(stream.read(4), 'big', signed=True)
        legacy_main_dc_id = int.from_bytes(stream.read(4), 'big', signed=True)

        # Check if this is new format (wide IDs)
        if legacy_user_id == -1 and legacy_main_dc_id == -1:
            user_id = int.from_bytes(stream.read(8), 'big', signed=False)
            main_dc_id = int.from_bytes(stream.read(4), 'big', signed=True)
        else:
            user_id = legacy_user_id
            main_dc_id = legacy_main_dc_id

        # Parse auth keys
        auth_keys = {}
        keys_to_destroy = {}

        try:
            # Read auth keys count
            keys_count_bytes = stream.read(4)
            if len(keys_count_bytes) == 4:
                keys_count = int.from_bytes(keys_count_bytes, 'big', signed=True)

                for _ in range(keys_count):
                    dc_id_bytes = stream.read(4)
                    if len(dc_id_bytes) != 4:
                        break
                    dc_id = int.from_bytes(dc_id_bytes, 'big', signed=True)

                    # Auth key is 256 bytes
                    auth_key = stream.read(256)
                    if len(auth_key) != 256:
                        break
                    auth_keys[dc_id] = auth_key

            # Read keys to destroy count
            destroy_count_bytes = stream.read(4)
            if len(destroy_count_bytes) == 4:
                destroy_count = int.from_bytes(destroy_count_bytes, 'big', signed=True)

                for _ in range(destroy_count):
                    dc_id_bytes = stream.read(4)
                    if len(dc_id_bytes) != 4:
                        break
                    dc_id = int.from_bytes(dc_id_bytes, 'big', signed=True)

                    auth_key = stream.read(256)
                    if len(auth_key) != 256:
                        break
                    keys_to_destroy[dc_id] = auth_key

        except Exception:
            # If parsing fails, return what we have
            pass

        return {
            'user_id': user_id,
            'dc_id': main_dc_id,
            'auth_keys': auth_keys,
            'keys_to_destroy': keys_to_destroy
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

    def _scan_cache_dir(self, cache_path: Path) -> List[Path]:
        """Scan a cache directory for TDEF files.

        Args:
            cache_path: Path to cache directory (media_cache or cache)

        Returns:
            List of file paths found
        """
        if not cache_path.exists():
            return []

        tdef_files = []
        version_dirs = [d for d in cache_path.iterdir() if d.is_dir()]
        if not version_dirs:
            return []

        for version_dir in version_dirs:
            for subfolder in version_dir.iterdir():
                if not subfolder.is_dir():
                    continue
                for file_path in subfolder.iterdir():
                    if file_path.is_file():
                        tdef_files.append(file_path)

        return tdef_files

    def find_cached_tdef_files(self) -> List[Path]:
        """Find all cached TDEF files in media_cache and cache directories.

        Returns:
            List of TDEF file paths
        """
        media_cache = self.tdata_path / 'user_data' / 'media_cache'
        cache = self.tdata_path / 'user_data' / 'cache'

        tdef_files = []
        tdef_files.extend(self._scan_cache_dir(media_cache))
        tdef_files.extend(self._scan_cache_dir(cache))

        return tdef_files

    def extract_cached_tdef_files(self, output_dir: str) -> Dict[str, Any]:
        """Extract and decrypt cached TDEF files from both cache directories.

        Args:
            output_dir: Output directory for decrypted files

        Returns:
            Dictionary with extraction statistics

        Raises:
            ValueError: If local key is not available
        """
        if self._local_key is None:
            from ..crypto.keys import get_local_key_from_key_datas
            self._local_key = get_local_key_from_key_datas(self.tdata_path, self.passcode)
        decryptor = Decryptor(self._local_key)
        output_path = Path(output_dir)
        stats = {'total': 0, 'success': 0, 'failed': 0, 'streaming': 0}
        media_cache = self.tdata_path / 'user_data' / 'media_cache'
        cache = self.tdata_path / 'user_data' / 'cache'
        for cache_path in [media_cache, cache]:
            if cache_path.exists():
                dir_stats = decryptor.decrypt_media_cache_directory(cache_path, output_path)
                stats['total'] += dir_stats['total']
                stats['success'] += dir_stats['success']
                stats['failed'] += dir_stats['failed']
                stats['streaming'] += dir_stats.get('streaming', 0)

        return stats
