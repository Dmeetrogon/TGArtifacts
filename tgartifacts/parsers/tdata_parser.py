from typing import Optional, Dict, Any, List
from pathlib import Path
from io import BytesIO

from .tdf_reader import read_tdf
from ..crypto.decryptor import Decryptor
from .qt_stream import QtDataStreamReader


DBI_KEY = 0x00
DBI_USER = 0x01
DBI_MTP_AUTHORIZATION = 0x4B


class TDataParser:
    def __init__(self, tdata_path: str, passcode: Optional[str] = None):
        self.tdata_path = Path(tdata_path)
        if not self.tdata_path.exists():
            raise FileNotFoundError(f"tdata path not found: {tdata_path}")
        self.passcode = passcode
        self._local_key: Optional[bytes] = None

    def _get_local_key(self) -> bytes:
        if self._local_key is None:
            from ..crypto.keys import get_local_key
            self._local_key = get_local_key(self.tdata_path, self.passcode)
        return self._local_key

    def find_account_dirs(self) -> List[str]:
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
        account_data_file = self.tdata_path / f"{account_dir}s"
        if not account_data_file.exists():
            raise FileNotFoundError(f"Account data file not found: {account_data_file}")

        local_key = self._get_local_key()
        tdf_data = read_tdf(str(account_data_file))
        reader = QtDataStreamReader(tdf_data['data'])
        encrypted_data = reader.read_bytearray()
        if encrypted_data is None:
            raise ValueError("Invalid account data file: no encrypted data found")

        decryptor = Decryptor(local_key)
        decrypted_data = decryptor.decrypt_tdf(encrypted_data)
        return self._parse_settings_blocks(decrypted_data)

    def _parse_settings_blocks(self, data: bytes) -> Dict[str, Any]:
        stream = BytesIO(data)
        result = {'auth_keys': {}, 'keys_to_destroy': {}}

        try:
            while True:
                block_id_bytes = stream.read(4)
                if len(block_id_bytes) != 4:
                    break

                block_id = int.from_bytes(block_id_bytes, 'big', signed=True)

                if block_id == DBI_MTP_AUTHORIZATION:
                    length_bytes = stream.read(4)
                    if len(length_bytes) != 4:
                        break
                    length = int.from_bytes(length_bytes, 'big', signed=True)
                    if length <= 0:
                        continue
                    mtp_auth_data = stream.read(length)
                    result.update(self._parse_mtp_authorization(mtp_auth_data))

                elif block_id == DBI_USER:
                    user_id = int.from_bytes(stream.read(4), 'big', signed=True)
                    dc_id = int.from_bytes(stream.read(4), 'big', signed=False)
                    if 'user_id' not in result or result['user_id'] == 0:
                        result['user_id'] = user_id
                    if 'dc_id' not in result or result['dc_id'] == 0:
                        result['dc_id'] = dc_id

                elif block_id == DBI_KEY:
                    dc_id = int.from_bytes(stream.read(4), 'big', signed=True)
                    auth_key = stream.read(256)
                    if len(auth_key) == 256:
                        result['auth_keys'][dc_id] = auth_key

                else:
                    length_bytes = stream.read(4)
                    if len(length_bytes) != 4:
                        break
                    length = int.from_bytes(length_bytes, 'big', signed=True)
                    if length > 0:
                        stream.read(length)
                    elif length < 0:
                        break
        except Exception:
            pass

        return result

    def _parse_mtp_authorization(self, data: bytes) -> Dict[str, Any]:
        stream = BytesIO(data)
        legacy_user_id = int.from_bytes(stream.read(4), 'big', signed=True)
        legacy_main_dc_id = int.from_bytes(stream.read(4), 'big', signed=True)

        if legacy_user_id == -1 and legacy_main_dc_id == -1:
            user_id = int.from_bytes(stream.read(8), 'big', signed=False)
            main_dc_id = int.from_bytes(stream.read(4), 'big', signed=True)
        else:
            user_id = legacy_user_id
            main_dc_id = legacy_main_dc_id

        auth_keys = {}
        keys_to_destroy = {}

        try:
            keys_count_bytes = stream.read(4)
            if len(keys_count_bytes) == 4:
                keys_count = int.from_bytes(keys_count_bytes, 'big', signed=True)
                for _ in range(keys_count):
                    dc_id_bytes = stream.read(4)
                    if len(dc_id_bytes) != 4:
                        break
                    dc_id = int.from_bytes(dc_id_bytes, 'big', signed=True)
                    auth_key = stream.read(256)
                    if len(auth_key) != 256:
                        break
                    auth_keys[dc_id] = auth_key

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
            pass

        return {
            'user_id': user_id,
            'dc_id': main_dc_id,
            'auth_keys': auth_keys,
            'keys_to_destroy': keys_to_destroy
        }

    def get_account_info(self, account_dir: str) -> Dict[str, Any]:
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
        accounts = self.find_account_dirs()
        return [self.get_account_info(acc) for acc in accounts]

    def _scan_cache_dir(self, cache_path: Path) -> List[Path]:
        if not cache_path.exists():
            return []
        tdef_files = []
        version_dirs = [d for d in cache_path.iterdir() if d.is_dir()]
        for version_dir in version_dirs:
            for subfolder in version_dir.iterdir():
                if not subfolder.is_dir():
                    continue
                for file_path in subfolder.iterdir():
                    if file_path.is_file():
                        tdef_files.append(file_path)
        return tdef_files

    def find_cached_tdef_files(self) -> List[Path]:
        media_cache = self.tdata_path / 'user_data' / 'media_cache'
        cache = self.tdata_path / 'user_data' / 'cache'
        tdef_files = []
        tdef_files.extend(self._scan_cache_dir(media_cache))
        tdef_files.extend(self._scan_cache_dir(cache))
        return tdef_files

    def extract_cached_tdef_files(self, output_dir: str) -> Dict[str, Any]:
        local_key = self._get_local_key()
        decryptor = Decryptor(local_key)
        output_path = Path(output_dir)
        stats = {'total': 0, 'success': 0, 'failed': 0, 'streaming': 0}

        for cache_name in ['media_cache', 'cache']:
            cache_path = self.tdata_path / 'user_data' / cache_name
            if cache_path.exists():
                dir_stats = decryptor.decrypt_media_cache(cache_path, output_path)
                for key in stats:
                    stats[key] += dir_stats.get(key, 0)

        return stats
