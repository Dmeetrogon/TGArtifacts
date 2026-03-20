import hashlib
from typing import Optional, Dict, Any, List
from pathlib import Path
from io import BytesIO

from .tdf_reader import read_tdf
from ..crypto.decryptor import Decryptor, decrypt_tdf_legacy
from .qt_stream import QtDataStreamReader


DBI_KEY = 0x00
DBI_USER = 0x01
DBI_SEND_KEY = 0x05
DBI_AUTO_START = 0x06
DBI_START_MINIMIZED = 0x07
DBI_SEEN_TRAY_TOOLTIP = 0x0A
DBI_AUTO_UPDATE = 0x0C
DBI_LAST_UPDATE_CHECK = 0x0D
DBI_WINDOW_POSITION = 0x0E
DBI_LOGGED_PHONE = 0x19
DBI_SEND_TO_MENU = 0x1D
DBI_AUTO_LOCK = 0x22
DBI_DIALOG_LAST_PATH = 0x23
DBI_DOWNLOAD_PATH = 0x33
DBI_MTP_AUTHORIZATION = 0x4B
DBI_LANG_PACK_KEY = 0x4E
DBI_CONNECTION_TYPE = 0x4F
DBI_THEME_KEY = 0x54
DBI_POWER_SAVING = 0x57
DBI_SCALE_PERCENT = 0x58
DBI_APPLICATION_SETTINGS = 0x5E
DBI_FALLBACK_PRODUCTION_CONFIG = 0x60
DBI_BACKGROUND_KEY = 0x61
DBI_ENCRYPTED_WITH_SALT = 333
DBI_ENCRYPTED = 444
DBI_VERSION = 666

BOOL_BLOCKS = {
    DBI_AUTO_START, DBI_START_MINIMIZED, DBI_SEEN_TRAY_TOOLTIP,
    DBI_AUTO_UPDATE, DBI_SEND_TO_MENU,
}

BOOL_BLOCK_NAMES = {
    DBI_AUTO_START: 'auto_start',
    DBI_START_MINIMIZED: 'start_minimized',
    DBI_SEEN_TRAY_TOOLTIP: 'seen_tray_tooltip',
    DBI_AUTO_UPDATE: 'auto_update',
    DBI_SEND_TO_MENU: 'send_to_menu',
}

INT32_BLOCKS = {
    DBI_LAST_UPDATE_CHECK: 'last_update_check',
    DBI_AUTO_LOCK: 'auto_lock',
    DBI_SCALE_PERCENT: 'scale_percent',
    DBI_POWER_SAVING: 'power_saving',
    DBI_SEND_KEY: 'send_key',
}


class TDataParser:
    def __init__(self, tdata_path: str, passcode: Optional[str] = None):
        self.tdata_path = Path(tdata_path)
        if not self.tdata_path.exists():
            raise FileNotFoundError(f"tdata path not found: {tdata_path}")
        self.passcode = passcode
        self._local_key: Optional[bytes] = None
        self._tdesktop_version: Optional[int] = None

    @property
    def tdesktop_version(self) -> int:
        if self._tdesktop_version is None:
            tdf = read_tdf(str(self.tdata_path / 'key_datas'))
            self._tdesktop_version = tdf['version']
        return self._tdesktop_version

    def _get_local_key(self) -> bytes:
        if self._local_key is None:
            from ..crypto.keys import get_local_key
            self._local_key = get_local_key(self.tdata_path, self.passcode)
        return self._local_key

    @staticmethod
    def _compute_data_name_key(dataname: str) -> str:
        filekey = hashlib.md5(dataname.encode('utf-8')).digest()[:8]
        return ''.join(f'{b:02X}'[::-1] for b in filekey)

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
                if keys_count < 0 or keys_count > 20:
                    keys_count = 0
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
                if destroy_count < 0 or destroy_count > 20:
                    destroy_count = 0
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

    def parse_settings_file(self) -> Dict[str, Any]:
        from ..crypto.keys import create_legacy_local_key

        settings_path = str(self.tdata_path / 'settingss')
        if not (self.tdata_path / 'settingss').exists():
            settings_path = str(self.tdata_path / 'settings')
            if not (self.tdata_path / 'settings').exists():
                return {}

        tdf = read_tdf(settings_path)
        reader = QtDataStreamReader(tdf['data'])
        salt = reader.read_bytearray()
        encrypted = reader.read_bytearray()

        if salt is None or encrypted is None:
            return {}

        settings_key = create_legacy_local_key(b"", salt)
        decrypted = decrypt_tdf_legacy(encrypted, settings_key)
        return self._parse_settings_blocks_extended(decrypted)

    def _parse_settings_blocks_extended(self, data: bytes) -> Dict[str, Any]:
        stream = BytesIO(data)
        result: Dict[str, Any] = {}

        try:
            while True:
                block_id_bytes = stream.read(4)
                if len(block_id_bytes) != 4:
                    break

                block_id = int.from_bytes(block_id_bytes, 'big', signed=True)

                if block_id in (DBI_ENCRYPTED_WITH_SALT, DBI_ENCRYPTED):
                    break

                if block_id == DBI_VERSION:
                    result['settings_version'] = int.from_bytes(stream.read(4), 'big', signed=True)
                    continue

                if block_id in BOOL_BLOCKS:
                    val = int.from_bytes(stream.read(4), 'big', signed=True)
                    result[BOOL_BLOCK_NAMES[block_id]] = val == 1
                    continue

                if block_id in INT32_BLOCKS:
                    val = int.from_bytes(stream.read(4), 'big', signed=True)
                    result[INT32_BLOCKS[block_id]] = val
                    continue

                if block_id == DBI_LOGGED_PHONE:
                    sub = QtDataStreamReader(data[stream.tell():])
                    phone = sub.read_utf16()
                    stream.seek(stream.tell() + sub.offset)
                    if phone:
                        result['phone_number'] = phone.replace(' ', '')
                    continue

                if block_id == DBI_DIALOG_LAST_PATH:
                    sub = QtDataStreamReader(data[stream.tell():])
                    path = sub.read_utf16()
                    stream.seek(stream.tell() + sub.offset)
                    if path:
                        result['dialog_last_path'] = path
                    continue

                if block_id == DBI_DOWNLOAD_PATH:
                    sub = QtDataStreamReader(data[stream.tell():])
                    dl_path = sub.read_utf16()
                    sub.read_bytearray()
                    stream.seek(stream.tell() + sub.offset)
                    if dl_path:
                        result['download_path'] = dl_path
                    continue

                if block_id == DBI_WINDOW_POSITION:
                    x = int.from_bytes(stream.read(4), 'big', signed=True)
                    y = int.from_bytes(stream.read(4), 'big', signed=True)
                    w = int.from_bytes(stream.read(4), 'big', signed=True)
                    h = int.from_bytes(stream.read(4), 'big', signed=True)
                    moncrc = int.from_bytes(stream.read(4), 'big', signed=True)
                    maximized = int.from_bytes(stream.read(4), 'big', signed=True)
                    result['window_position'] = {
                        'x': x, 'y': y, 'w': w, 'h': h,
                        'monitor_crc': moncrc, 'maximized': maximized == 1,
                    }
                    continue

                if block_id == DBI_LANG_PACK_KEY:
                    result['lang_pack_key'] = int.from_bytes(stream.read(8), 'big', signed=False)
                    continue

                if block_id == DBI_THEME_KEY:
                    day = int.from_bytes(stream.read(8), 'big', signed=False)
                    night = int.from_bytes(stream.read(8), 'big', signed=False)
                    night_mode = int.from_bytes(stream.read(4), 'big', signed=True) == 1
                    result['theme'] = {'day': day, 'night': night, 'night_mode': night_mode}
                    continue

                if block_id == DBI_BACKGROUND_KEY:
                    day = int.from_bytes(stream.read(8), 'big', signed=False)
                    night = int.from_bytes(stream.read(8), 'big', signed=False)
                    result['background'] = {'day': day, 'night': night}
                    continue

                if block_id == DBI_CONNECTION_TYPE:
                    result['connection'] = self._parse_connection_type(data[stream.tell():], stream)
                    continue

                if block_id == DBI_FALLBACK_PRODUCTION_CONFIG:
                    try:
                        result['production_config'] = self._parse_fallback_config(data[stream.tell():], stream)
                    except Exception:
                        length_bytes = stream.read(4)
                        if len(length_bytes) == 4:
                            length = int.from_bytes(length_bytes, 'big', signed=True)
                            if length > 0:
                                stream.read(length)
                    continue

                if block_id == DBI_MTP_AUTHORIZATION:
                    length_bytes = stream.read(4)
                    if len(length_bytes) != 4:
                        break
                    length = int.from_bytes(length_bytes, 'big', signed=True)
                    if length > 0:
                        mtp_data = stream.read(length)
                        mtp_result = self._parse_mtp_authorization(mtp_data)
                        result['mtp_authorization'] = mtp_result
                    continue

                if block_id == DBI_APPLICATION_SETTINGS:
                    sub = QtDataStreamReader(data[stream.tell():])
                    app_data = sub.read_bytearray()
                    stream.seek(stream.tell() + sub.offset)
                    if app_data:
                        result['app_settings_size'] = len(app_data)
                    continue

                if block_id == DBI_USER:
                    result['user_id'] = int.from_bytes(stream.read(4), 'big', signed=True)
                    result['dc_id'] = int.from_bytes(stream.read(4), 'big', signed=False)
                    continue

                if block_id == DBI_KEY:
                    dc_id = int.from_bytes(stream.read(4), 'big', signed=True)
                    stream.read(256)
                    continue

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

    def _parse_connection_type(self, data: bytes, parent_stream: BytesIO) -> Dict[str, Any]:
        sub = QtDataStreamReader(data)
        conn_type = sub.read_int32()
        result: Dict[str, Any] = {'type': conn_type}

        if conn_type in (4, 5):
            count = sub.read_int32()
            index = sub.read_int32()
            settings = 0
            calls = 0
            if conn_type == 5:
                settings = sub.read_int32()
                calls = sub.read_int32()
            elif abs(index) > count:
                calls = 1
                index -= count if index > 0 else -count
            if count < 0 or count > 100:
                count = 0
            proxies = []
            for _ in range(count):
                proxy_type = sub.read_int32()
                host = sub.read_utf16() or ''
                port = sub.read_int32()
                user = sub.read_utf16() or ''
                password = sub.read_utf16() or ''
                proxies.append({
                    'type': proxy_type, 'host': host, 'port': port,
                    'user': user, 'password': '***' if password else '',
                })
            result['proxies'] = proxies
            result['selected_index'] = abs(index)
            result['use_for_calls'] = calls == 1
            result['settings'] = settings
        elif conn_type in (2, 3):
            proxy_type = sub.read_int32()
            host = sub.read_utf16() or ''
            port = sub.read_int32()
            user = sub.read_utf16() or ''
            password = sub.read_utf16() or ''
            result['proxy'] = {
                'type': proxy_type, 'host': host, 'port': port,
                'user': user, 'password': '***' if password else '',
            }

        parent_stream.seek(parent_stream.tell() + sub.offset)
        return result

    def _parse_fallback_config(self, data: bytes, parent_stream: BytesIO) -> Dict[str, Any]:
        outer = QtDataStreamReader(data)
        config_data = outer.read_bytearray()
        parent_stream.seek(parent_stream.tell() + outer.offset)

        if not config_data:
            return {}

        sub = QtDataStreamReader(config_data)
        result: Dict[str, Any] = {}
        result['config_version'] = sub.read_int32()
        result['environment'] = sub.read_int32()

        dc_data = sub.read_bytearray()
        if dc_data:
            dc_reader = QtDataStreamReader(dc_data)
            minus_version = dc_reader.read_int32()
            version = -minus_version if minus_version < 0 else 0
            count = dc_reader.read_int32() if version > 0 else minus_version
            if count < 0 or count > 200:
                count = 0
            dc_options = []
            for _ in range(count):
                try:
                    dc_id = dc_reader.read_int32()
                    flags = dc_reader.read_int32()
                    port = dc_reader.read_int32()
                    ip = dc_reader.read_bytearray()
                    secret = dc_reader.read_bytearray()
                    dc_options.append({
                        'dc_id': dc_id, 'flags': flags, 'port': port,
                        'ip': ip.decode() if ip else '', 'secret_len': len(secret) if secret else 0,
                    })
                except Exception:
                    break
            result['dc_options'] = dc_options

        try:
            result['chat_size_max'] = sub.read_int32()
            result['megagroup_size_max'] = sub.read_int32()
            result['forwarded_count_max'] = sub.read_int32()
            result['online_update_period'] = sub.read_int32()
            sub.skip(4 * 4)
            sub.skip(4 * 2)
            sub.skip(4 * 2)
            result['edit_time_limit'] = sub.read_int32()
            result['revoke_time_limit'] = sub.read_int32()
            result['revoke_private_time_limit'] = sub.read_int32()
            sub.skip(4)
            sub.skip(4 * 2)
            result['internal_links_domain'] = sub.read_utf16()
        except Exception:
            pass

        return result

    def get_settings_info(self) -> Dict[str, Any]:
        try:
            return self.parse_settings_file()
        except Exception:
            return {}

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
