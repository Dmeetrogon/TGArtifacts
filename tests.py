import sys
import struct
import traceback
from io import BytesIO
from pathlib import Path

TDATA_NO_PASS = Path("tdata_test/no_pass/tdata_copy_without_password")
TDATA_WITH_PASS = Path("tdata_test/with_pass/tdata_with_password")
TDATA_NO_PASS_MULTI = Path("tdata_test/no_pass_multi/tdata_without_password_and_multi")
TDATA_WITH_PASS_MULTI = Path("tdata_test/with_pass_multi/tdata_with_password_and_multi")
TDATA_OLD = Path("tdata_test/tdata_old_without")
TDATA_OLD_WITH_PASS = Path("tdata_test/tdata_old_with")

PASS = "\033[92mPASS\033[0m"
FAIL = "\033[91mFAIL\033[0m"

results = []


def run_test(name, func):
    try:
        func()
        print(f"  [{PASS}] {name}")
        results.append(True)
    except Exception as e:
        print(f"  [{FAIL}] {name}: {e}")
        traceback.print_exc()
        results.append(False)


def test_read_tdf_version():
    from tgartifacts.parsers.tdf_reader import read_tdf
    for tdata in [TDATA_NO_PASS, TDATA_WITH_PASS]:
        tdf = read_tdf(str(tdata / "key_datas"))
        assert tdf["version"] > 0, f"version should be > 0, got {tdf['version']}"
        assert tdf["md5_valid"] is True
    tdf = read_tdf(str(TDATA_NO_PASS / "settingss"))
    assert tdf["version"] > 0


def test_settings_file_exists():
    for tdata in [TDATA_NO_PASS, TDATA_WITH_PASS]:
        path = tdata / "settingss"
        assert path.exists(), f"{path} not found"
        with open(path, "rb") as f:
            magic = f.read(4)
            assert magic == b"TDF$", f"expected TDF$, got {magic}"


def test_settings_salt_extraction():
    from tgartifacts.parsers.tdf_reader import read_tdf
    from tgartifacts.parsers.qt_stream import QtDataStreamReader
    tdf = read_tdf(str(TDATA_NO_PASS / "settingss"))
    reader = QtDataStreamReader(tdf["data"])
    salt = reader.read_bytearray()
    assert salt is not None, "salt is None"
    assert len(salt) == 32, f"salt should be 32 bytes, got {len(salt)}"
    encrypted = reader.read_bytearray()
    assert encrypted is not None, "encrypted settings is None"
    assert len(encrypted) > 16, f"encrypted too short: {len(encrypted)}"


def test_legacy_local_key():
    from tgartifacts.crypto.keys import create_legacy_local_key
    salt = b"\x00" * 32
    key = create_legacy_local_key(b"", salt)
    assert len(key) == 136, f"key should be 136 bytes, got {len(key)}"
    key2 = create_legacy_local_key(b"", salt)
    assert key == key2, "key derivation not deterministic"
    key_with_pass = create_legacy_local_key(b"test", salt)
    assert key_with_pass != key, "password should change the key"
    assert len(key_with_pass) == 136


def test_settings_decryption():
    from tgartifacts.parsers.tdf_reader import read_tdf
    from tgartifacts.parsers.qt_stream import QtDataStreamReader
    from tgartifacts.crypto.keys import create_legacy_local_key
    from tgartifacts.crypto.decryptor import decrypt_tdf_legacy

    tdf = read_tdf(str(TDATA_NO_PASS / "settingss"))
    reader = QtDataStreamReader(tdf["data"])
    salt = reader.read_bytearray()
    encrypted = reader.read_bytearray()

    settings_key = create_legacy_local_key(b"", salt)
    decrypted = decrypt_tdf_legacy(encrypted, settings_key)
    assert len(decrypted) > 0, "decrypted settings is empty"

    stream = BytesIO(decrypted)
    block_id = int.from_bytes(stream.read(4), "big", signed=True)
    assert block_id > 0, f"first block_id should be > 0, got {block_id}"


def test_read_utf16():
    from tgartifacts.parsers.qt_stream import QtDataStreamReader
    text = "Hello"
    encoded = text.encode("utf-16-be")
    data = struct.pack(">I", len(encoded)) + encoded
    reader = QtDataStreamReader(data)
    result = reader.read_utf16()
    assert result == text, f"expected '{text}', got '{result}'"

    cyrillic = "Привет"
    encoded_c = cyrillic.encode("utf-16-be")
    data_c = struct.pack(">I", len(encoded_c)) + encoded_c
    reader_c = QtDataStreamReader(data_c)
    result_c = reader_c.read_utf16()
    assert result_c == cyrillic, f"expected '{cyrillic}', got '{result_c}'"

    null_data = struct.pack(">I", 0xFFFFFFFF)
    reader_n = QtDataStreamReader(null_data)
    result_n = reader_n.read_utf16()
    assert result_n is None, f"expected None, got {result_n}"

    empty_data = struct.pack(">I", 0)
    reader_e = QtDataStreamReader(empty_data)
    result_e = reader_e.read_utf16()
    assert result_e == "", f"expected '', got '{result_e}'"


def test_settings_blocks_parsing():
    from tgartifacts.parsers.tdata_parser import TDataParser
    parser = TDataParser(str(TDATA_NO_PASS))
    settings = parser.get_settings_info()
    assert isinstance(settings, dict), f"expected dict, got {type(settings)}"
    assert len(settings) > 0, "settings is empty"
    print(f"    -> parsed settings keys: {list(settings.keys())}")


def test_account_index_from_key_datas():
    from tgartifacts.crypto.keys import decrypt_key_datas_info, get_local_key
    local_key = get_local_key(TDATA_NO_PASS)
    info = decrypt_key_datas_info(TDATA_NO_PASS, local_key)
    assert "account_indexes" in info
    assert "main_account" in info
    assert isinstance(info["account_indexes"], list)
    print(f"    -> account_indexes={info['account_indexes']}, main={info['main_account']}")


def test_account_index_multi():
    from tgartifacts.crypto.keys import decrypt_key_datas_info, get_local_key
    if not TDATA_NO_PASS_MULTI.exists():
        print("    -> skipped (no multi tdata)")
        return
    local_key = get_local_key(TDATA_NO_PASS_MULTI)
    info = decrypt_key_datas_info(TDATA_NO_PASS_MULTI, local_key)
    assert len(info["account_indexes"]) > 1, f"expected >1 accounts, got {info['account_indexes']}"
    print(f"    -> multi accounts: {info['account_indexes']}")


def test_version_propagation():
    from tgartifacts.parsers.tdata_parser import TDataParser
    parser = TDataParser(str(TDATA_NO_PASS))
    version = parser.tdesktop_version
    assert version > 0, f"version should be > 0, got {version}"
    assert version == 6006002, f"expected 6006002, got {version}"
    print(f"    -> tdesktop_version={version}")


def test_settings_with_password():
    from tgartifacts.parsers.tdata_parser import TDataParser
    parser = TDataParser(str(TDATA_WITH_PASS), passcode="penguin")
    settings = parser.get_settings_info()
    assert isinstance(settings, dict)
    print(f"    -> parsed settings keys (with pass): {list(settings.keys())}")


def test_compute_data_name_key():
    from tgartifacts.parsers.tdata_parser import TDataParser
    key = TDataParser._compute_data_name_key("data")
    assert len(key) == 16, f"expected 16 chars, got {len(key)}"
    assert key == "D877F783D5D3EF8C", f"expected D877F783D5D3EF8C, got {key}"
    print(f"    -> data -> {key}")

    key2 = TDataParser._compute_data_name_key("data#2")
    assert len(key2) == 16
    assert key2 != key
    print(f"    -> data#2 -> {key2}")


def test_detailed_settings_output():
    from tgartifacts.parsers.tdata_parser import TDataParser
    parser = TDataParser(str(TDATA_NO_PASS))
    settings = parser.get_settings_info()
    print(f"    -> tdesktop_version: {parser.tdesktop_version}")
    for key, val in settings.items():
        if key in ('mtp_authorization',):
            print(f"    -> {key}: <{type(val).__name__}>")
        elif isinstance(val, dict):
            print(f"    -> {key}:")
            for k, v in val.items():
                print(f"       {k}: {v}")
        else:
            print(f"    -> {key}: {val}")


def test_old_tdata_tdf_version():
    from tgartifacts.parsers.tdf_reader import read_tdf
    tdf = read_tdf(str(TDATA_OLD / "key_datas"))
    assert tdf["version"] == 4016010, f"expected 4016010, got {tdf['version']}"
    assert tdf["md5_valid"] is True
    tdf_s = read_tdf(str(TDATA_OLD / "settingss"))
    assert tdf_s["version"] == 4016010
    assert tdf_s["md5_valid"] is True
    print(f"    -> old tdata version: {tdf['version']}")


def test_old_tdata_settings_decryption():
    from tgartifacts.parsers.tdf_reader import read_tdf
    from tgartifacts.parsers.qt_stream import QtDataStreamReader
    from tgartifacts.crypto.keys import create_legacy_local_key
    from tgartifacts.crypto.decryptor import decrypt_tdf_legacy

    tdf = read_tdf(str(TDATA_OLD / "settingss"))
    reader = QtDataStreamReader(tdf["data"])
    salt = reader.read_bytearray()
    assert len(salt) == 32, f"salt should be 32 bytes, got {len(salt)}"
    encrypted = reader.read_bytearray()
    settings_key = create_legacy_local_key(b"", salt)
    decrypted = decrypt_tdf_legacy(encrypted, settings_key)
    assert len(decrypted) > 0, "decrypted settings is empty"
    print(f"    -> decrypted {len(decrypted)} bytes from old settings")


def test_old_tdata_settings_parsing():
    from tgartifacts.parsers.tdata_parser import TDataParser
    parser = TDataParser(str(TDATA_OLD))
    assert parser.tdesktop_version == 4016010, f"expected 4016010, got {parser.tdesktop_version}"
    settings = parser.get_settings_info()
    assert isinstance(settings, dict)
    assert len(settings) > 0
    assert "user_id" in settings
    assert "dc_id" in settings
    print(f"    -> old tdata settings keys: {list(settings.keys())}")


def test_old_tdata_account_index():
    from tgartifacts.crypto.keys import decrypt_key_datas_info, get_local_key
    local_key = get_local_key(TDATA_OLD)
    assert len(local_key) == 256
    info = decrypt_key_datas_info(TDATA_OLD, local_key)
    assert "account_indexes" in info
    assert isinstance(info["account_indexes"], list)
    assert 0 in info["account_indexes"]
    print(f"    -> old tdata accounts: {info['account_indexes']}")


def test_old_tdata_dc_options():
    from tgartifacts.parsers.tdata_parser import TDataParser
    parser = TDataParser(str(TDATA_OLD))
    settings = parser.get_settings_info()
    assert "production_config" in settings
    config = settings["production_config"]
    assert "dc_options" in config
    dc_ids = {opt["dc_id"] for opt in config["dc_options"]}
    assert len(dc_ids) >= 3, f"expected at least 3 DCs, got {dc_ids}"
    print(f"    -> old tdata DCs: {sorted(dc_ids)}")


def test_old_vs_new_key_derivation():
    from tgartifacts.crypto.keys import get_local_key
    old_key = get_local_key(TDATA_OLD)
    new_key = get_local_key(TDATA_NO_PASS)
    assert len(old_key) == 256
    assert len(new_key) == 256
    assert old_key != new_key
    print(f"    -> keys differ (old vs new): confirmed")


def test_old_tdata_with_password_settings():
    from tgartifacts.parsers.tdata_parser import TDataParser
    parser = TDataParser(str(TDATA_OLD_WITH_PASS), passcode="penguin")
    assert parser.tdesktop_version == 4016010
    settings = parser.get_settings_info()
    assert isinstance(settings, dict)
    assert len(settings) > 0
    assert "user_id" in settings
    print(f"    -> old tdata (with pass) settings keys: {list(settings.keys())}")


def test_old_tdata_with_password_account_index():
    from tgartifacts.crypto.keys import decrypt_key_datas_info, get_local_key
    local_key = get_local_key(TDATA_OLD_WITH_PASS, passcode="penguin")
    assert len(local_key) == 256
    info = decrypt_key_datas_info(TDATA_OLD_WITH_PASS, local_key)
    assert "account_indexes" in info
    assert 0 in info["account_indexes"]
    print(f"    -> old tdata (with pass) accounts: {info['account_indexes']}")


def test_old_tdata_wrong_password_fails():
    from tgartifacts.parsers.tdata_parser import TDataParser
    try:
        parser = TDataParser(str(TDATA_OLD_WITH_PASS), passcode="wrongpass")
        settings = parser.get_settings_info()
        assert False, "should have raised an exception with wrong password"
    except Exception:
        pass


if __name__ == "__main__":
    print("\n=== TGArtifacts Settings Decryption Tests ===\n")

    tests = [
        ("TDF version reading", test_read_tdf_version),
        ("Settings file exists", test_settings_file_exists),
        ("Settings salt extraction", test_settings_salt_extraction),
        ("Legacy local key", test_legacy_local_key),
        ("Settings decryption", test_settings_decryption),
        ("read_utf16", test_read_utf16),
        ("Settings blocks parsing", test_settings_blocks_parsing),
        ("Account index from key_datas", test_account_index_from_key_datas),
        ("Account index multi", test_account_index_multi),
        ("Version propagation", test_version_propagation),
        ("Settings with password", test_settings_with_password),
        ("compute_data_name_key", test_compute_data_name_key),
        ("Old tdata TDF version (v4.16.10)", test_old_tdata_tdf_version),
        ("Old tdata settings decryption", test_old_tdata_settings_decryption),
        ("Old tdata settings parsing", test_old_tdata_settings_parsing),
        ("Old tdata account index", test_old_tdata_account_index),
        ("Old tdata DC options", test_old_tdata_dc_options),
        ("Old vs new key derivation", test_old_vs_new_key_derivation),
        ("Old tdata with password settings", test_old_tdata_with_password_settings),
        ("Old tdata with password account index", test_old_tdata_with_password_account_index),
        ("Old tdata wrong password fails", test_old_tdata_wrong_password_fails),
    ]

    for name, func in tests:
        run_test(name, func)

    passed = sum(results)
    total = len(results)
    print(f"\n{'='*40}")
    print(f"Results: {passed}/{total} passed")
    if passed < total:
        print(f"Failed: {total - passed}")
        sys.exit(1)
    else:
        print("All tests passed!")
        sys.exit(0)
