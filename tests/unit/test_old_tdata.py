"""UT: Old tdata (v4.16.10) parsing and settings extraction."""

import pytest

from tgartifacts.parsers.tdf_reader import read_tdf
from tgartifacts.parsers.tdata_parser import TDataParser
from tgartifacts.crypto.keys import get_local_key, decrypt_key_datas_info


class TestOldTdfReader:

    def test_old_key_datas_version(self, old_no_pass_tdata):
        tdf = read_tdf(str(old_no_pass_tdata / "key_datas"))
        assert tdf["version"] == 4016010
        assert tdf["md5_valid"] is True

    def test_old_settingss_version(self, old_no_pass_tdata):
        tdf = read_tdf(str(old_no_pass_tdata / "settingss"))
        assert tdf["version"] == 4016010
        assert tdf["md5_valid"] is True

    def test_old_with_pass_version(self, old_with_pass_tdata):
        path, _ = old_with_pass_tdata
        tdf = read_tdf(str(path / "key_datas"))
        assert tdf["version"] == 4016010


class TestOldKeyDerivation:

    def test_old_local_key_length(self, old_no_pass_tdata):
        local_key = get_local_key(old_no_pass_tdata)
        assert len(local_key) == 256

    def test_old_account_indexes(self, old_no_pass_tdata):
        local_key = get_local_key(old_no_pass_tdata)
        info = decrypt_key_datas_info(old_no_pass_tdata, local_key)
        assert "account_indexes" in info
        assert 0 in info["account_indexes"]

    def test_old_with_pass_local_key(self, old_with_pass_tdata):
        path, passcode = old_with_pass_tdata
        local_key = get_local_key(path, passcode=passcode)
        assert len(local_key) == 256

    def test_old_vs_new_keys_differ(self, old_no_pass_tdata, no_pass_tdata):
        old_key = get_local_key(old_no_pass_tdata)
        new_key = get_local_key(no_pass_tdata)
        assert old_key != new_key

    def test_old_wrong_password_fails(self, old_with_pass_tdata):
        path, _ = old_with_pass_tdata
        parser = TDataParser(str(path), passcode="wrongpass")
        accounts = parser.get_all_accounts_info()
        failed = [a for a in accounts if not a.get("success")]
        assert len(failed) > 0


class TestOldSettingsParsing:

    def test_old_tdesktop_version(self, old_no_pass_tdata):
        parser = TDataParser(str(old_no_pass_tdata))
        assert parser.tdesktop_version == 4016010

    def test_old_settings_keys(self, old_no_pass_tdata):
        parser = TDataParser(str(old_no_pass_tdata))
        settings = parser.get_settings_info()
        assert isinstance(settings, dict)
        assert len(settings) > 0
        assert "user_id" in settings
        assert "dc_id" in settings

    def test_old_settings_booleans(self, old_no_pass_tdata):
        parser = TDataParser(str(old_no_pass_tdata))
        settings = parser.get_settings_info()
        for key in ["auto_start", "start_minimized", "send_to_menu", "auto_update"]:
            assert key in settings
            assert isinstance(settings[key], bool)

    def test_old_settings_production_config(self, old_no_pass_tdata):
        parser = TDataParser(str(old_no_pass_tdata))
        settings = parser.get_settings_info()
        assert "production_config" in settings
        config = settings["production_config"]
        assert "dc_options" in config
        dc_ids = {opt["dc_id"] for opt in config["dc_options"]}
        assert len(dc_ids) >= 3

    def test_old_settings_theme(self, old_no_pass_tdata):
        parser = TDataParser(str(old_no_pass_tdata))
        settings = parser.get_settings_info()
        assert "theme" in settings
        theme = settings["theme"]
        assert "day" in theme
        assert "night" in theme
        assert "night_mode" in theme

    def test_old_with_pass_settings(self, old_with_pass_tdata):
        path, passcode = old_with_pass_tdata
        parser = TDataParser(str(path), passcode=passcode)
        settings = parser.get_settings_info()
        assert isinstance(settings, dict)
        assert "user_id" in settings


class TestSettingsFields:

    def test_settings_auto_start(self, no_pass_tdata):
        parser = TDataParser(str(no_pass_tdata))
        settings = parser.get_settings_info()
        assert "auto_start" in settings
        assert isinstance(settings["auto_start"], bool)

    def test_settings_auto_update(self, no_pass_tdata):
        parser = TDataParser(str(no_pass_tdata))
        settings = parser.get_settings_info()
        assert "auto_update" in settings
        assert isinstance(settings["auto_update"], bool)

    def test_settings_scale_percent(self, no_pass_tdata):
        parser = TDataParser(str(no_pass_tdata))
        settings = parser.get_settings_info()
        assert "scale_percent" in settings
        assert isinstance(settings["scale_percent"], int)

    def test_settings_theme_structure(self, no_pass_tdata):
        parser = TDataParser(str(no_pass_tdata))
        settings = parser.get_settings_info()
        assert "theme" in settings
        theme = settings["theme"]
        assert "day" in theme
        assert "night" in theme
        assert "night_mode" in theme
        assert isinstance(theme["night_mode"], bool)

    def test_settings_background_structure(self, no_pass_tdata):
        parser = TDataParser(str(no_pass_tdata))
        settings = parser.get_settings_info()
        assert "background" in settings
        bg = settings["background"]
        assert "day" in bg
        assert "night" in bg

    def test_settings_production_config_limits(self, no_pass_tdata):
        parser = TDataParser(str(no_pass_tdata))
        settings = parser.get_settings_info()
        config = settings["production_config"]
        assert config["chat_size_max"] == 200
        assert config["megagroup_size_max"] == 200000
        assert config["forwarded_count_max"] == 100

    def test_settings_dc_options(self, no_pass_tdata):
        parser = TDataParser(str(no_pass_tdata))
        settings = parser.get_settings_info()
        dc_opts = settings["production_config"]["dc_options"]
        assert len(dc_opts) > 0
        for opt in dc_opts:
            assert "dc_id" in opt
            assert "ip" in opt
            assert "port" in opt

    def test_settings_with_password(self, with_pass_tdata):
        path, passcode = with_pass_tdata
        parser = TDataParser(str(path), passcode=passcode)
        settings = parser.get_settings_info()
        assert "auto_start" in settings
        assert "production_config" in settings
