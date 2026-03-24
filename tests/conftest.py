import platform
import sys

import pytest
from pathlib import Path

TDATA_TEST = Path(__file__).parent.parent / "tdata_test"
FIXTURES = Path(__file__).parent / "fixtures"



def pytest_configure(config):
    config.addinivalue_line("markers", "live: tests that hit real Telegram API")
    config.addinivalue_line("markers", "slow: slow tests (bruteforce)")

    try:
        from importlib.metadata import version
        project_version = version("tgartifacts")
    except Exception:
        project_version = "unknown"

    config.stash["tgartifacts_version"] = project_version

    if hasattr(config, "_metadata"):
        config._metadata["Project"] = "TGArtifacts"
        config._metadata["Version"] = project_version
        config._metadata["Python"] = sys.version
        config._metadata["Platform"] = platform.platform()


def pytest_html_report_title(report):
    report.title = "TGArtifacts Test Report"


def pytest_html_results_table_header(cells):
    cells.insert(2, "<th>Description</th>")


def pytest_html_results_table_row(report, cells):
    cells.insert(2, f"<td>{getattr(report, 'description', '')}</td>")


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    report = outcome.get_result()
    report.description = str(item.function.__doc__ or "")



@pytest.fixture
def no_pass_tdata():
    path = TDATA_TEST / "no_pass" / "tdata_copy_without_password"
    if not path.exists():
        pytest.skip("tdata_test/no_pass not available")
    return path


@pytest.fixture
def with_pass_tdata():
    path = TDATA_TEST / "with_pass" / "tdata_with_password"
    if not path.exists():
        pytest.skip("tdata_test/with_pass not available")
    return path, "penguin"


@pytest.fixture
def no_pass_multi_tdata():
    path = TDATA_TEST / "no_pass_multi" / "tdata_without_password_and_multi"
    if not path.exists():
        pytest.skip("tdata_test/no_pass_multi not available")
    return path


@pytest.fixture
def with_pass_multi_tdata():
    path = TDATA_TEST / "with_pass_multi" / "tdata_with_password_and_multi"
    if not path.exists():
        pytest.skip("tdata_test/with_pass_multi not available")
    return path, "penguin"


@pytest.fixture
def old_no_pass_tdata():
    path = TDATA_TEST / "tdata_old_without"
    if not path.exists():
        pytest.skip("tdata_test/tdata_old_without not available")
    return path


@pytest.fixture
def old_with_pass_tdata():
    path = TDATA_TEST / "tdata_old_with"
    if not path.exists():
        pytest.skip("tdata_test/tdata_old_with not available")
    return path, "penguin"



@pytest.fixture
def key_datas_fixture():
    path = FIXTURES / "key_datas_modern"
    if not path.exists():
        pytest.skip("fixtures/key_datas_modern not available")
    return path


@pytest.fixture
def sample_tdef_fixture():
    path = FIXTURES / "sample.tdef"
    if not path.exists():
        pytest.skip("fixtures/sample.tdef not available")
    return path



@pytest.fixture
def cli_runner():
    from click.testing import CliRunner
    from tgartifacts.cli import cli
    return CliRunner(), cli



@pytest.fixture
def output_dir(tmp_path):
    out = tmp_path / "output"
    out.mkdir()
    return out


@pytest.fixture
def corrupted_tdata_no_keys(tmp_path):
    """tdata directory without key_datas file."""
    tdata = tmp_path / "tdata_no_keys"
    tdata.mkdir()
    (tdata / "settingss").write_bytes(b"\x00" * 64)
    return tdata


@pytest.fixture
def corrupted_tdata_no_settings(tmp_path, no_pass_tdata):
    """tdata directory with valid key_datas but no settingss file."""
    import shutil
    tdata = tmp_path / "tdata_no_settings"
    shutil.copytree(no_pass_tdata, tdata)
    settings = tdata / "settingss"
    if settings.exists():
        settings.unlink()
    settings_s = tdata / "settingss0"
    if settings_s.exists():
        settings_s.unlink()
    settings_1 = tdata / "settingss1"
    if settings_1.exists():
        settings_1.unlink()
    return tdata


@pytest.fixture
def corrupted_tdata_bad_key_datas(tmp_path):
    """tdata directory with garbage key_datas."""
    tdata = tmp_path / "tdata_bad_keys"
    tdata.mkdir()
    (tdata / "key_datas").write_bytes(b"TDF$\x00\x00\x00\x01" + b"\xff" * 200)
    return tdata


@pytest.fixture
def corrupted_tdata_empty(tmp_path):
    """Completely empty tdata directory."""
    tdata = tmp_path / "tdata_empty"
    tdata.mkdir()
    return tdata


@pytest.fixture
def corrupted_tdata_truncated_key(tmp_path, no_pass_tdata):
    """tdata with truncated key_datas (partial file)."""
    import shutil
    tdata = tmp_path / "tdata_truncated"
    shutil.copytree(no_pass_tdata, tdata)
    key_datas = tdata / "key_datas"
    original = key_datas.read_bytes()
    key_datas.write_bytes(original[:32])
    return tdata
