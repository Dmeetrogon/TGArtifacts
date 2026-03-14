import pytest
from pathlib import Path

TDATA_TEST = Path(__file__).parent.parent / "tdata_test"
FIXTURES = Path(__file__).parent / "fixtures"


def pytest_configure(config):
    config.addinivalue_line("markers", "live: tests that hit real Telegram API")
    config.addinivalue_line("markers", "slow: slow tests (bruteforce)")


# --------------- tdata fixtures ---------------

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


# --------------- fixture files ---------------

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


# --------------- CLI runner ---------------

@pytest.fixture
def cli_runner():
    from click.testing import CliRunner
    from tgartifacts.cli import cli
    return CliRunner(), cli


# --------------- tmp output dir ---------------

@pytest.fixture
def output_dir(tmp_path):
    out = tmp_path / "output"
    out.mkdir()
    return out
