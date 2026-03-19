"""TC-18..21: bruteforce command integration tests."""

import pytest


@pytest.mark.slow
class TestBruteforce:
    """TC-18..21."""

    def test_tc18_bruteforce_finds_passcode(self, cli_runner, with_pass_tdata, tmp_path):
        """TC-18: Bruteforce finds 'penguin' in wordlist."""
        runner, cli = cli_runner
        path, passcode = with_pass_tdata
        wl = tmp_path / "wl.txt"
        wl.write_text("wrong1\nwrong2\npenguin\nwrong3\n")
        result = runner.invoke(cli, ['bruteforce', str(path), '-w', str(wl)])
        assert result.exit_code == 0
        assert 'Passcode found: penguin' in result.output
        assert 'TDesktop version:' in result.output

    def test_tc19_bruteforce_not_found(self, cli_runner, with_pass_tdata, tmp_path):
        """TC-19: Wordlist without correct passcode → not found."""
        runner, cli = cli_runner
        path, _ = with_pass_tdata
        wl = tmp_path / "wl.txt"
        wl.write_text("wrong1\nwrong2\nwrong3\n")
        result = runner.invoke(cli, ['bruteforce', str(path), '-w', str(wl)])
        assert result.exit_code == 0
        assert 'Passcode not found' in result.output

    def test_tc20_bruteforce_no_pass_tdata(self, cli_runner, no_pass_tdata, tmp_path):
        """TC-20: No-passcode tdata — bruteforcer skips empty lines, reports not found."""
        runner, cli = cli_runner
        wl = tmp_path / "wl.txt"
        wl.write_text("wrong1\nwrong2\n")
        result = runner.invoke(cli, ['bruteforce', str(no_pass_tdata), '-w', str(wl)])
        assert result.exit_code == 0
        assert 'Passcode not found' in result.output

    def test_tc21_bruteforce_shows_stats(self, cli_runner, with_pass_tdata, tmp_path):
        """TC-21: Output includes attempts and timing."""
        runner, cli = cli_runner
        path, _ = with_pass_tdata
        wl = tmp_path / "wl.txt"
        wl.write_text("a\nb\nc\n")
        result = runner.invoke(cli, ['bruteforce', str(path), '-w', str(wl)])
        assert 'Attempts:' in result.output
        assert 'Time:' in result.output

    def test_tc27_bruteforce_top10_common_passwords(self, cli_runner, with_pass_tdata, tmp_path):
        """Bruteforce should crack passcode using top-10 common passwords."""
        runner, cli = cli_runner
        path, _ = with_pass_tdata
        wl = tmp_path / "top10.txt"
        wl.write_text(
            "123456\npassword\nadmin\nqwerty\nletmein\n"
            "welcome\nmonkey\nmaster\ndragon\nlogin\n"
        )
        result = runner.invoke(cli, ['bruteforce', str(path), '-w', str(wl)])
        assert result.exit_code == 0
        assert 'Passcode found' in result.output

    def test_tc28_bruteforce_rockyou_subset(self, cli_runner, with_pass_tdata, tmp_path):
        """Bruteforce should find passcode within rockyou subset."""
        runner, cli = cli_runner
        path, _ = with_pass_tdata
        wl = tmp_path / "rockyou_subset.txt"
        wl.write_text(
            "rockyou\niloveyou\nprincess\nabc123\nnicole\n"
            "daniel\nbabygirl\nlovely\nmichael\nashley\n"
            "shadow\nsunshine\njessica\npepper\nginger\n"
        )
        result = runner.invoke(cli, ['bruteforce', str(path), '-w', str(wl)])
        assert result.exit_code == 0
        assert 'Passcode found' in result.output
