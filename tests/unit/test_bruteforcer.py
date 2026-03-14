"""UT-057..061: Bruteforcer tests."""

import pytest
from pathlib import Path

from tgartifacts.modules.bruteforce.bruteforcer import Bruteforcer, BruteforceResult


class TestBruteforceResult:
    """UT-057..058."""

    def test_ut057_result_attrs(self):
        """UT-057: BruteforceResult has correct attributes."""
        r = BruteforceResult(found=True, passcode="abc", attempts=10, elapsed=2.0)
        assert r.found is True
        assert r.passcode == "abc"
        assert r.attempts == 10
        assert r.elapsed == 2.0

    def test_ut058_speed_property(self):
        """UT-058: speed = attempts / elapsed."""
        r = BruteforceResult(found=False, attempts=100, elapsed=10.0)
        assert r.speed == pytest.approx(10.0)

    def test_speed_zero_elapsed(self):
        """speed == 0 when elapsed == 0."""
        r = BruteforceResult(found=False, attempts=0, elapsed=0.0)
        assert r.speed == 0


class TestBruteforcer:
    """UT-059..061."""

    def test_ut059_missing_key_datas(self, tmp_path):
        """UT-059: No key_datas → FileNotFoundError."""
        with pytest.raises(FileNotFoundError, match="key_datas"):
            Bruteforcer(tmp_path)

    def test_ut060_wordlist_not_found(self, no_pass_tdata):
        """UT-060: Missing wordlist → FileNotFoundError."""
        bf = Bruteforcer(no_pass_tdata)
        with pytest.raises(FileNotFoundError, match="Wordlist"):
            bf.bruteforce_wordlist(Path("/nonexistent/wordlist.txt"))

    def test_ut061_bruteforce_with_correct_passcode(self, with_pass_tdata, tmp_path):
        """UT-061: Bruteforcer finds 'penguin' in wordlist."""
        path, passcode = with_pass_tdata
        wordlist = tmp_path / "wl.txt"
        wordlist.write_text(f"wrong1\nwrong2\n{passcode}\n")
        bf = Bruteforcer(path)
        result = bf.bruteforce_wordlist(wordlist)
        assert result.found is True
        assert result.passcode == passcode
        assert result.local_key is not None
        assert len(result.local_key) == 256
