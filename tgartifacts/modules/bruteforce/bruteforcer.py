import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
from typing import Optional, Callable, List, Tuple

from ...parsers.tdf_reader import read_tdf
from ...parsers.qt_stream import QtDataStreamReader
from ...crypto.keys import create_local_key
from ...crypto.decryptor import decrypt_tdf_legacy


class BruteforceResult:
    def __init__(self, found: bool, passcode: Optional[str] = None,
                 local_key: Optional[bytes] = None, attempts: int = 0,
                 elapsed: float = 0.0):
        self.found = found
        self.passcode = passcode
        self.local_key = local_key
        self.attempts = attempts
        self.elapsed = elapsed

    @property
    def speed(self) -> float:
        if self.elapsed == 0:
            return 0
        return self.attempts / self.elapsed


def _try_batch(salt: bytes, key_encrypted: bytes, version: int,
               batch: List[str]) -> Optional[Tuple[str, bytes]]:
    for passcode in batch:
        try:
            passcode_key = create_local_key(passcode, salt, version)
            local_key = decrypt_tdf_legacy(key_encrypted, passcode_key)
            return (passcode, local_key)
        except ValueError:
            continue
    return None


class Bruteforcer:
    def __init__(self, tdata_path: Path):
        self.tdata_path = Path(tdata_path)
        key_datas_path = self.tdata_path / 'key_datas'
        if not key_datas_path.exists():
            raise FileNotFoundError("key_datas not found")

        key_datas_tdf = read_tdf(str(key_datas_path))
        self.version = key_datas_tdf['version']
        reader = QtDataStreamReader(key_datas_tdf['data'])
        self.salt = reader.read_bytearray()
        self.key_encrypted = reader.read_bytearray()

        if self.salt is None or self.key_encrypted is None:
            raise ValueError("Invalid key_datas format")

    def _try_passcode(self, passcode: str) -> Optional[bytes]:
        try:
            passcode_key = create_local_key(passcode, self.salt, self.version)
            return decrypt_tdf_legacy(self.key_encrypted, passcode_key)
        except ValueError:
            return None

    def bruteforce_wordlist(self, wordlist_path: Path,
                            threads: int = 1,
                            on_progress: Optional[Callable] = None) -> BruteforceResult:
        wordlist_path = Path(wordlist_path)
        if not wordlist_path.exists():
            raise FileNotFoundError(f"Wordlist not found: {wordlist_path}")

        start = time.time()

        if threads <= 1:
            return self._bruteforce_single(wordlist_path, start, on_progress)

        return self._bruteforce_multi(wordlist_path, threads, start, on_progress)

    def _bruteforce_single(self, wordlist_path: Path, start: float,
                           on_progress: Optional[Callable]) -> BruteforceResult:
        attempts = 0
        with open(wordlist_path, 'r', errors='ignore') as f:
            for line in f:
                passcode = line.strip()
                if not passcode:
                    continue
                attempts += 1
                local_key = self._try_passcode(passcode)
                if local_key is not None:
                    return BruteforceResult(
                        found=True, passcode=passcode, local_key=local_key,
                        attempts=attempts, elapsed=time.time() - start
                    )
                if on_progress and attempts % 10 == 0:
                    on_progress(attempts, time.time() - start)

        return BruteforceResult(
            found=False, attempts=attempts, elapsed=time.time() - start
        )

    def _bruteforce_multi(self, wordlist_path: Path, threads: int,
                          start: float,
                          on_progress: Optional[Callable]) -> BruteforceResult:
        batch_size = 50
        attempts = 0

        with open(wordlist_path, 'r', errors='ignore') as f:
            passwords = [line.strip() for line in f if line.strip()]

        with ProcessPoolExecutor(max_workers=threads) as executor:
            futures = {}
            for i in range(0, len(passwords), batch_size):
                batch = passwords[i:i + batch_size]
                future = executor.submit(
                    _try_batch, self.salt, self.key_encrypted,
                    self.version, batch
                )
                futures[future] = batch

            for future in as_completed(futures):
                batch = futures[future]
                attempts += len(batch)
                result = future.result()

                if result is not None:
                    passcode, local_key = result
                    executor.shutdown(wait=False, cancel_futures=True)
                    return BruteforceResult(
                        found=True, passcode=passcode, local_key=local_key,
                        attempts=attempts, elapsed=time.time() - start
                    )

                if on_progress and attempts % 50 == 0:
                    on_progress(attempts, time.time() - start)

        return BruteforceResult(
            found=False, attempts=attempts, elapsed=time.time() - start
        )
