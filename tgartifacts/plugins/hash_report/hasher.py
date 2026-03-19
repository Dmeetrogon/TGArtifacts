import hashlib
from pathlib import Path
from typing import Dict


def compute_hashes(file_path: Path) -> Dict[str, str]:
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        while chunk := f.read(8192):
            sha256.update(chunk)
            md5.update(chunk)
    return {"sha256": sha256.hexdigest(), "md5": md5.hexdigest()}
