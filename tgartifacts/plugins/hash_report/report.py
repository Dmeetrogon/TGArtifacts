from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from .hasher import compute_hashes


def collect_entries(files: List[Path]) -> Dict[str, list]:
    by_type: Dict[str, list] = {}
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    for file_path in files:
        file_type = "".join(file_path.suffix.split('.')[1:])
        hashes = compute_hashes(file_path)
        entry = {
            "name": file_path.name,
            "sha256": hashes["sha256"],
            "md5": hashes["md5"],
            "type": file_type,
            "timestamp": timestamp,
        }
        by_type.setdefault(file_type, []).append(entry)
    return by_type


def write_report(by_type: Dict[str, list], report_path: Path) -> None:
    with open(report_path, "w") as f:
        for file_type in sorted(by_type):
            f.write(f"=== {file_type} ({len(by_type[file_type])} files) ===\n")
            for entry in by_type[file_type]:
                f.write(f"SHA-256 {entry['name']} {entry['sha256']} {entry['timestamp']}\n")
                f.write(f"MD5     {entry['name']} {entry['md5']} {entry['timestamp']}\n")
            f.write("\n")


def generate_report(target_dir: Path) -> Dict[str, Any]:
    files = sorted(f for f in target_dir.rglob("*") if f.is_file())
    if not files:
        return {"total": 0, "report": "No files found"}

    by_type = collect_entries(files)
    report_path = target_dir / "hash_report.txt"
    write_report(by_type, report_path)

    return {
        "total": len(files),
        "types": {t: len(entries) for t, entries in sorted(by_type.items())},
        "report": str(report_path),
    }
