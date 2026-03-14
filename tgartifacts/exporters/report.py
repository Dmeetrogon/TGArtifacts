from pathlib import Path
from typing import Any, Dict, List

from .json_exporter import JSONExporter


class ReportGenerator:
    def __init__(self, accounts: List[Dict[str, Any]], extracted_files: List[Path] = None):
        self.accounts = accounts
        self.extracted_files = extracted_files or []

    def generate_json(self, output_path: Path) -> None:
        exporter = JSONExporter(self.accounts, self.extracted_files)
        exporter.export(output_path)
