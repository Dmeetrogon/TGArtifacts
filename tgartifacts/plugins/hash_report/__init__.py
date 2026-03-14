from typing import Any, Dict

from tgartifacts.plugins import BasePlugin, PluginContext
from .report import generate_report


class HashReportPlugin(BasePlugin):
    name = "hash-report"
    description = "Generate SHA-256 and MD5 hashes for decrypted files, sorted by type"
    version = "0.2.0"

    def run(self, context: PluginContext) -> Dict[str, Any]:
        target_dir = context.output_dir or context.tdata_path
        if not target_dir.is_dir():
            raise FileNotFoundError(f"Directory not found: {target_dir}")
        return generate_report(target_dir)
