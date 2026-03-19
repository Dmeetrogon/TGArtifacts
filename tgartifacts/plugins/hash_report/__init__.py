from typing import Any, Dict

from tgartifacts.plugins import BasePlugin, PluginContext


class HashReportPlugin(BasePlugin):
    name = "hash-report"
    description = "Generate SHA-256 and MD5 hashes for decrypted files, sorted by type"
    version = "0.2.0"

    def run(self, context: PluginContext) -> Dict[str, Any]:
        from .answer_cli import run
        return run(context)
