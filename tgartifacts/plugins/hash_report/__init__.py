import hashlib
from typing import Any, Dict

from tgartifacts.plugins import BasePlugin, PluginContext


class HashReportPlugin(BasePlugin):
    name = "hash-report"
    description = "Generate SHA-256 hashes for all cached files"
    version = "0.1.0"

    def run(self, context: PluginContext) -> Dict[str, Any]:
        hashes = {}
        for file_path in context.cache_files:
            with open(file_path, "rb") as f:
                sha256 = hashlib.sha256(f.read()).hexdigest()
            hashes[file_path.name] = sha256

        return {"total": len(hashes), "hashes": hashes}
