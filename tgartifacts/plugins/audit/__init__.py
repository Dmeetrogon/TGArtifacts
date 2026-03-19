from typing import Any, Dict

from tgartifacts.plugins import BasePlugin, PluginContext


class AuditPlugin(BasePlugin):
    name = "audit"
    description = "Security audit of tdata directory with MITRE ATT&CK mapping"
    version = "0.2.0"

    def run(self, context: PluginContext) -> Dict[str, Any]:
        from .answer_cli import run
        return run(context)
