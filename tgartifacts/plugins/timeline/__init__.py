from typing import Any, Dict

from tgartifacts.plugins import BasePlugin, PluginContext


class TimelinePlugin(BasePlugin):
    name = "timeline"
    description = "Forensic timeline analysis of tdata with anomaly detection"
    version = "0.1.0"

    def run(self, context: PluginContext) -> Dict[str, Any]:
        from .answer_cli import run
        return run(context)
