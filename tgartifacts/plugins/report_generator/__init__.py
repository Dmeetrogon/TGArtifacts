from typing import Any, Dict

from tgartifacts.plugins import BasePlugin, PluginContext


class ReportGeneratorPlugin(BasePlugin):
    name = "report-generator"
    description = "Full forensic report: extract cache, sessions, validate, hash — HTML + JSON"
    version = "0.1.0"

    def run(self, context: PluginContext) -> Dict[str, Any]:
        from .answer_cli import run
        return run(context)
