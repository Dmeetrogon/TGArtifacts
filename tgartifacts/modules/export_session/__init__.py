from ..base import BaseModule


class ExportSessionModule(BaseModule):
    @property
    def name(self):
        return 'export-session'

    @property
    def description(self):
        return 'Export session data from tdata (JSON or Telethon StringSession)'

    @property
    def help_text(self):
        return (
            "Export session data from tdata (JSON or Telethon StringSession).\n"
            "\n"
            "Extracts auth keys and session data from all accounts found in tdata "
            "and saves them in the chosen format.\n"
            "\n"
            "\b\n"
            "Output formats:\n"
            "  json      Auth keys, user IDs, DC IDs as structured JSON\n"
            "  telethon  Telethon StringSession strings (v1 format)\n"
            "\n"
            "\b\n"
            "Examples:\n"
            "  tgartifacts export-session /path/to/tdata session.json\n"
            "  tgartifacts export-session /path/to/tdata session.txt -f telethon\n"
            "  tgartifacts export-session /path/to/tdata out.json -p mypasscode"
        )

    @property
    def available_methods(self):
        return ['export-session']


module = ExportSessionModule()
