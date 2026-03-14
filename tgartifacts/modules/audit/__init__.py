from ..base import BaseModule


class AuditModule(BaseModule):
    @property
    def name(self):
        return 'audit'

    @property
    def description(self):
        return 'Security audit of tdata directory with MITRE ATT&CK mapping'

    @property
    def help_text(self):
        return (
            "Security audit of a tdata directory with MITRE mapping.\n"
            "\n"
            "Performs automated security checks and maps findings to MITRE ATT&CK "
            "and D3FEND frameworks.\n"
            "\n"
            "\b\n"
            "Checks performed:\n"
            "  - Passcode strength (tests against top-50 common passwords)\n"
            "  - File permissions on sensitive key files\n"
            "  - Encryption version detection\n"
            "  - Auth key exposure analysis\n"
            "\n"
            "\b\n"
            "Findings are color-coded by severity:\n"
            "  CRITICAL (red), WARNING (yellow), INFO (cyan)\n"
            "  Each finding includes the relevant MITRE ATT&CK technique ID.\n"
            "\n"
            "\b\n"
            "Examples:\n"
            "  tgartifacts audit /path/to/tdata\n"
            "  tgartifacts audit ~/.local/share/TelegramDesktop/tdata"
        )

    @property
    def available_methods(self):
        return ['audit']


module = AuditModule()
