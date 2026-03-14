from ..base import BaseModule


class InfoModule(BaseModule):
    @property
    def name(self):
        return 'info'

    @property
    def description(self):
        return 'Show information about tdata directory'

    @property
    def help_text(self):
        return (
            "Show information about a tdata directory.\n"
            "\n"
            "\b\n"
            "Displays:\n"
            "  - Number of accounts and their directory names\n"
            "  - User IDs and DC IDs for each account\n"
            "  - Passcode protection status\n"
            "  - Auth keys per DC (count and auth_key_id hashes)\n"
            "  - Keys marked for destruction\n"
            "  - Cached TDEF file count\n"
            "\n"
            "\b\n"
            "Examples:\n"
            "  tgartifacts info /path/to/tdata\n"
            "  tgartifacts info /path/to/tdata -p mypasscode\n"
            "  tgartifacts info /path/to/tdata -k"
        )

    @property
    def available_methods(self):
        return ['info']


module = InfoModule()
