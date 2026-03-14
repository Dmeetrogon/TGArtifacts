from ..base import BaseModule


class ValidateSessionModule(BaseModule):
    @property
    def name(self):
        return 'validate-session'

    @property
    def description(self):
        return 'Validate a Telethon StringSession via Telegram API'

    @property
    def help_text(self):
        return (
            "Validate a Telethon StringSession via Telegram API.\n"
            "\n"
            "Connects to Telegram using the provided StringSession string and "
            "checks if the session is still active. On success, displays the "
            "associated user information.\n"
            "\n"
            "\b\n"
            "Output on valid session:\n"
            "  - User ID\n"
            "  - First/last name\n"
            "  - Username\n"
            "  - Phone number\n"
            "\n"
            "\b\n"
            "Requires: telethon>=2.0\n"
            "Install:  pip install tgartifacts[validate-session]\n"
            "\n"
            "\b\n"
            "Examples:\n"
            "  tgartifacts validate-session 1BVtsOH...\n"
            "  tgartifacts validate-session \"$(cat session.txt)\""
        )

    @property
    def dependencies(self):
        return ['export-session']

    @property
    def requirements(self):
        return ['telethon>=2.0']

    @property
    def available_methods(self):
        return ['validate-session']


module = ValidateSessionModule()
