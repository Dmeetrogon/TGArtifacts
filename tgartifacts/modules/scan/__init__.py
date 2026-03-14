from ..base import BaseModule


class ScanModule(BaseModule):
    @property
    def name(self):
        return 'scan'

    @property
    def description(self):
        return 'Auto-detect Telegram Desktop tdata directories'

    @property
    def help_text(self):
        return (
            "Auto-detect Telegram Desktop tdata directories.\n"
            "\n"
            "Searches standard installation locations and optional custom paths.\n"
            "\n"
            "\b\n"
            "Searches:\n"
            "  - Native install (~/.local/share/TelegramDesktop)\n"
            "  - Snap (~/snap/telegram-desktop)\n"
            "  - Flatpak (~/.var/app/org.telegram.desktop)\n"
            "\n"
            "For each location found, shows validation status, key_datas presence, "
            "and account directories.\n"
            "\n"
            "\b\n"
            "Examples:\n"
            "  tgartifacts scan\n"
            "  tgartifacts scan -p /mnt/backup/tdata -p /tmp/tdata"
        )

    @property
    def available_methods(self):
        return ['scan']


module = ScanModule()
