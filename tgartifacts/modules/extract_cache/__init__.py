from ..base import BaseModule


class ExtractCacheModule(BaseModule):
    @property
    def name(self):
        return 'extract-cache'

    @property
    def description(self):
        return 'Extract and decrypt cached TDEF files'

    @property
    def help_text(self):
        return (
            "Extract and decrypt cached TDEF files from a tdata directory.\n"
            "\n"
            "Finds all cached TDEF (Telegram Desktop Encrypted File) entries, "
            "decrypts them, and saves the plaintext files to the output directory. "
            "Also reassembles streaming cache fragments.\n"
            "\n"
            "\b\n"
            "Output statistics:\n"
            "  - Total files found\n"
            "  - Successfully decrypted\n"
            "  - Streaming cache reassembled\n"
            "  - Failures\n"
            "\n"
            "\b\n"
            "Examples:\n"
            "  tgartifacts extract-cache /path/to/tdata ./extracted\n"
            "  tgartifacts extract-cache /path/to/tdata ./out -p mypasscode"
        )

    @property
    def available_methods(self):
        return ['extract-cache']


module = ExtractCacheModule()
