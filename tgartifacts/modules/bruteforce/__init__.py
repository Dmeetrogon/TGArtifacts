from ..base import BaseModule


class BruteforceModule(BaseModule):
    @property
    def name(self):
        return 'bruteforce'

    @property
    def description(self):
        return 'Bruteforce tdata passcode using a wordlist. \nNote: this can be PAINFULLY slow'

    @property
    def help_text(self):
        return (
            "Bruteforce tdata passcode using a wordlist.\n"
            "\n"
            "Attempts to crack the local passcode protecting a tdata directory "
            "by trying each password from a wordlist file.\n"
            "\n"
            "\b\n"
            "Performance:\n"
            "  ~3 passwords/sec per thread (limited by PBKDF2 with 100k iterations).\n"
            "  Use --threads to parallelize across CPU cores.\n"
            "\n"
            "\b\n"
            "Examples:\n"
            "  tgartifacts bruteforce /path/to/tdata -w rockyou.txt\n"
            "  tgartifacts bruteforce /path/to/tdata -w wordlist.txt -t 4"
        )

    @property
    def available_methods(self):
        return ['bruteforce']


module = BruteforceModule()
