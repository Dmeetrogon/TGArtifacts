from ..base import BaseModule


class ListPluginsModule(BaseModule):
    @property
    def name(self):
        return 'list-plugins'

    @property
    def description(self):
        return 'List all available plugins'

    @property
    def help_text(self):
        return (
            "List all available plugins.\n"
            "\n"
            "Scans the built-in contrib directory and an optional custom plugins "
            "directory. For each plugin, displays name, version, and description.\n"
            "\n"
            "\b\n"
            "Examples:\n"
            "  tgartifacts list-plugins\n"
            "  tgartifacts list-plugins --plugins-dir ./my-plugins"
        )

    @property
    def available_methods(self):
        return ['list-plugins']


module = ListPluginsModule()
