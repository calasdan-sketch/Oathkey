"""safeeasyapi was renamed to oathkey. This package only points to it."""
import sys

__version__ = "0.9.0"

MESSAGE = (
    "safeeasyapi has been renamed to oathkey.\n"
    "Nothing was moved for you: your old saved keys, settings and hook entries\n"
    "are not read by oathkey. To switch:\n"
    "  1. pipx install oathkey   (or: pip install oathkey)\n"
    "  2. oathkey get <service>  for each key you want to keep\n"
    "  3. oathkey install        to plug it into your AI tools\n"
    "  4. remove the old 'safeeasyapi' hook and MCP entries from your AI tools' settings\n"
    "More: https://github.com/calasdan-sketch/oathkey\n"
)


def main() -> int:
    sys.stderr.write(MESSAGE)
    return 1
