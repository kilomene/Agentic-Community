"""`python -m acp_api` entry point.

Subcommands:
  keys ...   manage third-party API keys (see keys.py)
  serve ...  run the directory + presence server (see server.py)

Run from services/ so the acp_api package is importable.
"""
import sys


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__.strip())
        return 0
    if argv[0] == "keys":
        from . import keys
        return keys.main(argv[1:])
    if argv[0] == "serve":
        from . import server
        return server.main(argv[1:]) or 0
    print("unknown subcommand: %s\n" % argv[0] + __doc__.strip(),
          file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
