"""i18n_patch: wire ``--lang`` into the acp CLI without editing cli.py.

Public API: ``apply_i18n(lang)`` monkey-patches the CLI's message
functions so status/error strings come out in the requested locale:

  - ``cli.build_parser`` is wrapped to add a ``--lang`` flag
    (choices = acp_i18n.available_langs());
  - ``cli.AcpShell._emit`` is wrapped: every REPL output line passes
    through ``_tr_line``;
  - ``cli.init_home`` / ``cli.serve_home`` / ``cli.main`` are wrapped so
    their ``print`` output is translated line-by-line while streaming
    (the interactive REPL keeps working).

Translation is pattern-based: the exact English format strings emitted
by cli.py are matched with regexes and rebuilt from acp_i18n fragments
(dynamic values — peer ids, hosts, codes — are preserved verbatim).
Lines that match nothing pass through unchanged (English); coverage is
deliberate, not guessed.

Run the CLI with a locale like this::

    python3 apps/acp_cli/i18n_patch.py --lang es serve --home DIR --port 8080
    python3 apps/acp_cli/i18n_patch.py --lang yo init --home DIR --handle x

or from Python::

    from apps.acp_cli import i18n_patch  # with apps/acp_cli on sys.path
    i18n_patch.apply_i18n("fr")
    import cli
    cli.main([...])   # --lang is accepted now
"""

import builtins
import functools
import os
import re
import sys

CLI_DIR = os.path.dirname(os.path.abspath(__file__))
PROJ_ROOT = os.path.dirname(os.path.dirname(CLI_DIR))
for _p in (CLI_DIR, os.path.join(PROJ_ROOT, "packages")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from acp_i18n import t, available_langs  # noqa: E402
import cli as _cli  # noqa: E402

__all__ = ["apply_i18n", "tr_line", "main"]


def tr_line(line, lang="en"):
    """Translate one CLI output line. Unknown lines pass through."""
    if not lang or lang == "en":
        return line
    for rx, build in _PATTERNS:
        m = rx.match(line)
        if m:
            try:
                return build(m, lang)
            except Exception:
                return line
    return line


# Alias kept for the documented name.
_tr_line = tr_line


def _b(key):
    return lambda m, lang: t(key, lang)


def _j(*parts):
    return lambda m, lang: "".join(
        p(m, lang) if callable(p) else p for p in parts)


def _g(i):
    return lambda m, lang: m.group(i)


_PATTERNS = [
    # init_home
    (re.compile(r"^home already initialized at (.+)$"),
     _j(lambda m, l: t("cli_home_exists", l), " ", _g(1))),
    (re.compile(r"^identity created at (.+)$"),
     _j(lambda m, l: t("cli_identity_created", l), " ", _g(1))),
    (re.compile(r"^handle:  (.+)$"),
     _j(lambda m, l: t("cli_handle", l), " ", _g(1))),
    (re.compile(r"^peer id: (.+)$"),
     _j(lambda m, l: t("cli_peer_id", l), " ", _g(1))),
    # serve_home startup / errors
    (re.compile(r"^ERROR (\S+): (.+?) is not initialized "
                r"\(run: acp init --home (.+) --handle NAME first\)$"),
     lambda m, l: "%s %s: %s %s" % (
         t("cli_error", l), m.group(1), m.group(2),
         t("cli_not_initialized", l).format(home=m.group(3)))),
    (re.compile(r"^serving as '(.+)' \((.+)\)$"),
     _j(lambda m, l: t("cli_serving_as", l), " '", _g(1), "' (", _g(2), ")")),
    (re.compile(r"^listening on (.+):(\d+)$"),
     _j(lambda m, l: t("cli_listening_on", l), " ", _g(1), ":", _g(2))),
    (re.compile(r"^type 'help' for commands, 'quit' to exit\.$"),
     _b("cli_type_help")),
    (re.compile(r"^stopped\.$"), _b("cli_stopped")),
    # pairing flow
    (re.compile(r"^PAIRING REQUEST from '(.+)' \((.+)\)\. Your code: (.+)$"),
     lambda m, l: "%s '%s' (%s). %s: %s" % (
         t("cli_pairing_request", l), m.group(1), m.group(2),
         t("cli_your_code", l), m.group(3))),
    (re.compile(r"^Ask the other side to type:  confirm (.+)$"),
     _j(lambda m, l: t("cli_ask_confirm", l), " confirm ", _g(1))),
    (re.compile(r"^Pairing request sent to (.+):(\d+)\.$"),
     _j(lambda m, l: t("cli_pairing_request_sent", l), " ",
        _g(1), ":", _g(2), ".")),
    (re.compile(r"^Waiting for code \u2014 type:  "
                r"confirm <code shown on other side>$"),
     _j(lambda m, l: t("cli_waiting_for_code", l), " \u2014 ",
        lambda m2, l2: t("cli_type_confirm", l2))),
    (re.compile(r"^no pending pairing \u2014 use: pair <host> <port> first$"),
     _b("cli_no_pending_pair")),
    (re.compile(r"^challenge not received yet \u2014 wait a moment, "
                r"then retry: confirm <code>$"),
     _b("cli_challenge_pending")),
    (re.compile(r"^already paired with '(.+)' \((.+)\)$"),
     _j(lambda m, l: t("cli_already_paired", l), " '", _g(1), "' (",
        _g(2), ")")),
    (re.compile(r"^Paired with '(.+)' \((.+)\)$"),
     _j(lambda m, l: t("cli_paired_with", l), " '", _g(1), "' (", _g(2),
        ")")),
    (re.compile(r"^pairing failed \u2014 check: audit$"),
     _b("cli_pairing_failed")),
    (re.compile(r"^confirm sent; welcome not received yet \u2014 "
                r"check: peers$"),
     _b("cli_confirm_sent")),
    # peers / messaging / files
    (re.compile(r"^\(no paired peers yet \u2014 use: pair <host> <port>\)$"),
     _b("cli_no_peers")),
    (re.compile(r"^sent \((.+)\)$"),
     _j(lambda m, l: t("cli_sent", l), " (", _g(1), ")")),
    (re.compile(r"^\(inbox empty\)$"), _b("cli_inbox_empty")),
    (re.compile(r"^MSG from (.+): (.*)$"),
     _j(lambda m, l: t("cli_msg_from", l), " ", _g(1), ": ", _g(2))),
    (re.compile(r"^FILE received: (.+) \((\d+) bytes, sha256 ok\)$"),
     lambda m, l: "%s %s (%s %s)" % (
         t("cli_file_received", l), m.group(1), m.group(2),
         t("cli_bytes_ok", l))),
    # permissions / projects / misc commands
    (re.compile(r"^granted '(.+)' to (.+)$"),
     _j(lambda m, l: t("cli_granted", l), " '", _g(1), "' \u2192 ", _g(2))),
    (re.compile(r"^revoked '(.+)' from (.+)$"),
     _j(lambda m, l: t("cli_revoked", l), " '", _g(1), "' \u2192 ", _g(2))),
    (re.compile(r"^peer (.+) revoked$"),
     _j(lambda m, l: t("label_peer", l), " ", _g(1), " ",
        lambda m2, l2: t("cli_revoked", l2))),
    (re.compile(r"^presence set: (.+)$"),
     _j(lambda m, l: t("cli_presence_set", l), " ", _g(1))),
    (re.compile(r"^E2E keys rotated; KEY_ROTATE broadcast to peers\.$"),
     _b("cli_keys_rotated")),
    (re.compile(r"^registered handle '(.+)' at (.+)$"),
     _j(lambda m, l: t("cli_registered", l), " '", _g(1), "' @ ", _g(2))),
    (re.compile(r"^project created: (.+)$"),
     _j(lambda m, l: t("cli_project_created", l), ": ", _g(1))),
    (re.compile(r"^task added: (.+)$"),
     _j(lambda m, l: t("cli_task_added", l), ": ", _g(1))),
    (re.compile(r"^family member added: (.+)$"),
     _j(lambda m, l: t("cli_family_added", l), ": ", _g(1))),
    (re.compile(r"^\(audit log empty\)$"), _b("cli_audit_empty")),
    (re.compile(r"^\(no grants for (.+)\)$"),
     lambda m, l: "(%s)" % t("cli_no_grants_for", l).format(
         peer=m.group(1))),
    (re.compile(r"^unknown command '(.+)' \u2014 type 'help' for commands\.$"),
     _j(lambda m, l: t("cli_unknown_command", l), " '", _g(1), "'")),
    # guard / main error formatting (specific before general)
    (re.compile(r"^interrupted$"), _b("cli_interrupted")),
    (re.compile(r"^ERROR DIRECTORY: (.*)$"),
     _j(lambda m, l: t("cli_error", l), " DIRECTORY: ", _g(1))),
    (re.compile(r"^ERROR INTERNAL: ([A-Za-z_]+): (.*)$"),
     _j(lambda m, l: t("cli_error", l), " INTERNAL: ", _g(1), ": ",
        _g(2))),
    (re.compile(r"^ERROR ([A-Z_]+): (.*)$"),
     _j(lambda m, l: t("cli_error", l), " ", _g(1), ": ", _g(2))),
]

del _b, _j, _g

_ORIGINALS = {}


def _wrap(key, obj, attr, make):
    """Wrap obj.attr with make(original), always from the original so
    apply_i18n stays idempotent and lang-switchable."""
    if key not in _ORIGINALS:
        _ORIGINALS[key] = getattr(obj, attr)
    setattr(obj, attr, make(_ORIGINALS[key]))


def _patch_build_parser():
    def make(orig):
        @functools.wraps(orig)
        def build_parser():
            p = orig()
            try:
                # idempotent: only add once per parser instance chain
                p.add_argument("--lang", default="en",
                               choices=sorted(available_langs()),
                               help="output language for status/error "
                                    "messages")
            except Exception:
                pass
            return p

        return build_parser

    _wrap("build_parser", _cli, "build_parser", make)


def _translated_emit(orig_emit, lang):
    @functools.wraps(orig_emit)
    def _emit(self, line):
        return orig_emit(self, tr_line(line, lang))

    return _emit


def _with_translated_print(fn, lang):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        orig_print = builtins.print

        def tprint(*pargs, **pkwargs):
            sep = pkwargs.pop("sep", " ")
            end = pkwargs.pop("end", "\n")
            text = sep.join(str(x) for x in pargs)
            text = "\n".join(tr_line(ln, lang)
                             for ln in text.split("\n"))
            orig_print(text, end=end, **pkwargs)

        builtins.print = tprint
        try:
            return fn(*args, **kwargs)
        finally:
            builtins.print = orig_print

    return wrapper


def apply_i18n(lang="en"):
    """Patch the CLI's message functions for locale ``lang``.

    Safe to call repeatedly (re-applying switches language). Unknown
    locale codes fall back to English.
    """
    if lang not in available_langs():
        lang = "en"
    _patch_build_parser()
    _wrap("emit", _cli.AcpShell, "_emit",
          lambda orig: _translated_emit(orig, lang))
    for name in ("init_home", "serve_home", "main"):
        _wrap(name, _cli, name,
              lambda orig, _n=name: _with_translated_print(orig, lang))
    return lang


def main(argv=None):
    """Entry point: parse --lang early, patch, then run the real CLI."""
    import argparse
    pre = argparse.ArgumentParser(add_help=False)
    pre.add_argument("--lang", default="en")
    ns, _ = pre.parse_known_args(argv)
    apply_i18n(ns.lang)
    return _cli.main(argv)


if __name__ == "__main__":
    sys.exit(main())
