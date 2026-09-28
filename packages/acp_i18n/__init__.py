"""acp_i18n: gettext-style string catalogs for the Agent Community UI/CLI.

Six locales: en, es, fr, de, zh, yo (Yoruba). ``t(key, lang)`` looks the
key up in the requested locale and falls back to English, then to the key
itself, so a missing translation never breaks rendering.

Stdlib only. No external .mo files: catalogs are plain dicts in
catalogs.py, hand-written (short, human-quality strings).
"""

from .catalogs import CATALOGS, LANG_NAMES  # noqa: F401

DEFAULT_LANG = "en"

__all__ = ["t", "available_langs", "lang_name", "DEFAULT_LANG",
           "CATALOGS", "LANG_NAMES"]


def available_langs():
    """Locale codes with full catalogs, in preferred order."""
    return [c for c in ("en", "es", "fr", "de", "zh", "yo")
            if c in CATALOGS]


def lang_name(code):
    """Human-readable language name for a locale code."""
    return LANG_NAMES.get(code, code)


def t(key, lang="en"):
    """Translate ``key`` into ``lang``.

    Fallback chain: requested locale -> English -> the key itself.
    Never returns an empty string for a known key.
    """
    if not lang or lang not in CATALOGS:
        lang = DEFAULT_LANG
    s = CATALOGS[lang].get(key)
    if s:
        return s
    s = CATALOGS[DEFAULT_LANG].get(key)
    if s:
        return s
    return key
