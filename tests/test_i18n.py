"""Tests for packages/acp_i18n and apps/acp_cli/i18n_patch.

Run: python3 -m pytest tests/test_i18n.py -q   (from repo root)
"""
import os
import sys
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "packages"))
sys.path.insert(0, os.path.join(REPO_ROOT, "apps", "acp_cli"))

from acp_i18n import (  # noqa: E402
    t, available_langs, lang_name, DEFAULT_LANG, CATALOGS,
)


class CatalogTests(unittest.TestCase):
    def test_six_locales_available(self):
        self.assertEqual(available_langs(),
                         ["en", "es", "fr", "de", "zh", "yo"])

    def test_every_key_present_in_every_locale(self):
        en_keys = set(CATALOGS["en"])
        self.assertGreaterEqual(len(en_keys), 60,
                               "catalog must cover >= 60 UI/CLI strings")
        for lang in available_langs():
            keys = set(CATALOGS[lang])
            self.assertEqual(keys, en_keys,
                             "locale %s key set differs from en" % lang)

    def test_no_empty_strings(self):
        for lang in available_langs():
            for key, val in CATALOGS[lang].items():
                self.assertIsInstance(val, str)
                self.assertTrue(val.strip(),
                                "empty string for %s/%s" % (lang, key))

    def test_t_returns_translations(self):
        self.assertEqual(t("btn_send", "es"), "Enviar")
        self.assertEqual(t("btn_send", "fr"), "Envoyer")
        self.assertEqual(t("btn_send", "de"), "Senden")
        self.assertEqual(t("btn_send", "zh"), "发送")
        self.assertEqual(t("btn_send", "yo"), "Ránṣẹ́")
        self.assertEqual(t("nav_audit", "yo"), "Àyẹ̀wò")

    def test_fallback_to_english(self):
        # unknown locale -> english
        self.assertEqual(t("btn_send", "xx"), t("btn_send", "en"))
        self.assertEqual(t("btn_send", None), t("btn_send", "en"))
        self.assertEqual(t("btn_send", ""), t("btn_send", "en"))

    def test_missing_key_returns_key(self):
        self.assertEqual(t("no.such.key", "es"), "no.such.key")
        self.assertEqual(t("no.such.key", "en"), "no.such.key")

    def test_lang_names(self):
        self.assertEqual(lang_name("yo"), "Yorùbá")
        self.assertEqual(lang_name("zh"), "中文")
        self.assertEqual(DEFAULT_LANG, "en")

    def test_translations_are_not_english_copies(self):
        # every locale must actually translate (not just copy en)
        for lang in ("es", "fr", "de", "zh", "yo"):
            same = sum(1 for k in CATALOGS["en"]
                       if CATALOGS[lang][k] == CATALOGS["en"][k])
            # a handful of tokens (ERROR, Token, Host...) legitimately match
            self.assertLess(same, 15,
                            "locale %s looks untranslated (%d identical)"
                            % (lang, same))


class PatchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import i18n_patch  # noqa: E402
        cls.patch = i18n_patch
        import cli  # noqa: E402
        cls.cli = cli
        # NOTE: wrapped in staticmethod so that reading them back via
        # ``self.orig_*`` does NOT bind them to the test instance. A bare
        # function kept as a class attribute is a descriptor, so
        # ``self.orig_parser`` would otherwise return a *bound method* of
        # the test instance and tearDown would restore that bound method
        # onto the cli module, poisoning every later test.
        cls.orig_emit = staticmethod(cli.AcpShell._emit)
        cls.orig_main = staticmethod(cli.main)
        cls.orig_init = staticmethod(cli.init_home)
        cls.orig_serve = staticmethod(cli.serve_home)
        cls.orig_parser = staticmethod(cli.build_parser)

    def tearDown(self):
        # restore pristine cli module state for other tests
        self.cli.AcpShell._emit = self.orig_emit
        self.cli.main = self.orig_main
        self.cli.init_home = self.orig_init
        self.cli.serve_home = self.orig_serve
        self.cli.build_parser = self.orig_parser
        self.patch._ORIGINALS.clear()

    def test_apply_i18n_patches_emit(self):
        self.patch.apply_i18n("es")
        self.assertIsNot(self.cli.AcpShell._emit, self.orig_emit)
        self.assertEqual(self.patch.tr_line("stopped.", "es"), "detenido.")
        self.assertEqual(self.patch.tr_line("stopped.", "fr"), "arrêté.")
        self.assertEqual(self.patch.tr_line("stopped.", "de"), "gestoppt.")
        self.assertEqual(self.patch.tr_line("stopped.", "zh"), "已停止。")
        self.assertEqual(self.patch.tr_line("stopped.", "yo"), "ó ti dúró.")

    def test_apply_i18n_idempotent_and_switchable(self):
        self.patch.apply_i18n("es")
        first = self.cli.AcpShell._emit
        self.patch.apply_i18n("es")
        # re-applying wraps the ORIGINAL again, not the wrapper
        self.assertIsNot(self.cli.AcpShell._emit, first)
        self.patch.apply_i18n("fr")
        self.assertEqual(self.patch.tr_line("stopped.", "fr"), "arrêté.")

    def test_build_parser_gains_lang_flag(self):
        self.patch.apply_i18n("en")
        ns = self.cli.build_parser().parse_args(
            ["--lang", "yo", "init", "--home", "/tmp/x", "--handle", "y"])
        self.assertEqual(ns.lang, "yo")

    def test_error_lines_translated(self):
        tr = self.patch.tr_line
        self.assertEqual(tr("ERROR FOO: boom", "es"), "ERROR FOO: boom")
        self.assertEqual(tr("ERROR FOO: boom", "fr"), "ERREUR FOO: boom")
        self.assertEqual(tr("interrupted", "de"), "unterbrochen")
        self.assertEqual(tr("sent (abc123)", "zh"), "已发送 (abc123)")
        self.assertEqual(tr("MSG from a1b2: hello", "yo"),
                         "Ìránṣẹ́ láti ọ̀dọ̀ a1b2: hello")

    def test_unknown_lines_pass_through(self):
        self.assertEqual(self.patch.tr_line("some random output", "es"),
                         "some random output")
        self.assertEqual(self.patch.tr_line("", "es"), "")

    def test_emit_wrapper_translates(self):
        import io
        self.patch.apply_i18n("es")
        shell = self.cli.AcpShell.__new__(self.cli.AcpShell)
        import threading
        shell._print_lock = threading.Lock()
        buf = io.StringIO()
        old = sys.stdout
        sys.stdout = buf
        try:
            shell._emit("stopped.")
        finally:
            sys.stdout = old
        self.assertEqual(buf.getvalue().strip(), "detenido.")


if __name__ == "__main__":
    unittest.main()
