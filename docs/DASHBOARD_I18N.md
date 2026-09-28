# Dashboard + CLI internationalization (V2)

This doc covers the two i18n pieces shipped in V2: the `acp_i18n` package
(6 locales) and the `i18n_patch` shim that translates the CLI without
touching `cli.py`.

## `packages/acp_i18n`

Pure-stdlib string catalog, no gettext dependency.

- `catalogs.py` — `STRINGS`: dict of `{key: {locale: text}}` for locales
  `en es fr de zh yo` (English, Spanish, French, German, Chinese,
  Yoruba). 133 keys covering: nav labels, section titles, buttons,
  table headers, status/presence words, error messages (`err_*`),
  empty-states, the token unlock box, and the pair dialog.
- `__init__.py` — public API:
  - `t(key, lang="en")` — translate; falls back `lang → en → key`.
    Never raises, never returns empty.
  - `available_langs()` — `["en", "es", "fr", "de", "zh", "yo"]`.

Every key is present in every locale and no string is empty — enforced
by `tests/test_i18n.py::CatalogTests`.

### Adding a string

1. Add the `en` text plus all 5 translations to `STRINGS` in
   `catalogs.py` (all six, no exceptions — the catalog test fails
   otherwise).
2. Use it via `t("my_key", lang)` in `apps/acp_dashboard` (server or
   `ui.py`).

## Dashboard language selection

- `Dashboard(..., lang="en")` sets the default language.
- `GET /?lang=<code>` re-renders the page in that language and sets an
  `acp_lang` cookie (valid code required, else ignored).
- API error strings (`err_unauthorized`, `err_not_found`, …) are
  translated per request: `?lang=` wins, then the `acp_lang` cookie,
  then the dashboard default.
- `ui.py::render_page(lang)` builds the page with a server-injected
  `STR` dict, so the UI works with JavaScript disabled for the initial
  render and needs no external assets.

## `apps/acp_cli/i18n_patch.py` — CLI translation without editing `cli.py`

`cli.py` is frozen; `i18n_patch.py` translates its user-facing output by
monkey-patching at runtime. It never modifies `cli.py` on disk.

Run it exactly like the CLI, with an extra `--lang` flag **before** the
subcommand:

```bash
python3 apps/acp_cli/i18n_patch.py --lang es serve --home ~/.acp --port 9000
python3 apps/acp_cli/i18n_patch.py --lang yo init --home ~/.acp --handle me
python3 apps/acp_cli/i18n_patch.py --help   # --lang listed first
```

`--lang` accepts only `available_langs()`; anything else is rejected by
argparse with the valid choices.

### How it works

1. `apply_i18n(lang)` wraps (idempotently — always from the pristine
   originals, so switching languages re-wraps cleanly):
   - `cli.build_parser` — adds the `--lang` flag to the existing parser.
   - `AcpShell._emit` — translates each emitted line before printing.
   - `cli.init_home` / `cli.serve_home` / `cli.main` — installs a
     streaming `builtins.print` interceptor so translated `print()`
     output still flows through the REPL instead of bypassing it.
2. `tr_line(line, lang)` translates one line via ordered regex patterns
   (`_PATTERNS`): each pattern captures the dynamic parts (paths,
   handles, counts, ids) and rebuilds the line from catalog fragments,
   so values are never mistranslated.
3. Lines that match no pattern pass through **in English, unchanged**.
   This is deliberate: an untranslated line is honest; a guessed
   translation could corrupt a path or id.

### Coverage honesty

`_PATTERNS` covers the CLI's stable status/error/section lines
(identity created/loaded, serving, peer/presence/message/file/project
lines, common errors). New or reworded `print()` calls in `cli.py`
fall back to English automatically — check `i18n_patch._PATTERNS` when
adding CLI output and extend it with a capture-group pattern plus
catalog fragments.

### Tests

`tests/test_i18n.py`:

- `CatalogTests` (8 tests) — 6 locales × 133 keys all present, no
  empty strings, fallback chain (`xx` → en → key), all dashboard/UI
  keys referenced by `ui.py`/`server.py` exist.
- `PatchTests` (6 tests) — `--lang` flag appears with valid choices and
  parses; `_emit` translates known lines; error lines translate;
  unknown lines pass through in English; `apply_i18n` is idempotent
  and language-switchable. The patch is fully reverted after each test
  (pristine `cli` functions restored via `staticmethod` so the
  descriptor protocol can't bind them to the test instance).
