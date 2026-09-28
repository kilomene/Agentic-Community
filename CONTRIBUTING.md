# Contributing to Agentic-Community

Everyone is welcome here. You don't need permission to contribute — fork
the repo, build, and open a pull request. Small fixes, new docs, new
transports, new platform SDKs: all in scope.

## Ground rules (non-negotiable)

1. **Python 3.8+ standard library ONLY.** No third-party packages, no
   paid services, no API keys. If your change needs a dependency, it
   doesn't belong here — find the stdlib way or leave it out.
2. **Protocol first, software second.** Behavior changes that alter the
   wire format MUST update `docs/PROTOCOL.md` and `docs/SCHEMA.md` in the
   same PR. The protocol spec is the source of truth.
3. **Tests or it didn't happen.** Every PR that changes behavior adds or
   updates tests under `tests/`. The bar: `python3 -m pytest tests/ -q`
   passes clean, including `tests/test_attack.py` (the attack suite must
   stay green — new attack surfaces need new attack tests).
4. **Crypto is sacred.** Changes to `packages/acp_crypto` must pass the
   RFC test vectors (`tests/test_crypto.py`) and keep timing-attack
   discipline. Long term we migrate to libsodium; see
   `docs/SECURITY.md`.
5. **No real-money rails, no credential handling.** Marketplace payments
   stay bookkeeping-only (`NullAdapter`) until the community designs a
   proper payment-adapter protocol extension. Never accept passwords, API
   keys, or tokens in issues or PRs.

## Getting started

```bash
git clone https://github.com/kilomene/Agentic-Community.git
cd Agentic-Community
python3 -m pytest tests/ -q        # everything green before you start
python3 apps/acp_cli/cli.py init --home /tmp/acp-a --handle alice
python3 apps/acp_cli/cli.py init --home /tmp/acp-b --handle bob
# pair, message, call: see README quick start
```

## How to contribute

- **Bugs:** open an issue with reproduction steps (template provided).
  A failing test in `tests/` is worth a thousand words.
- **Features:** open an issue first for anything that changes the
  protocol or adds a message kind — protocol changes need review by
  maintainers before code.
- **PRs:** keep them focused, one concern per PR. Update the docs that
  describe your feature. Keep commit messages plain and descriptive.
- **Translations:** add your language to the `--lang` set. Copy an
  existing language file, translate every string, and add a test that
  asserts no key is missing.

## Security issues

Do NOT open a public issue for vulnerabilities. Open a **private
security advisory** on GitHub (Security → Advisories) with a
proof-of-concept. We will credit you in `docs/SECURITY.md`.

## Code of conduct

Be decent. Assume good faith, review the code not the person, and don't
ship anyone's private data. Maintainers can remove contributions that
harass or dox.
