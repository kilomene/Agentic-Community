"""acp_sdk.examples: runnable end-to-end demos of the SDK.

Every script here:

* takes ``--home`` / ``--passphrase`` style argparse flags,
* spins up real local agents (and a real local directory server where
  needed), so nothing external is required,
* runs with ``python3 -m acp_sdk.examples.<name>`` or directly.

They double as integration smoke tests: if an example prints its
final ``OK`` line, that feature works end to end.
"""
