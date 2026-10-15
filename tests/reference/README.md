# Python behavior references

These former Python modules are inputs to the retained unit, protocol and
black-box fixtures. SafeYolo does not install or stage this tree.
The source installer, bundles, guest shares and launchers use the
implementation. Python test drivers can read or construct test state;
that execution does not establish a SafeYolo operation.

`tests/conftest.py` and the test environment select this tree explicitly.
The existing tests keep their original `safeyolo` imports so the retained
schema, encrypted-vault, process-identity and Coord fixtures remain reusable.
The retired CLI entry and command modules are deleted. References retained
here are reached by schema, protocol, storage or test-state consumers. They do
not provide a product entry point. Command and installed-platform checks
remain under `proxy/tests`, `tests/proxy_contracts` and `tests/blackbox`.
