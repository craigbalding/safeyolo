#!/usr/bin/env bash
# Disposable detector control. Run separately from product observation windows.
set -u
available=0
# env makes actual PATH exec attempts even when bash's PATH search finds nothing.
if env python3 -c 'pass'; then available=1; fi
if /usr/bin/python3 -c 'pass'; then available=1; fi
if /bin/sh -c 'exec /usr/bin/python3 -c "pass"'; then available=1; fi
echo "attempted Python: interpreter_available=$available" >&2
# An attempted-Python fixture must never return ordinary product success.
exit 97
