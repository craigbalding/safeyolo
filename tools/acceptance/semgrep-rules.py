import subprocess
import tempfile

import httpx
import yaml

# ruleid: safeyolo-production-tls-verification-disabled
httpx.get("https://example.invalid", verify=False)

# ok: safeyolo-production-tls-verification-disabled
httpx.get("https://example.invalid", verify="/trusted/ca.pem")

# ruleid: safeyolo-production-shell-true
subprocess.run("echo unsafe", shell=True)

# ok: safeyolo-production-shell-true
subprocess.run(["echo", "safe"], check=True)

# ruleid: safeyolo-unsafe-tempfile-name
tempfile.mktemp()

# ok: safeyolo-unsafe-tempfile-name
tempfile.mkstemp()

# ruleid: safeyolo-unsafe-yaml-load
yaml.load("unsafe: input")

# ok: safeyolo-unsafe-yaml-load
yaml.safe_load("plain: data")
