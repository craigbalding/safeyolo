"""Exercise the guest hook with real pip and lock-derived package artifacts."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tomllib
import urllib.request
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
HOOK = ROOT / 'tests/blackbox/prepare-guest-tests.sh'
REQUIREMENTS = HOOK.with_name('guest-requirements.txt')


def test_guest_requirements_match_frozen_export():
    result = subprocess.run([
        'uv', 'export', '--frozen', '--only-group', 'guest-tests', '--no-emit-workspace',
        '--format', 'requirements-txt', '--no-header',
    ], cwd=ROOT, capture_output=True, text=True, check=True, timeout=30)
    expected = [line.strip() for line in result.stdout.splitlines() if line.strip() and not line.lstrip().startswith('#')]
    actual = [line.strip() for line in REQUIREMENTS.read_text().splitlines() if line.strip() and not line.lstrip().startswith('#')]
    assert actual == expected


def _venv(path, interpreter):
    # Reuse the development environment's virtualenv, including its offline pip seed.
    subprocess.run([
        sys.executable, '-m', 'virtualenv', '--no-download', '--no-periodic-update',
        '--python', str(interpreter), str(path),
    ], capture_output=True, text=True, check=True, timeout=30)
    return path / 'bin/python3'


@pytest.fixture(scope='module')
def guest_package_artifacts(tmp_path_factory):
    """Download the maintained pure-Python wheels once, through the configured proxy."""
    root = tmp_path_factory.mktemp('guest-package-artifacts')
    python = _venv(root / 'downloader', sys.executable)
    wheels = root / 'wheels'
    # Acquire both interpreter variants even when the test host runs Python 3.13.
    # The actual installation below still uses the unchanged exported markers.
    all_variants = root / 'all-variants.txt'
    records = []
    for line in REQUIREMENTS.read_text().replace('\\\n', '').splitlines():
        if line.strip() and not line.lstrip().startswith('#'):
            requirement, *hashes = line.split(' --hash=')
            records.append(' --hash='.join([requirement.split(';')[0].strip(), *hashes]))
    all_variants.write_text('\n'.join(records) + '\n')
    subprocess.run([
        str(python), '-m', 'pip', 'download', '--require-hashes', '-r', str(all_variants),
        '--only-binary=:all:', '--dest', str(wheels), '--no-cache-dir',
        '--disable-pip-version-check', '--retries', '0', '--timeout', '15',
    ], capture_output=True, text=True, check=True, timeout=120)
    # Keep one real source archive as a refusal input. Hash failure must occur
    # before pip starts a build or asks for build dependencies.
    lock = tomllib.loads((ROOT / 'uv.lock').read_text())
    archive = next(p['sdist'] for p in lock['package'] if p['name'] == 'pytest-timeout')
    source = root / archive['url'].rsplit('/', 1)[1]
    with urllib.request.urlopen(archive['url'], timeout=30) as response:
        source.write_bytes(response.read())
    assert 'sha256:' + hashlib.sha256(source.read_bytes()).hexdigest() == archive['hash']
    return wheels, source


@pytest.mark.parametrize('python_version', ['3.12', '3.13'])
@pytest.mark.parametrize('failure', [None, 'wheel', 'source', 'missing-hash', 'missing-all-hashes'])
def test_guest_hook_installs_locked_packages_and_refuses_unverified_bytes(
    tmp_path, guest_package_artifacts, python_version, failure
):
    interpreter = shutil.which(f'python{python_version}')
    if interpreter is None:
        pytest.skip(f'Python {python_version} is not installed')
    python = _venv(tmp_path / 'guest', interpreter)
    wheels, source = guest_package_artifacts
    local_wheels = tmp_path / 'artifacts'
    shutil.copytree(wheels, local_wheels)
    if failure == 'wheel':
        wheel = next(local_wheels.glob('httpx-*.whl'))
        wheel.write_bytes(wheel.read_bytes() + b'changed bytes')
    elif failure == 'source':
        next(local_wheels.glob('pytest_timeout-*.whl')).unlink()
        (local_wheels / source.name).write_bytes(source.read_bytes() + b'changed bytes')
    hook = tmp_path / HOOK.name
    shutil.copyfile(HOOK, hook)
    requirements = REQUIREMENTS.read_text()
    if failure in ('missing-hash', 'missing-all-hashes'):
        requirements = '\n'.join(
            line.split(' --hash=')[0].rstrip()
            if failure == 'missing-all-hashes' or line.startswith('h11==') else line
            for line in requirements.replace('\\\n', '').splitlines()
        ) + '\n'
    hook.with_name(REQUIREMENTS.name).write_text(requirements)
    environment = dict(os.environ, PATH=f'{python.parent}:{os.environ["PATH"]}',
                       PIP_NO_INDEX='1', PIP_FIND_LINKS=str(local_wheels), PIP_NO_CACHE_DIR='1',
                       PIP_DISABLE_PIP_VERSION_CHECK='1', PIP_CONFIG_FILE=os.devnull)
    for name in ('PYTHONPATH', 'PIP_TARGET', 'PIP_PREFIX', 'PIP_REQUIREMENT', 'PIP_CONSTRAINT'):
        environment.pop(name, None)
    result = subprocess.run(['/bin/bash', str(hook)], env=environment,
                            capture_output=True, text=True, timeout=60)
    if failure:
        assert result.returncode != 0, result.stdout
        message = 'do not match the hashes' if failure in ('wheel', 'source') else 'hashes are required'
        assert message in result.stderr.lower(), result.stderr
        subprocess.run([str(python), '-c',
                        "import importlib.util; assert importlib.util.find_spec('pytest') is None"],
                       env=environment, check=True, timeout=10)
    else:
        assert result.returncode == 0, result.stderr
        installed = subprocess.check_output([
            str(python), '-c', 'import importlib.metadata as m, json; '
            'print(json.dumps({p.metadata["Name"].lower().replace("_", "-"): p.version for p in m.distributions()}))',
        ], env=environment, text=True, timeout=10)
        packages = json.loads(installed)
        assert {'pytest', 'httpx', 'pytest-timeout', 'anyio', 'h11'} <= packages.keys()
        assert ('typing-extensions' in packages) == (python_version == '3.12')
        assert 'colorama' not in packages
        # A warm guest can prepare again without changing the interpreter or imports.
        subprocess.run(['/bin/bash', str(hook)], env=environment,
                       capture_output=True, text=True, check=True, timeout=60)
