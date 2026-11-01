"""Run with the frozen root development Python; the wheel test reads PyPI."""

import ast
import base64
import csv
import hashlib
import io
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import virtualenv
from filelock import FileLock, Timeout
from python_discovery._cache import DiskContentStore
from virtualenv.app_data import AppDataDiskFolder
from virtualenv.create.pyenv_cfg import PyEnvCfg
from virtualenv.seed.wheels.acquire import download_wheel, get_wheel
from virtualenv.seed.wheels.embed import get_embed_wheel
from virtualenv.util.lock import ReentrantFileLock


class HookDependencies(unittest.TestCase):
    def test_virtualenv_cache_lock_is_reentrant_and_exclusive(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cache = ReentrantFileLock(root)
            lock = FileLock(str(root / "wheel.lock"))
            with cache.lock_for_key("wheel"), cache.lock_for_key("wheel"):
                with self.assertRaises(Timeout):
                    lock.acquire(timeout=0)
            with lock.acquire(timeout=0):
                self.assertTrue(lock.is_locked)
            with cache.non_reentrant_lock_for_key("wheel"):
                with self.assertRaises(Timeout):
                    lock.acquire(timeout=0)

    def test_discovery_cache_lock_releases_after_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "cache"
            store = DiskContentStore(root, "python")
            lock = FileLock(str(root / "python.lock"))
            with self.assertRaisesRegex(RuntimeError, "abort cache write"):
                with store.locked():
                    store.write({"executable": sys.executable})
                    with self.assertRaises(Timeout):
                        lock.acquire(timeout=0)
                    raise RuntimeError("abort cache write")
            with lock.acquire(timeout=0):
                self.assertEqual(store.read(), {"executable": sys.executable})
            with store.locked():
                store.remove()
            self.assertFalse(store.exists())

    def activate(self, shell, script, root, command):
        options = {"bash": ["--noprofile", "--norc"], "fish": ["--no-config"], "zsh": ["-f"]}
        return subprocess.run(
            [shell, *options[shell], "-c", command],
            cwd=root,
            env=dict(os.environ, TEST_ACTIVATE=str(script), VIRTUAL_ENV_DISABLE_PROMPT=""),
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )

    def test_seeded_launchers_execute_destination_paths_literally(self):
        # GHSA-c978-59m8-c77v: execute the sh/Python wrapper, not just activation.
        names = (
            "space $(touch injected-dollar)`touch injected-backtick`",
            "x" * 140 + "$(touch${IFS}injected-dollar)`touch${IFS}injected-backtick`",
            "space 'quoted\" back\\slash",
        )
        for seeder in ("app-data", "pip"):
            for name in names:
                with self.subTest(seeder=seeder, name=name), tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    folder = root / name
                    session = virtualenv.cli_run([
                        "--no-download", "--no-periodic-update", "--seeder", seeder,
                        "--app-data", str(root / "app-data"), str(folder),
                    ])
                    markers = [root / "injected-dollar", root / "injected-backtick"]
                    self.assertFalse(any(marker.exists() for marker in markers))
                    launcher = folder / "bin/pip"
                    self.assertTrue(launcher.read_bytes().startswith(b"#!/bin/sh\n"))
                    result = subprocess.run(
                        [str(launcher), "--version"], cwd=root, capture_output=True,
                        text=True, timeout=20, check=False,
                    )
                    self.assertFalse(any(marker.exists() for marker in markers))
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn(f"from {folder}/", result.stdout)
                    if seeder == "pip":
                        # Rewriting a pip-seeded launcher must update its RECORD.
                        record = next(session.creator.purelib.glob("pip-*.dist-info/RECORD"))
                        with record.open(newline="") as stream:
                            row = next(row for row in csv.reader(stream) if row[0] == "../../../bin/pip")
                        content = launcher.read_bytes()
                        digest = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b"=").decode()
                        self.assertEqual(row[1:], [f"sha256={digest}", str(len(content))])

    @unittest.skipIf(os.getuid() == 0, "failed deletion must run as an ordinary user")
    def test_failed_symlink_deletion_preserves_external_target(self):
        # GHSA-43mp-35q3-x3fq: a read-only parent causes a real unlink failure.
        for clear in (False, True):
            for mode in (0o700, 0o500):
                with self.subTest(clear=clear, mode=oct(mode)), tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    target = root / "private-key"
                    target.write_bytes(b"private fixture")
                    target.chmod(0o400)
                    folder = root / "venv"
                    blocked = folder / "bin/python"
                    blocked.mkdir(parents=True)
                    (blocked / "entry").symlink_to(target)
                    blocked.chmod(mode)
                    args = ["--no-seed", "--no-periodic-update", str(folder)]
                    if clear:
                        args.insert(0, "--clear")
                    try:
                        if mode == 0o500:
                            with self.assertRaises(PermissionError):
                                virtualenv.cli_run(args)
                            self.assertTrue((blocked / "entry").is_symlink())
                        else:
                            virtualenv.cli_run(args)
                    finally:
                        if blocked.is_dir():
                            blocked.chmod(0o700)  # Restore only the owned fixture for cleanup.
                    self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o400)
                    self.assertEqual(target.read_bytes(), b"private fixture")

    def test_prepared_directory_links_do_not_redirect_creation(self):
        # GHSA-cw65-gx24-rc82: include both executable and library parents.
        library = f"lib/python{sys.version_info.major}.{sys.version_info.minor}/site-packages"
        for seeder in ("app-data", "pip"):
            for directory in ("bin", "lib", library):
                with self.subTest(seeder=seeder, directory=directory), tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    outside = root / "outside"
                    outside.mkdir(mode=0o750)
                    target = outside / ("activate" if directory == "bin" else "_virtualenv.py")
                    target.write_bytes(b"external fixture")
                    target.chmod(0o640)
                    folder = root / "venv"
                    link = folder / directory
                    link.parent.mkdir(parents=True)
                    link.symlink_to(outside, target_is_directory=True)
                    directory_mode = stat.S_IMODE(outside.stat().st_mode)
                    virtualenv.cli_run([
                        "--no-download", "--no-periodic-update", "--seeder", seeder,
                        "--app-data", str(root / "app-data"), str(folder),
                    ])
                    self.assertFalse(link.is_symlink())
                    self.assertTrue(link.resolve().is_relative_to(folder))
                    self.assertEqual(list(outside.iterdir()), [target])
                    self.assertEqual(target.read_bytes(), b"external fixture")
                    self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o640)
                    self.assertEqual(stat.S_IMODE(outside.stat().st_mode), directory_mode)

    def test_generated_files_replace_links_without_writing_external_targets(self):
        # GHSA-558c-9hv2-4prj: distinguish existing, dangling and hard-linked files.
        for relative in ("pyvenv.cfg", "bin/activate"):
            for kind in ("symlink", "dangling", "hardlink"):
                with self.subTest(file=relative, kind=kind), tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    target = root / "external"
                    if kind != "dangling":
                        target.write_bytes(b"external fixture")
                        target.chmod(0o640)
                    folder = root / "venv"
                    linked = folder / relative
                    linked.parent.mkdir(parents=True)
                    if kind == "hardlink":
                        os.link(target, linked)
                    else:
                        linked.symlink_to(target)
                    virtualenv.cli_run(["--no-seed", "--activators", "bash", str(folder)])
                    self.assertTrue(linked.is_file())
                    self.assertFalse(linked.is_symlink())
                    if kind == "dangling":
                        self.assertFalse(target.exists())
                    else:
                        self.assertEqual(target.read_bytes(), b"external fixture")
                        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o640)
                        self.assertFalse(linked.samefile(target))

    def test_warm_copy_seed_respects_current_umask(self):
        # GHSA-fc2g-4w5p-6whm: the second environment must not inherit cache modes.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            args = ["--no-download", "--no-periodic-update", "--app-data", str(root / "app-data")]
            previous = os.umask(0o022)
            try:
                virtualenv.cli_run([*args, str(root / "warm")])
                cached = next((root / "app-data").rglob("pip/__init__.py"))
                self.assertEqual(stat.S_IMODE(cached.stat().st_mode), 0o644)
                os.umask(0o077)
                session = virtualenv.cli_run([*args, str(root / "private")])
            finally:
                os.umask(previous)
            self.assertEqual(stat.S_IMODE((session.creator.purelib / "pip/__init__.py").stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(cached.stat().st_mode), 0o644)

    def test_seed_replacement_contains_metadata_deletion_paths(self):
        # GHSA-hhxq-47xx-j5xx: hostile RECORD/top_level entries cannot delete outside.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            folder = root / "venv"
            args = ["--no-download", "--no-periodic-update", "--app-data", str(root / "app-data"), str(folder)]
            session = virtualenv.cli_run(args)
            outside = root / "outside"
            outside.mkdir()
            target = outside / "keep"
            target.write_bytes(b"external fixture")
            target.chmod(0o640)
            (session.creator.purelib / "outside-link").symlink_to(outside, target_is_directory=True)
            metadata = next(session.creator.purelib.glob("pip-*.dist-info"))
            names = [str(target), os.path.relpath(target, session.creator.purelib), "outside-link/keep"]
            (metadata / "top_level.txt").write_text("\n".join(names) + "\n")
            (metadata / "RECORD").write_text("".join(f"{name},,\n" for name in [*names, "../..", "../../../bin/pip"]))
            virtualenv.cli_run(args)
            self.assertEqual(target.read_bytes(), b"external fixture")
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o640)
            self.assertTrue((session.creator.purelib / "pip/__init__.py").is_file())
            result = subprocess.run([str(folder / "bin/pip"), "--version"], capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_venv_creator_rejects_configuration_boundaries_before_writing(self):
        # GHSA-qmx5-4p3x-wvqf: exercise the stdlib creator, not the builtin writer.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for boundary in "\n\r\v\f\x1c\x1d\x1e\x85\u2028\u2029":
                with self.subTest(boundary=repr(boundary)):
                    folder = root / f"env{boundary}home = /attacker{boundary}include-system-site-packages = true"
                    with patch("sys.stderr", new_callable=io.StringIO) as error:
                        with self.assertRaises(SystemExit) as raised:
                            virtualenv.cli_run(["--creator", "venv", "--no-seed", str(folder)])
                    self.assertIn("must not contain a line boundary", error.getvalue())
                    self.assertEqual(raised.exception.code, 2)
                    self.assertEqual(list(root.iterdir()), [])
            session = virtualenv.cli_run(["--creator", "venv", "--no-seed", str(root / "ordinary path")])
            self.assertEqual(PyEnvCfg.from_folder(session.creator.dest)["include-system-site-packages"], "false")

    def test_xonsh_activation_literals_survive_legacy_decoding(self):
        # GHSA-394h-qwmc-48pf: use the upstream codec/literal boundary control.
        payload = "中'; __import__(\"os\").system(\"touch injected\"); #"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            virtualenv.cli_run([
                "--no-seed", "--activators", "xonsh", "--prompt", payload, str(root / "venv"),
            ])
            script = (root / "venv/bin/activate.xsh").read_bytes()
            for codec in ("utf-8", "gbk", "big5"):
                line = next(line for line in script.decode(codec).splitlines()
                            if line.strip().startswith("self.embedded_virtual_prompt ="))
                self.assertEqual(ast.literal_eval(line.partition(" = ")[2]), payload)
            self.assertFalse((root / "injected").exists())

    def test_bash_compat42_prompt_remains_literal(self):
        # GHSA-6w3r-xr62-4xcp: compatibility 4.2 uses different replacement semantics.
        payload = r"x\$(touch injected-dollar)\`touch injected-backtick`"
        for source in ("path", "prompt"):
            with self.subTest(source=source), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                folder = root / (payload if source == "path" else "venv")
                prompt = ["--prompt", payload] if source == "prompt" else []
                virtualenv.cli_run([
                    "--no-seed", "--activators", "bash", *prompt, str(folder),
                ])
                result = self.activate(
                    "bash", folder / "bin/activate", root,
                    'BASH_COMPAT=4.2; shopt -s promptvars; PS1="base> "; source "$TEST_ACTIVATE" || exit; '
                    'printf "%s\\n" "${PS1@P}"',
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.splitlines(), [f"({payload}) base> "])
                self.assertFalse((root / "injected-dollar").exists())
                self.assertFalse((root / "injected-backtick").exists())

    def test_placeholder_in_path_is_not_substituted_again(self):
        # GHSA-8rjx-v5ww-45pp: a later replacement must not rewrite quoted input.
        for shell, script in (("bash", "activate"), ("fish", "activate.fish")):
            with self.subTest(shell=shell):
                if not shutil.which(shell):
                    self.skipTest(f"{shell} is not installed")
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    folder = root / "A__VIRTUAL_NAME__B" / "x'$(touch injected)'y"
                    virtualenv.cli_run([
                        "--no-seed", "--no-periodic-update", "--activators", shell, str(folder),
                    ])
                    result = self.activate(
                        shell, folder / "bin" / script, root,
                        'source "$TEST_ACTIVATE" || exit; printf "%s\\n" "$VIRTUAL_ENV"',
                    )
                    self.assertFalse((root / "injected").exists())
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stdout.splitlines(), [str(folder)])

    @unittest.skipUnless(shutil.which("fish"), "fish is not installed")
    def test_fish_backslash_quote_is_literal_in_path_and_prompt(self):
        # GHSA-c947-3pg5-gm8q: fish interprets backslashes inside single quotes.
        payload = r"x\'$(touch injected)'\'"
        for source in ("path", "prompt"):
            with self.subTest(source=source), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                folder = root / (payload if source == "path" else "venv")
                prompt = ["--prompt", payload] if source == "prompt" else []
                virtualenv.cli_run([
                    "--no-seed", "--no-periodic-update", "--activators", "fish", *prompt, str(folder),
                ])
                result = self.activate(
                    "fish", folder / "bin/activate.fish", root,
                    'source "$TEST_ACTIVATE" || exit; printf "%s\\n" "$VIRTUAL_ENV" "$VIRTUAL_ENV_PROMPT"',
                )
                self.assertFalse((root / "injected").exists())
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.splitlines(), [str(folder), payload])

    @unittest.skipUnless(shutil.which("zsh"), "zsh is not installed")
    def test_zsh_prompt_substitution_does_not_execute_environment_name(self):
        # GHSA-5vjq-rrrf-7h2q: render PS1 with the option used by oh-my-zsh.
        payload = "x$(touch injected-dollar)`touch injected-backtick`%ny"
        for source in ("path", "prompt"):
            with self.subTest(source=source), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                folder = root / (payload if source == "path" else "venv")
                prompt = ["--prompt", payload] if source == "prompt" else []
                virtualenv.cli_run([
                    "--no-seed", "--no-periodic-update", "--activators", "bash", *prompt, str(folder),
                ])
                result = self.activate(
                    "zsh", folder / "bin/activate", root,
                    'setopt PROMPT_SUBST; PS1="base> "; source "$TEST_ACTIVATE" || exit; '
                    'print -r -- "$VIRTUAL_ENV"; print -rP -- "$PS1"',
                )
                self.assertFalse((root / "injected-dollar").exists())
                self.assertFalse((root / "injected-backtick").exists())
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.splitlines(), [str(folder), f"({payload}) base> "])

    def test_bash_prompt_two_pass_expansion_does_not_execute_environment_name(self):
        # GHSA-vxj4-q4g9-crj7: @P performs both prompt decoding and expansion.
        for payload in (r"x\$(touch injected)", r"x\`touch injected`"):
            for source in ("path", "prompt"):
                with self.subTest(payload=payload, source=source), tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    folder = root / (payload if source == "path" else "venv")
                    prompt = ["--prompt", payload] if source == "prompt" else []
                    virtualenv.cli_run([
                        "--no-seed", "--no-periodic-update", "--activators", "bash", *prompt, str(folder),
                    ])
                    result = self.activate(
                        "bash", folder / "bin/activate", root,
                        'shopt -s promptvars; PS1="base> "; source "$TEST_ACTIVATE" || exit; '
                        'printf "%s\\n" "$VIRTUAL_ENV" "${PS1@P}"',
                    )
                    self.assertFalse((root / "injected").exists())
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stdout.splitlines(), [str(folder), f"({payload}) base> "])

    def test_prompt_cannot_inject_configuration_lines(self):
        boundaries = "\n\r\v\f\x1c\x1d\x1e\x85\u2028\u2029"
        with tempfile.TemporaryDirectory() as temporary:
            for boundary in boundaries:
                with self.subTest(boundary=repr(boundary)):
                    folder = Path(temporary) / f"venv-{ord(boundary)}"
                    virtualenv.cli_run(
                        [
                            "--no-seed",
                            "--no-periodic-update",
                            "--prompt",
                            f'x"{boundary}home = /attacker{boundary}prompt = "z',
                            str(folder),
                        ]
                    )
                    lines = (folder / "pyvenv.cfg").read_text().splitlines()
                    self.assertEqual(sum(line.startswith("home =") for line in lines), 1)
                    self.assertNotEqual(PyEnvCfg.from_folder(folder)["home"], "/attacker")

    def test_relocated_bash_activation_does_not_execute_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            folder = root / "x'$(touch injected)'y"
            virtualenv.cli_run(["--no-seed", "--no-periodic-update", "--activators", "bash", str(folder)])
            moved = root / "moved"
            folder.rename(moved)
            result = subprocess.run(
                [
                    "bash",
                    "--noprofile",
                    "--norc",
                    "-c",
                    'source "$1" || exit; printf "%s\\n" "$VIRTUAL_ENV"',
                    "activation-test",
                    str(moved / "bin/activate"),
                ],
                cwd=root,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            self.assertFalse((root / "injected").exists())
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), str(moved))
            self.assertIn("does not exist", result.stderr)

    @unittest.skipUnless(shutil.which("fish"), "fish is not installed")
    def test_fish_activation_preserves_library_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            folder = root / "venv"
            session = virtualenv.cli_run(["--no-seed", "--no-periodic-update", "--activators", "fish", str(folder)])
            tcl_path = "/tcl/(touch injected)/lib path"
            tk_path = "/tk/'(touch injected-tk)'/lib"
            session.creator.interpreter.tcl_lib = tcl_path
            session.creator.interpreter.tk_lib = tk_path
            session.activators[0].generate(session.creator)
            result = subprocess.run(
                [
                    "fish",
                    "--no-config",
                    "-c",
                    'source $argv[1]; printf "%s\\n" "$TCL_LIBRARY" "$TK_LIBRARY"',
                    str(folder / "bin/activate.fish"),
                ],
                cwd=root,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            self.assertFalse((root / "injected").exists())
            self.assertFalse((root / "injected-tk").exists())
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.splitlines(), [tcl_path, tk_path])

    def test_downloaded_seed_wheel_is_checked_against_pypi(self):
        from virtualenv.seed.wheels.periodic_update import verify_wheel_digest

        project_root = Path(__file__).resolve().parents[3]
        lock = tomllib.loads((project_root / "tools/acceptance/uv.lock").read_text())
        pip_version = next(package["version"] for package in lock["package"] if package["name"] == "pip")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            env = dict(os.environ)
            # Exercise the default-index integrity path. Keep the configured proxy and CA.
            for name in ("PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL", "PIP_INDEX"):
                env.pop(name, None)
            wheel = download_wheel(
                "pip",
                f"=={pip_version}",
                f"{sys.version_info.major}.{sys.version_info.minor}",
                [],
                AppDataDiskFolder(str(root / "app-data")),
                root,
                env,
            )
            verify_wheel_digest(wheel)
            clean = wheel.path.read_bytes()
            wheel.path.write_bytes(wheel.path.read_bytes() + b"tampered")
            with self.assertRaisesRegex(RuntimeError, "sha256"):
                verify_wheel_digest(wheel)
            # GHSA-494p-63j8-28p3 / GHSA-cx28-75q4-x26q: fake only the external
            # downloader; use the real PyPI verifier and real pip-seeder selection.
            decoy = root / "decoy" / wheel.name
            decoy.parent.mkdir()
            decoy.write_bytes(clean)

            def corrupted_download(command, **kwargs):
                staging = Path(command[command.index("-d") + 1])
                (staging / wheel.name).write_bytes(clean + b"tampered")
                return Mock(returncode=0, communicate=lambda: (f"Saved {decoy}\n", ""))

            with patch("virtualenv.seed.wheels.acquire.Popen", side_effect=corrupted_download):
                house = root / "verified-house"
                with self.assertRaisesRegex(RuntimeError, "sha256"):
                    download_wheel(
                        "pip", f"=={pip_version}", f"{sys.version_info.major}.{sys.version_info.minor}",
                        [], AppDataDiskFolder(str(root / "download-data")), house, env,
                    )
                self.assertEqual(list(house.iterdir()), [])
                # The pip seeder must verify the downloaded input before installation.
                with patch.dict(os.environ, env, clear=True), self.assertRaisesRegex(RuntimeError, "sha256"):
                    virtualenv.cli_run([
                        "--seeder", "pip", "--download", "--no-periodic-update", "--pip", pip_version,
                        "--app-data", str(root / "pip-data"), str(root / "downloaded-venv"),
                    ])
                self.assertFalse(list((root / "pip-data").rglob(wheel.name)))
                with patch("virtualenv.seed.wheels.periodic_update._pypi_sha256_for_wheel", return_value=None), \
                        patch("virtualenv.seed.wheels.periodic_update.sleep"):
                    selected = get_wheel(
                        "pip", "bundle", f"{sys.version_info.major}.{sys.version_info.minor}", [], True,
                        AppDataDiskFolder(str(root / "fallback-data")), False, env,
                    )
                    self.assertEqual(
                        selected.name, get_embed_wheel("pip", f"{sys.version_info.major}.{sys.version_info.minor}").name,
                    )
                    self.assertFalse(list((root / "fallback-data").rglob(wheel.name)))


if __name__ == "__main__":
    unittest.main()
