"""Run with the frozen root development Python; the wheel test reads PyPI."""

import os
import shutil
import subprocess
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path

import virtualenv
from virtualenv.app_data import AppDataDiskFolder
from virtualenv.create.pyenv_cfg import PyEnvCfg
from virtualenv.seed.wheels.acquire import download_wheel


class HookDependencies(unittest.TestCase):
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
            wheel.path.write_bytes(wheel.path.read_bytes() + b"tampered")
            with self.assertRaisesRegex(RuntimeError, "sha256"):
                verify_wheel_digest(wheel)


if __name__ == "__main__":
    unittest.main()
