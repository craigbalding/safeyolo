"""Exercise production feature resolution with real, entirely local Cargo crates."""

import importlib.util
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("rust_dependencies", Path(__file__).with_name("rust_dependencies.py"))
graph = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(graph)


class ProductionGraph(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="safeyolo-graph-control-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        environment = patch.dict(os.environ, {
            "CARGO_TARGET_DIR": str(graph.ROOT / "proxy/target"),
            "SAFEYOLO_CARGO_RESERVE_GIB": "10",
            "SAFEYOLO_CARGO_SPACE_POLL_SECONDS": "1",
        })
        environment.start()
        self.addCleanup(environment.stop)
        for name in ("shared", "leaf", "dev-leaf", "dev-only", "mac-only", "builder", "a", "product"):
            self.write(f"{name}/src/lib.rs", "pub fn present() {}\n")
            self.write(f"{name}/Cargo.toml", f'[package]\nname="{name}"\nversion="0.1.0"\nedition="2024"\n')
        self.append("shared/Cargo.toml", '[features]\nextra=["dep:leaf"]\ndev-extra=["dep:dev-leaf"]\n[dependencies]\nleaf={path="../leaf",optional=true}\ndev-leaf={path="../dev-leaf",optional=true}\n')
        self.append("a/Cargo.toml", '[dependencies]\nshared={path="../shared",features=["extra"]}\n')
        self.append("product/Cargo.toml", '[dependencies]\na={path="../a"}\nshared={path="../shared"}\n[build-dependencies]\nbuilder={path="../builder"}\n[dev-dependencies]\nshared={path="../shared",features=["dev-extra"]}\ndev-only={path="../dev-only"}\n[target.\'cfg(target_os = "macos")\'.dependencies]\nmac-only={path="../mac-only"}\n')
        self.write("product/build.rs", "fn main() {}\n")
        self.product = self.root / "product"
        graph.cargo(self.product, "generate-lockfile", "--offline")

    def write(self, name, text):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def append(self, name, text):
        with (self.root / name).open("a") as stream:
            stream.write(text)

    def test_production_excludes_dev_features_and_selects_platform_and_build_edges(self):
        linux = graph.resolve(self.product, "aarch64-unknown-linux-gnu", reasons=True)
        self.assertEqual(set(linux["packages"]), {"a@0.1.0", "shared@0.1.0", "leaf@0.1.0", "builder@0.1.0"})
        self.assertEqual(linux["packages"]["shared@0.1.0"]["features"], ["extra"])
        self.assertNotIn('feature "dev-extra"', linux["feature_reasons"])
        mac = graph.resolve(self.product, "aarch64-apple-darwin")
        self.assertEqual(set(mac["packages"]) - set(linux["packages"]), {"mac-only@0.1.0"})
        self.assertIn("builder", linux["direct"])

    def test_knockout_re_resolves_shared_features_without_changing_product_lock(self):
        original = (self.product / "Cargo.lock").read_bytes()
        before = graph.resolve(self.product, "aarch64-unknown-linux-gnu")
        after = graph.resolve(self.product, "aarch64-unknown-linux-gnu", "a")
        delta = graph.removal_delta(before, after)
        self.assertEqual(delta["removed"], ["a@0.1.0", "leaf@0.1.0"])
        self.assertEqual(delta["feature_changes"]["shared@0.1.0"]["after"], [])
        self.assertEqual((self.product / "Cargo.lock").read_bytes(), original)

    def test_resolution_failure_cannot_become_an_empty_successful_graph(self):
        self.append("product/Cargo.toml", '\n[dependencies.missing]\npath="../absent"\n')
        with self.assertRaises(subprocess.CalledProcessError):
            graph.resolve(self.product, "aarch64-unknown-linux-gnu")


if __name__ == "__main__":
    unittest.main()
