# Native host packages

Use [native installation](native-policy.md#install-and-start) for the current
fresh-state product. Public release publication is stopped. Existing published
wheel archives belong to the earlier Python CLI and are not inputs to the
native install/start journey.

Choose a prepared bundle for your host (linux-amd64, linux-arm64 or darwin-arm64)
and selected source. A production bundle contains release Rust executables;
a debug bundle contains dev executables. The macOS helper is signed and retains
its matching profile: the development helper additionally has the
get-task-allow entitlement for authorized debugging.

Verify a transferred archive against its supplied SHA-256 before extraction.
The unpacked install.sh invokes the same native installer used by source
install.sh. It verifies package-info, internal SHA256SUMS, native executable
identity, matching host/guest source and profile, runtime compatibility and
macOS helper signature/identity. It installs into a root with no existing
instance configuration, then initializes trust, tokens and state internally.
There is no wheel, venv, uv-tool replacement or old-state conversion.

[Build inputs and layout](native-policy.md#build-a-native-bundle) describe the
three host executables, Linux guest helpers/receipts, private tmux and libraries,
boot/host scripts, skills, launchers and services. Platform rootfs/images are
separate prepared inputs. package-info records full source, profile, platform
and the actual minimum glibc or macOS version; it is the runtime requirement,
not an inferred wheel tag. Read installed --version and native status to
attribute a run, and retain separate guest/platform observations.

Publication and promotion remain an operator-owned stopped outcome. Source
integration and focused installer results do not publish packages or accept
the final installed platform suites.
