#!/usr/bin/env bash
# Install a verified host download with uv. Run as the host operator.
set -euo pipefail
package_dir=$(cd -- "$(dirname -- "$0")" && pwd)
python_requirement='@PYTHON_REQUIREMENT@'

uv run --no-project --python "$python_requirement" python "$package_dir/verify.py"
uv tool install --python "$python_requirement" --no-build \
  --constraints "$package_dir/dependencies.txt" --reinstall "$package_dir"/*.whl

if [[ -f "$package_dir/safeyolo-vm" ]]; then
  # Match vm/Makefile's existing installed helper and guest-tool locations.
  install_dir="$HOME/.safeyolo/bin"
  mkdir -p "$install_dir"
  install -m 0755 "$package_dir/safeyolo-vm" "$install_dir/safeyolo-vm"
  install -m 0755 "$package_dir/vsock-term" "$install_dir/vsock-term"
  install -m 0644 "$package_dir/safeyolo-vm.build-info.json" "$install_dir/safeyolo-vm.build-info.json"
  ditto "$package_dir/safeyolo-vm.dSYM" "$install_dir/safeyolo-vm.dSYM"
  profile=$(uv run --no-project --python "$python_requirement" python -c \
    'import json,sys; print(json.load(open(sys.argv[1]))["native"]["helper"]["profile"])' \
    "$package_dir/manifest.json")
  uv run --no-project --python "$python_requirement" python "$package_dir/build-info.py" \
    verify --profile "$profile" "$install_dir/safeyolo-vm"
fi

printf '%s\n' 'Host package installed. Run safeyolo --help; guest images and host runtime setup are separate.'
