#!/bin/bash -eu

# Build script for ClusterFuzzLite
# Builds Atheris fuzz targets for SafeYolo

cd $SRC/safeyolo

# Package each fuzzer with pyinstaller
for fuzzer in fuzz/*_fuzzer.py; do
    fuzzer_basename=$(basename -s .py $fuzzer)
    fuzzer_package=${fuzzer_basename}.pkg

    # Create standalone package with all addon dependencies
    pyinstaller --distpath $OUT --onefile --name $fuzzer_package \
        --paths addons \
        --hidden-import yaml \
        --hidden-import yarl \
        --hidden-import multidict \
        --hidden-import idna \
        --hidden-import pydantic \
        --collect-all mitmproxy \
        --collect-all pydantic \
        $fuzzer

    # Create wrapper script (no LD_PRELOAD needed for pure Python)
    cat > $OUT/$fuzzer_basename << EOF
#!/bin/sh
# LLVMFuzzerTestOneInput for fuzzer detection.
this_dir=\$(dirname "\$0")
chmod +x \$this_dir/$fuzzer_package
\$this_dir/$fuzzer_package \$@
EOF
    chmod +x $OUT/$fuzzer_basename
done
