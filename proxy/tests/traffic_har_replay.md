# Selected HAR replay check

The native replay test reconstructs each HTTP recipe from the owned byte and
timing inputs, then prints one complete HAR document per recipe.  Run the
checked-in standard-library comparator in `run` mode from the repository root.
Use Python 3.12 and the repository's Rust 1.94 toolchain, with Cargo dependencies
already cached for the offline check:

```sh
python3 \
  proxy/tests/compare_traffic_har_replay.py run \
  "$PWD" /tmp/traffic-har-replay.log
```

`run` invokes only the named offline, locked Cargo library test, captures combined
stdout and stderr in the supplied log, checks its exit status, and compares
the complete entry objects. It preserves an existing `CARGO_TARGET_DIR`; otherwise,
Cargo uses the checkout's default target directory. It rejects missing, extra, duplicate, malformed,
or misaligned records.  Python's standard JSON reader preserves escaped
surrogateescape values.  Every HTTP recipe must succeed; skips are rejected.
`timed_reused` is compared with the standalone reused-flow selection.  Use
`check` to compare an already captured log without rerunning the Rust test, and
`self-test` to verify the intentional mismatch and duplicate-record guards:

```sh
python3 \
  proxy/tests/compare_traffic_har_replay.py self-test
```
