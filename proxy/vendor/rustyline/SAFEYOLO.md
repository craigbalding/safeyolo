# Rustyline 18.0.1

Source: the MIT-licensed crates.io `rustyline` 18.0.1 package.

The Unix reader checks its buffered input before selecting terminal and
external-printer file descriptors. Without this check, pasted or quickly typed
input stops until another terminal input edge arrives. The installed Coord
PTY test exercises typing, cursor movement and send while a message arrives.

The second key uses checked access under the existing length guard. This
preserves behavior and permits compilation with `custom-bindings` disabled:
that configuration uses a one-element array, whose unreachable index otherwise
fails Rust's `unconditional_panic` check when built as a local dependency.

The remaining library source is unchanged. Examples and unrelated upstream
guides are omitted, with their example targets removed from the manifest.
Default features are disabled; SafeYolo
does not write a second chat transcript or file history.
