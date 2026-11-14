//! Display host elevation from the invocation that will actually execute.

use std::{
    ffi::OsStr,
    io::{self, Write},
    process::Command,
};

fn quote(argument: &OsStr) -> String {
    if let Some(text) = argument.to_str()
        && !text.chars().any(char::is_control)
    {
        return crate::host_lifecycle::shell_quote(text);
    }
    // Bash byte escapes preserve non-UTF-8 paths and keep terminal controls
    // visible. This text is for disclosure only; execution always uses Command.
    let bytes = argument
        .as_encoded_bytes()
        .iter()
        .map(|byte| format!("\\x{byte:02x}"))
        .collect::<String>();
    format!("$'{bytes}'")
}

pub(crate) fn display(command: &Command) -> String {
    std::iter::once(command.get_program())
        .chain(command.get_args())
        .map(quote)
        .collect::<Vec<_>>()
        .join(" ")
}

pub(crate) fn preview(command: &Command, purpose: &str) -> io::Result<()> {
    let mut stderr = io::stderr().lock();
    writeln!(stderr, "Host command: {}\n  {purpose}", display(command))?;
    stderr.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::ffi::OsStrExt;

    #[test]
    fn preview_round_trips_arguments_without_running_them() {
        let arguments = [
            OsStr::new(""),
            OsStr::new("a 'quote' $(touch forbidden); & *"),
            OsStr::new("line\nnext\u{1b}"),
            OsStr::from_bytes(b"non-utf8-\xff"),
        ];
        let mut command = Command::new("sudo");
        command.args(arguments);
        let printed = display(&command);
        let decoded = Command::new("bash")
            .args(["-c", &format!("set -- {printed}; printf '%s\\0' \"$@\"")])
            .output()
            .unwrap();
        assert!(decoded.status.success());
        let expected = std::iter::once(OsStr::new("sudo"))
            .chain(arguments)
            .flat_map(|argument| argument.as_bytes().iter().copied().chain([0]))
            .collect::<Vec<_>>();
        assert_eq!(decoded.stdout, expected);
        assert!(!printed.contains('\n') && !printed.contains('\u{1b}'));
    }
}
