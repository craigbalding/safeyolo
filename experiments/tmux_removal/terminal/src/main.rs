//! Standalone feasibility probe, not a production session implementation.
use serde_json::{Value, json};
use std::{collections::VecDeque, error::Error, num::NonZeroU16, path::PathBuf};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{UnixListener, UnixStream},
    sync::mpsc,
};

type Result<T> = std::result::Result<T, Box<dyn Error>>;
const HISTORY: usize = 200;

#[derive(Default)]
struct Queries {
    replies: Vec<u8>,
    answered: usize,
    unhandled: VecDeque<String>,
}
impl vt100::Callbacks for Queries {
    fn unhandled_csi(
        &mut self,
        screen: &mut vt100::Screen,
        i1: Option<u8>,
        i2: Option<u8>,
        params: &[&[u16]],
        c: char,
    ) {
        if i1.is_none() && i2.is_none() && params == [&[6_u16][..]] && c == 'n' {
            let (row, col) = screen.cursor_position();
            self.replies
                .extend_from_slice(format!("\x1b[{};{}R", row + 1, col + 1).as_bytes());
            self.answered += 1;
        } else {
            self.unhandled
                .push_back(format!("CSI {i1:?} {i2:?} {params:?} {c}"));
            if self.unhandled.len() > HISTORY {
                self.unhandled.pop_front();
            }
        }
    }
    fn unhandled_osc(&mut self, _: &mut vt100::Screen, params: &[&[u8]]) {
        // Retain only the command number, never a clipboard/title payload.
        let command = params
            .first()
            .map(|p| String::from_utf8_lossy(p).to_string());
        self.unhandled.push_back(format!("OSC {command:?}"));
        if self.unhandled.len() > HISTORY {
            self.unhandled.pop_front();
        }
    }
}

struct Command {
    client: usize,
    request: Value,
    reply: mpsc::Sender<Value>,
}

async fn client(stream: UnixStream, id: usize, commands: mpsc::Sender<Command>) -> Result<()> {
    let (read, mut write) = stream.into_split();
    let (reply, mut output) = mpsc::channel::<Value>(16);
    let writer = tokio::spawn(async move {
        while let Some(value) = output.recv().await {
            write
                .write_all(serde_json::to_string(&value)?.as_bytes())
                .await?;
            write.write_all(b"\n").await?;
        }
        Ok::<_, Box<dyn Error + Send + Sync>>(())
    });
    let mut lines = BufReader::new(read).lines();
    while let Some(line) = lines.next_line().await? {
        let request = serde_json::from_str(&line)?;
        commands
            .send(Command {
                client: id,
                request,
                reply: reply.clone(),
            })
            .await?;
    }
    commands
        .send(Command {
            client: id,
            request: json!({"op":"detach"}),
            reply,
        })
        .await?;
    writer.abort();
    Ok(())
}

fn snapshot(
    parser: &vt100::Parser<Queries>,
    pid: u32,
    session: &str,
    exit: Option<i32>,
    bytes: usize,
    viewers: usize,
) -> Value {
    let screen = parser.screen();
    let (rows, cols) = screen.size();
    json!({"pid":pid,"session":session,"exit":exit,"bytes":bytes,"viewers":viewers,
        "rows":rows,"cols":cols,"alternate":screen.alternate_screen(),
        "contents":screen.contents(),"screen":screen.state_formatted(),
        "scrollback":screen.scrollback_len(),"history_bound":HISTORY,
        "queries_answered":parser.callbacks().answered,"unhandled":parser.callbacks().unhandled})
}

fn dimension(request: &Value, field: &str) -> Result<NonZeroU16> {
    let value = u16::try_from(request[field].as_u64().ok_or("missing dimension")?)?;
    NonZeroU16::new(value).ok_or("zero dimension".into())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    let socket = PathBuf::from(
        args.next()
            .ok_or("usage: tmux-removal-poc SOCKET ROWS COLS PROGRAM [ARGS...]")?,
    );
    if socket == std::path::Path::new("--replay") {
        use std::io::Read;
        let mut source = String::new();
        std::io::stdin().read_to_string(&mut source)?;
        let frame: Value = serde_json::from_str(&source)?;
        let mut display =
            vt100::Parser::new(dimension(&frame, "rows")?, dimension(&frame, "cols")?, 0);
        display.process(frame["screen"].as_str().ok_or("missing screen")?.as_bytes());
        println!(
            "{}",
            json!({"contents":display.screen().contents(),"cursor":display.screen().cursor_position()})
        );
        return Ok(());
    }
    let rows: NonZeroU16 = args
        .next()
        .ok_or("missing rows")?
        .to_str()
        .ok_or("rows not UTF-8")?
        .parse()?;
    let cols: NonZeroU16 = args
        .next()
        .ok_or("missing cols")?
        .to_str()
        .ok_or("cols not UTF-8")?
        .parse()?;
    let program = args.next().ok_or("missing program")?;
    // The caller creates a private, owned directory. Refuse an existing socket.
    let listener = UnixListener::bind(&socket)?;
    let (pty, pts) = pty_process::open()?;
    pty.resize(pty_process::Size::new(rows.get(), cols.get()))?;
    let mut child = pty_process::Command::new(program)
        .args(args)
        .env("TERM", "xterm-256color")
        .kill_on_drop(true)
        .spawn(pts)?;
    let pid = child.id().ok_or("child PID unavailable")?;
    let session = format!(
        "{pid}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    );
    let (mut read, mut write) = pty.into_split();
    let mut parser = vt100::Parser::new_with_callbacks(rows, cols, HISTORY, Queries::default());
    let (commands, mut requests) = mpsc::channel::<Command>(64);
    let mut viewers: Vec<(usize, mpsc::Sender<Value>)> = Vec::new();
    let mut client_id = 0;
    let mut buffer = [0; 16384];
    let mut bytes = 0;
    let mut eof = false;
    let mut exit = None;
    println!("{}", json!({"pid":pid,"session":session,"socket":socket}));
    let result: Result<()> = async {
        loop {
            tokio::select! {
                incoming = listener.accept() => {
                    let (stream, _) = incoming?;
                    client_id += 1;
                    let commands = commands.clone();
                    tokio::spawn(async move {
                        if let Err(error) = client(stream, client_id, commands).await { eprintln!("viewer: {error}"); }
                    });
                },
                output = read.read(&mut buffer), if !eof => {
                    match output {
                        Ok(0) => eof = true,
                        Err(error) if error.raw_os_error() == Some(5) => eof = true, // Linux PTY EOF is EIO.
                        Err(error) => return Err(error.into()),
                        Ok(count) => {
                            bytes += count;
                            parser.process(&buffer[..count]);
                            let replies = std::mem::take(&mut parser.callbacks_mut().replies);
                            if !replies.is_empty() { write.write_all(&replies).await?; }
                            // Render state rather than forwarding queries to viewers. A
                            // real terminal must not issue a second reply to the child.
                            let frame = snapshot(&parser, pid, &session, exit, bytes, viewers.len());
                            viewers.retain(|(_, viewer)| viewer.try_send(frame.clone()).is_ok());
                        }
                    }
                },
                status = child.wait(), if exit.is_none() => {
                    let status = status?;
                    use std::os::unix::process::ExitStatusExt;
                    exit = Some(status.code().unwrap_or_else(|| 128 + status.signal().unwrap_or(0)));
                    let frame = snapshot(&parser, pid, &session, exit, bytes, viewers.len());
                    viewers.retain(|(_, viewer)| viewer.try_send(frame.clone()).is_ok());
                },
                Some(command) = requests.recv() => {
                    let mut answer = None;
                    match command.request["op"].as_str().ok_or("missing operation")? {
                        "state" => {},
                        "attach" => { viewers.push((command.client, command.reply.clone())); },
                        "detach" => { viewers.retain(|(id, _)| *id != command.client); continue; },
                        "input" => { write.write_all(command.request["text"].as_str().ok_or("missing input")?.as_bytes()).await?; },
                        "resize" => {
                            let rows = dimension(&command.request, "rows")?;
                            let cols = dimension(&command.request, "cols")?;
                            write.resize(pty_process::Size::new(rows.get(), cols.get()))?;
                            parser.set_size(rows, cols);
                        },
                        "history" => {
                            let mut screen = parser.screen().clone();
                            let cols = screen.size().1;
                            let lines: Vec<_> = (1..=screen.scrollback_len()).rev().map(|offset| {
                                screen.set_scrollback(offset);
                                screen.rows(0, cols.get()).next().unwrap_or_default()
                            }).collect();
                            answer = Some(json!({"history":lines,"history_bound":HISTORY}));
                        },
                        "quit" => break,
                        _ => return Err("unknown probe operation".into()),
                    }
                    let answer = answer.unwrap_or_else(|| snapshot(&parser, pid, &session, exit, bytes, viewers.len()));
                    let _ = command.reply.try_send(answer);
                }
            }
        }
        Ok(())
    }.await;
    if exit.is_none() {
        child.kill().await?;
    }
    std::fs::remove_file(socket)?;
    result
}
