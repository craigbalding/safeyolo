fn main() {
    #[cfg(unix)]
    if let Some(result) =
        safeyolo_host_executor::endpoints::command(&std::env::args().skip(1).collect::<Vec<_>>())
    {
        if let Err(error) = result {
            eprintln!("{error}");
            std::process::exit(1);
        }
        return;
    }
    #[cfg(windows)]
    if let Some(result) =
        safeyolo_host_executor::windows::command(std::env::args().skip(1).collect())
    {
        if let Err(error) = result {
            eprintln!("{error}");
            std::process::exit(1);
        }
        return;
    }
    if let Err(error) = safeyolo_host_executor::server::command(std::env::args().skip(1).collect())
    {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
