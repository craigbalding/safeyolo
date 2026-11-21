//! CPU fixture for the identical no_std client library; this is not VM proof.
use serde_json::{Value, json};
use std::io::{self, Write};

fn main() {
    let input = std::fs::read(std::env::args().nth(1).expect("request JSON path")).unwrap();
    let result = safeyolo_checker::network::check(
        &input,
        |call| {
            println!("{}", json!({"call":call}));
            io::stdout().flush().map_err(|e| e.to_string())?;
            let mut reply = String::new();
            io::stdin()
                .read_line(&mut reply)
                .map_err(|e| e.to_string())?;
            let reply: Value = serde_json::from_str(&reply).map_err(|e| e.to_string())?;
            if reply["ok"] != true {
                return Err(reply["error"]
                    .as_str()
                    .unwrap_or("fixture call failed")
                    .into());
            }
            Ok(reply["value"].clone())
        },
        || {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .ok()
                .map(|time| time.as_secs())
        },
    );
    let result = match result {
        Ok(value) => json!({"Ok":value}),
        Err(error) => json!({"Err":error}),
    };
    println!("{}", json!({"result":result}));
}
