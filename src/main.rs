// jfs — JFSecure's command line. A thin client of the RUNNING, unlocked app: one JSON
// request over a local pipe, one JSON answer (the app side is src/cli.rs). It never
// opens vault files and never sees the vault password. Every value needs your OK in
// the app (once, or for 15 min in this terminal).
use serde_json::{json, Map, Value};
use std::io::{BufRead, BufReader, Write};
use std::process::ExitCode;

const HELP: &str = "jfs — JFSecure from the command line (the app must be running and unlocked)

  jfs get <secret>/<key>      print a value (a template is filled in)
  jfs copy <secret>/<key>     put it into the clipboard, print nothing
  jfs totp <name>             print the current 2FA code
  jfs run <secret> -- <command…>
                              run a command with every key of the secret as an
                              environment variable ($db-password → DB_PASSWORD; jfs ls
                              <secret> shows each name); exits with the command's exit
                              code. Output going to a pipe or a file (not a terminal)
                              has every value masked: [JFSecure: NAME]
  jfs render <template> [-o <file>]
                              fill a file's {{Secret:key}} / {{totp:Name}} in (e.g. a
                              .env from .env.tpl) — into <file>, or printed
  jfs ls [secret|folder]      list secrets and 2FA names, or a secret's keys
  jfs git-credential get      git's credential helper: the login of the secret whose
                              $url is on that host ($user + $token or $password).
                              Set it up: git config --global credential.helper
                              \"!jfs git-credential\" (git never writes into the vault)
  jfs status                  is JFSecure running and unlocked?
  jfs palette                 open the search palette (for a desktop shortcut)
  jfs mcp                     an MCP server for AI agents (Claude Code: claude mcp add
                              --scope user jfsecure -- jfs mcp); values stay out of
                              the agent's sight

  <secret> may include its folder: work/github/token
  -a, --answer name=value     answer a template's {{?name}} question (repeatable)
  -n                          no new line after the value
  -o, --output <file>         jfs render: write here (only you can read it)
  --stdin <key>               jfs run: also write that key's value to the command's
                              stdin — exactly the value, no new line added (a
                              password for docker login --password-stdin, ssh …)
  --no-mask                   jfs run: don't mask the output (the window says so)

Each value asks for your OK in JFSecure: once, or for 15 minutes in this terminal.
Exit codes: 0 ok · 1 error · 2 usage · 3 not running / locked · 4 denied · 5 not PRO
(jfs run: the command's own exit code once it ran)";

const PROTOCOL: u64 = 1;

struct Args {
    cmd: String,
    path: String,
    answers: Map<String, Value>,
    no_newline: bool,
    // jfs run: everything after "--", untouched
    command: Vec<String>,
    // jfs render -o
    output: Option<String>,
    // jfs run --stdin <key>, --no-mask
    stdin: Option<String>,
    no_mask: bool,
}

fn parse(argv: &[String]) -> Result<Args, String> {
    let mut rest = argv.iter();
    let cmd = rest.next().cloned().unwrap_or_else(|| "help".into());
    let mut args = Args { cmd, path: String::new(), answers: Map::new(), no_newline: false, command: Vec::new(), output: None, stdin: None, no_mask: false };
    while let Some(a) = rest.next() {
        match a.as_str() {
            "--" => {
                args.command = rest.by_ref().cloned().collect();
                break;
            }
            "-n" => args.no_newline = true,
            "-o" | "--output" => args.output = Some(rest.next().ok_or("--output needs a file")?.clone()),
            "--stdin" => args.stdin = Some(rest.next().ok_or("--stdin needs a key")?.clone()),
            "--no-mask" => args.no_mask = true,
            "-a" | "--answer" => {
                let kv = rest.next().ok_or("--answer needs name=value")?;
                let (k, v) = kv.split_once('=').ok_or("--answer needs name=value")?;
                args.answers.insert(k.trim().to_string(), json!(v));
            }
            s if s.starts_with('-') => return Err(format!("unknown option {s}")),
            s if args.path.is_empty() => args.path = s.to_string(),
            s => return Err(format!("unexpected {s}")),
        }
    }
    if (args.stdin.is_some() || args.no_mask) && args.cmd != "run" {
        return Err("--stdin and --no-mask are for jfs run".into());
    }
    Ok(args)
}

// $db-password → DB_PASSWORD: the variable a key becomes (src/utils/cli.js envName, the same rule)
// Cyrillic → Latin ($пароль → PAROL); anything else outside A-Z0-9 is "_"
fn env_name(key: &str) -> String {
    let name: String = key.trim().to_uppercase().chars().map(|c| match translit(c) {
        Some(latin) => latin.to_string(),
        None if c.is_ascii_alphanumeric() || c == '_' => c.to_string(),
        None => "_".to_string(),
    }).collect();
    if name.starts_with(|c: char| c.is_ascii_digit()) { format!("_{name}") } else { name }
}

fn translit(c: char) -> Option<&'static str> {
    Some(match c {
        'А' => "A", 'Б' => "B", 'В' => "V", 'Г' => "G", 'Д' => "D", 'Е' => "E", 'Ё' => "YO", 'Ж' => "ZH",
        'З' => "Z", 'И' => "I", 'Й' => "Y", 'К' => "K", 'Л' => "L", 'М' => "M", 'Н' => "N", 'О' => "O",
        'П' => "P", 'Р' => "R", 'С' => "S", 'Т' => "T", 'У' => "U", 'Ф' => "F", 'Х' => "KH", 'Ц' => "TS",
        'Ч' => "CH", 'Ш' => "SH", 'Щ' => "SHCH", 'Ъ' => "", 'Ы' => "Y", 'Ь' => "", 'Э' => "E", 'Ю' => "YU",
        'Я' => "YA", 'І' => "I", 'Ї' => "YI", 'Є' => "YE", 'Ґ' => "G", 'Ў' => "U",
        _ => return None,
    })
}

// the value --stdin names, by its key (wg-admin) or its variable (WG_ADMIN)
fn stdin_value<'a>(vars: &'a [(String, String)], key: &str) -> Result<&'a str, String> {
    let wanted = env_name(key);
    vars.iter().find(|(name, _)| *name == wanted).map(|(_, v)| v.as_str()).ok_or_else(|| {
        let names: Vec<&str> = vars.iter().map(|(n, _)| n.as_str()).collect();
        format!("--stdin {key}: the secret has no such key (variables: {})", names.join(", "))
    })
}

// what the approval window shows for a run: the command, where stdin comes from, whether
// the output is masked — an approval covers exactly that (cli.rs grant_scope)
fn shown_run(command: &[String], stdin: Option<&str>, masked: bool) -> String {
    let mut shown = mcp::shown_command(command);
    if let Some(key) = stdin {
        shown.push_str(&format!(" < ${}", env_name(key)));
    }
    if !masked {
        shown.push_str("   (output NOT masked)");
    }
    shown
}

// every value (and each longer line of a multi-line value) → [JFSecure: NAME]; longest
// first so a value containing another is masked whole
fn redact(out: &str, vars: &[(String, String)]) -> String {
    let mut pieces: Vec<(String, &str)> = Vec::new();
    for (name, value) in vars {
        let v = value.trim();
        if v.chars().count() >= 4 {
            pieces.push((v.to_string(), name));
        }
        if value.contains('\n') {
            pieces.extend(value.lines().map(str::trim).filter(|l| l.chars().count() >= 8).map(|l| (l.to_string(), name.as_str())));
        }
    }
    pieces.sort_by_key(|(v, _)| std::cmp::Reverse(v.len()));
    let mut out = out.to_string();
    for (v, name) in pieces {
        out = out.replace(&v, &format!("[JFSecure: {name}]"));
    }
    out
}

// the app's pipe: per OS user (src/cli.rs pipe_name, the same rule)
#[cfg(windows)]
fn pipe_name() -> String {
    if cfg!(debug_assertions) {
        if let Ok(name) = std::env::var("JFSECURE_CLI_PIPE") {
            return format!(r"\\.\pipe\{name}");
        }
    }
    let user: String = std::env::var("USERNAME").unwrap_or_default().chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_').collect();
    format!(r"\\.\pipe\jfsecure-cli-{user}")
}

// None: JFSecure isn't running (no pipe)
#[cfg(windows)]
fn ask(req: &Value) -> Result<Option<Value>, String> {
    const ERROR_FILE_NOT_FOUND: i32 = 2;
    const ERROR_PIPE_BUSY: i32 = 231;
    let name = pipe_name();
    let mut pipe = None;
    // busy = another jfs is being answered right now; the app opens a new instance at once
    for _ in 0..100 {
        match std::fs::OpenOptions::new().read(true).write(true).open(&name) {
            Ok(p) => {
                pipe = Some(p);
                break;
            }
            Err(e) if e.raw_os_error() == Some(ERROR_FILE_NOT_FOUND) => return Ok(None),
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) => std::thread::sleep(std::time::Duration::from_millis(50)),
            Err(e) => return Err(e.to_string()),
        }
    }
    let mut pipe = pipe.ok_or("JFSecure is busy — try again")?;
    let_app_come_forward(&pipe);
    pipe.write_all(format!("{req}\n").as_bytes()).map_err(|e| e.to_string())?;
    let mut line = String::new();
    BufReader::new(pipe).read_line(&mut line).map_err(|e| e.to_string())?;
    serde_json::from_str(&line).map(Some).map_err(|_| "no answer from JFSecure".to_string())
}

// the app's socket (src/cli.rs socket_path, the same rule)
#[cfg(unix)]
fn socket_path() -> std::path::PathBuf {
    if cfg!(debug_assertions) {
        if let Ok(p) = std::env::var("JFSECURE_CLI_PIPE") {
            return p.into();
        }
    }
    let home = std::path::PathBuf::from(std::env::var("HOME").unwrap_or_default());
    let base = if cfg!(target_os = "macos") {
        home.join("Library/Application Support")
    } else {
        std::env::var("XDG_CONFIG_HOME").ok().filter(|d| !d.is_empty()).map(Into::into).unwrap_or_else(|| home.join(".config"))
    };
    base.join("JFSecure/cli/jfs.sock")
}

// None: JFSecure isn't running (no socket, or nobody listening on it)
#[cfg(unix)]
fn ask(req: &Value) -> Result<Option<Value>, String> {
    use std::io::ErrorKind;
    let mut sock = match std::os::unix::net::UnixStream::connect(socket_path()) {
        Ok(s) => s,
        Err(e) if matches!(e.kind(), ErrorKind::NotFound | ErrorKind::ConnectionRefused) => return Ok(None),
        Err(e) => return Err(e.to_string()),
    };
    sock.write_all(format!("{req}\n").as_bytes()).map_err(|e| e.to_string())?;
    let mut line = String::new();
    BufReader::new(sock).read_line(&mut line).map_err(|e| e.to_string())?;
    serde_json::from_str(&line).map(Some).map_err(|_| "no answer from JFSecure".to_string())
}

// Windows won't let a background app put its window in front (it could steal typing).
// The terminal IS in front, and a program it started may hand that right on: the app's
// approval window then opens in front, with the keyboard.
#[cfg(windows)]
fn let_app_come_forward(pipe: &std::fs::File) {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::System::Pipes::GetNamedPipeServerProcessId;
    use windows_sys::Win32::UI::WindowsAndMessaging::AllowSetForegroundWindow;
    let mut pid = 0u32;
    unsafe {
        if GetNamedPipeServerProcessId(pipe.as_raw_handle() as _, &mut pid) != 0 {
            AllowSetForegroundWindow(pid);
        }
    }
}

#[cfg(not(any(windows, unix)))]
fn ask(_req: &Value) -> Result<Option<Value>, String> {
    Err("jfs isn't available on this system".into())
}

fn exit_code(code: &str) -> u8 {
    match code {
        "usage" => 2,
        "locked" => 3,
        "denied" => 4,
        "pro" => 5,
        _ => 1,
    }
}

// one request → the app's successful answer, or (exit code, why)
fn request(req: &Value) -> Result<Value, (u8, String)> {
    match ask(req) {
        Ok(Some(a)) if a["ok"] == json!(true) => Ok(a),
        Ok(Some(a)) => Err((exit_code(a["code"].as_str().unwrap_or_default()), a["error"].as_str().unwrap_or("failed").to_string())),
        Ok(None) => Err((3, "JFSecure isn't running — start it and log in".into())),
        Err(e) => Err((1, e)),
    }
}

// a template for jfs render (the app reads at most 512 KB per request)
const MAX_TEMPLATE: u64 = 400 * 1024;

fn read_template(path: &str) -> Result<String, String> {
    if std::fs::metadata(path).map_err(|e| format!("{path}: {e}"))?.len() > MAX_TEMPLATE {
        return Err(format!("{path} is larger than 400 KB"));
    }
    std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))
}

// the absolute path, for the approval window (the file need not exist yet)
fn shown_path(path: &str) -> String {
    let p = std::path::Path::new(path);
    if p.is_absolute() { path.to_string() } else { std::env::current_dir().map(|d| d.join(p).display().to_string()).unwrap_or_else(|_| path.to_string()) }
}

// a file only this user can read (a filled-in .env holds secrets)
fn write_private(path: &str, text: &str) -> std::io::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options.open(path)?.write_all(text.as_bytes())
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if argv.first().map(String::as_str) == Some("git-credential") {
        return git_credential(argv.get(1).map(String::as_str).unwrap_or_default());
    }
    let args = match parse(&argv) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("jfs: {e}\n\n{HELP}");
            return ExitCode::from(2);
        }
    };
    let mut req = json!({"v": PROTOCOL, "cmd": args.cmd, "path": args.path, "answers": args.answers, "command": args.command.join(" ")});
    match args.cmd.as_str() {
        "help" | "-h" | "--help" => {
            println!("{HELP}");
            return ExitCode::SUCCESS;
        }
        "-V" | "--version" | "version" => {
            println!("jfs {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        "mcp" => return mcp::serve(),
        "status" | "ls" | "get" | "copy" | "totp" | "palette" => {}
        "run" if args.command.is_empty() => {
            eprintln!("jfs: jfs run <secret> -- <command…>\n\n{HELP}");
            return ExitCode::from(2);
        }
        "run" => req["command"] = json!(shown_run(&args.command, args.stdin.as_deref(), !args.no_mask)),
        "render" if args.path.is_empty() => {
            eprintln!("jfs: jfs render <template> [-o <file>]\n\n{HELP}");
            return ExitCode::from(2);
        }
        "render" => match read_template(&args.path) {
            Ok(text) => {
                req["text"] = json!(text);
                req["path"] = json!("");
                req["output"] = json!(args.output.as_deref().map(shown_path).unwrap_or_default());
            }
            Err(e) => {
                eprintln!("jfs: {e}");
                return ExitCode::from(1);
            }
        },
        other => {
            eprintln!("jfs: unknown command {other}\n\n{HELP}");
            return ExitCode::from(2);
        }
    }
    let answer = match request(&req) {
        Ok(a) => a,
        Err((code, e)) => {
            eprintln!("jfs: {e}");
            return ExitCode::from(code);
        }
    };
    match args.cmd.as_str() {
        "render" => {
            let text = answer["text"].as_str().unwrap_or_default();
            match &args.output {
                Some(out) => {
                    if let Err(e) = write_private(out, text) {
                        eprintln!("jfs: {out}: {e}");
                        return ExitCode::from(1);
                    }
                    let names: Vec<&str> = answer["names"].as_array().into_iter().flatten().filter_map(Value::as_str).collect();
                    eprintln!("wrote {out} — filled in {}", names.join(", "));
                }
                None => print!("{text}"),
            }
        }
        "status" => {
            let unlocked = answer["unlocked"] == json!(true);
            println!("JFSecure {} is running · {} · plan {}", answer["version"].as_str().unwrap_or("?"),
                if unlocked { "unlocked" } else { "locked" }, answer["plan"].as_str().unwrap_or("?"));
            if !unlocked {
                return ExitCode::from(3);
            }
        }
        "ls" => {
            for line in answer["lines"].as_array().into_iter().flatten() {
                println!("{}", line.as_str().unwrap_or_default());
            }
        }
        "copy" => eprintln!("copied"),
        "run" => {
            let vars: Vec<(String, String)> = answer["vars"].as_object().into_iter().flatten()
                .map(|(k, v)| (k.clone(), v.as_str().unwrap_or_default().to_string())).collect();
            let input = match args.stdin.as_deref().map(|k| stdin_value(&vars, k)).transpose() {
                Ok(i) => i,
                Err(e) => {
                    eprintln!("jfs: {e}");
                    return ExitCode::from(2);
                }
            };
            return run(&args.command, &vars, input, !args.no_mask);
        }
        _ => {
            let value = answer["value"].as_str().unwrap_or_default();
            let mut out = std::io::stdout();
            let _ = if args.no_newline { write!(out, "{value}") } else { writeln!(out, "{value}") };
        }
    }
    ExitCode::SUCCESS
}

// git's credential helper (git config --global credential.helper "!jfs git-credential"). git asks with
// `get` and key=value lines on stdin (protocol, host, path, username); the answer is username= / password=
// of the secret whose $url is on that host — after your OK in JFSecure, like jfs get. `store` / `erase` are
// ignored: git never writes into the vault. Whatever can't be served prints nothing — git then asks the next
// helper, or you — and says why on stderr. Always exit 0: a failing helper only makes git noisier.
fn git_credential(op: &str) -> ExitCode {
    if op != "get" {
        return ExitCode::SUCCESS;
    }
    let mut input = String::new();
    for line in std::io::stdin().lock().lines().map_while(Result::ok) {
        if line.is_empty() {
            break;
        }
        input.push_str(&line);
        input.push('\n');
    }
    let fields = credential_fields(&input);
    let field = |k: &str| fields.get(k).cloned().unwrap_or_default();
    if field("host").is_empty() {
        eprintln!("jfs: git gave no host");
        return ExitCode::SUCCESS;
    }
    let req = json!({"v": PROTOCOL, "cmd": "git", "host": field("host"), "username": field("username"), "protocol": field("protocol")});
    match request(&req) {
        Ok(a) => {
            let user = a["username"].as_str().unwrap_or_default();
            let pass = a["password"].as_str().unwrap_or_default();
            if user.contains('\n') || pass.contains('\n') || pass.is_empty() {
                eprintln!("jfs: that login has a line break or no password — git can't take it");
            } else {
                print!("username={user}\npassword={pass}\n");
            }
        }
        Err((_, e)) => eprintln!("jfs: {e}"),
    }
    ExitCode::SUCCESS
}

// "host=github.com\nusername=octo\n" → {host: github.com, username: octo}; the first of each key wins
fn credential_fields(input: &str) -> std::collections::HashMap<String, String> {
    let mut fields = std::collections::HashMap::new();
    for line in input.lines() {
        if let Some((k, v)) = line.split_once('=') {
            fields.entry(k.trim().to_string()).or_insert_with(|| v.to_string());
        }
    }
    fields
}

// the command with the service's keys added to its environment; its exit code is ours.
// Windows finds only .exe by name: a .cmd / .bat (npm, yarn…) goes through cmd /C.
// Output that goes to a terminal is the user's own screen and passes untouched (prompts,
// colors); to a pipe or a file — a script, an AI agent — it is masked line by line.
fn run(command: &[String], vars: &[(String, String)], input: Option<&str>, mask: bool) -> ExitCode {
    use std::io::IsTerminal;
    use std::process::{Command, Stdio};
    let mask_out = mask && !std::io::stdout().is_terminal();
    let mask_err = mask && !std::io::stderr().is_terminal();
    let start = |program: &str, args: &[String]| {
        let mut c = Command::new(program);
        c.args(args).envs(vars.iter().cloned());
        if input.is_some() {
            c.stdin(Stdio::piped());
        }
        if mask_out {
            c.stdout(Stdio::piped());
        }
        if mask_err {
            c.stderr(Stdio::piped());
        }
        c.spawn()
    };
    let mut child = start(&command[0], &command[1..]);
    if cfg!(windows) && matches!(&child, Err(e) if e.kind() == std::io::ErrorKind::NotFound) {
        let mut via_cmd = vec!["/C".to_string()];
        via_cmd.extend(command.iter().cloned());
        child = start("cmd", &via_cmd);
    }
    let mut child = match child {
        Ok(c) => c,
        Err(e) => {
            eprintln!("jfs: can't run {}: {e}", command[0]);
            return ExitCode::from(1);
        }
    };
    if let (Some(text), Some(mut pipe)) = (input, child.stdin.take()) {
        let text = text.to_string();
        // the pipe is dropped afterwards = the end of the input
        std::thread::spawn(move || {
            let _ = pipe.write_all(text.as_bytes());
        });
    }
    let pumps = [
        child.stdout.take().map(|p| masked_copy(p, vars.to_vec(), false)),
        child.stderr.take().map(|p| masked_copy(p, vars.to_vec(), true)),
    ];
    let status = child.wait();
    for p in pumps.into_iter().flatten() {
        let _ = p.join();
    }
    match status {
        Ok(s) => ExitCode::from(s.code().map(|c| c.clamp(0, 255) as u8).unwrap_or(1)),
        Err(e) => {
            eprintln!("jfs: {}: {e}", command[0]);
            ExitCode::from(1)
        }
    }
}

// copies a child's output to ours line by line, every value masked; a line that isn't text
// (binary output) passes as it is — a value is text, it can't be in there whole
fn masked_copy(from: impl std::io::Read + Send + 'static, vars: Vec<(String, String)>, to_stderr: bool) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let mut from = BufReader::new(from);
        let mut line = Vec::new();
        loop {
            line.clear();
            match from.read_until(b'\n', &mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
            let out = match std::str::from_utf8(&line) {
                Ok(text) => redact(text, &vars).into_bytes(),
                Err(_) => line.clone(),
            };
            let written = if to_stderr {
                let mut e = std::io::stderr().lock();
                e.write_all(&out).and_then(|_| e.flush())
            } else {
                let mut o = std::io::stdout().lock();
                o.write_all(&out).and_then(|_| o.flush())
            };
            if written.is_err() {
                break;
            }
        }
    })
}

// `jfs mcp`: an MCP server (JSON-RPC 2.0, one message per line on stdin / stdout) for AI
// agents such as Claude Code. The rule: useful to the agent, never harmful to the user.
//   - no tool hands a value to the agent: run_with_secrets puts them into a command's
//     environment (its output comes back with every value masked), render_template into a
//     file (the agent gets the names only); list_secrets is names only, like `jfs ls`;
//   - every use goes through the app's approval window like `jfs` — the agent's grant covers
//     only that secret with that exact command / file (src-tauri/src/cli.rs grant_scope);
//     `keys` narrows a run to the keys it needs;
//   - it works with whatever vault is OPEN in the app; it never takes the vault password.
mod mcp {
    use super::*;
    use std::io::Read;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    const VERSIONS: &[&str] = &["2025-06-18", "2025-03-26", "2024-11-05"];
    const MAX_OUTPUT: usize = 100 * 1024;
    const DEFAULT_TIMEOUT: u64 = 120;
    const MAX_TIMEOUT: u64 = 600;

    const INSTRUCTIONS: &str = "JFSecure is the user's local password manager. Use it to work WITH secrets without seeing them: \
run_with_secrets runs a command with a secret's keys as environment variables; render_template writes a file (e.g. .env) with \
{{Secret:key}} references filled in. Values never come back to you — outputs are masked. Every use asks the user in a JFSecure \
window; if it is denied or the vault is locked, tell the user and don't retry in a loop. Never ask the user to paste a secret \
into the chat. SSH keys listed by list_secrets need no tool: run ssh / git / scp as usual — JFSecure is their SSH agent and \
asks the user itself.";

    fn tools() -> Value {
        json!([
            {
                "name": "list_secrets",
                "description": "Names only (never values): every secret (folder/name), 2FA code and SSH key (name + fingerprint) of the vault open in JFSecure; or one secret's keys, each with the environment variable it becomes in run_with_secrets; or the secrets in a folder.",
                "inputSchema": {"type": "object", "properties": {
                    "path": {"type": "string", "description": "optional: a secret (\"work/github\") to list its keys, or a folder"}
                }},
                "annotations": {"readOnlyHint": true}
            },
            {
                "name": "run_with_secrets",
                "description": "Run a command with the $key:value lines of a JFSecure secret as environment variables (named like the key in upper case: $db-password → DB_PASSWORD, $token → TOKEN; list_secrets shows them) — all of them, or only `keys`. Not needed for ssh / git with a JFSecure SSH key: run those directly. The user approves it in JFSecure, seeing the exact command. The command is NOT run by a shell: to use a variable in an argument start a shell yourself, e.g. [\"bash\", \"-c\", \"curl -s -H \\\"Authorization: Bearer $TOKEN\\\" https://api.github.com/user\"] (Windows: [\"powershell\", \"-NoProfile\", \"-Command\", \"... $env:TOKEN ...\"]). stdout / stderr come back with every value replaced by [JFSecure: NAME] — don't try to print or exfiltrate values.",
                "inputSchema": {"type": "object", "required": ["secret", "command"], "properties": {
                    "secret": {"type": "string", "description": "the secret's name, with its folder if the name is used twice (\"work/github\")"},
                    "command": {"type": "array", "items": {"type": "string"}, "minItems": 1, "description": "the program and its arguments"},
                    "cwd": {"type": "string", "description": "working directory (default: this server's)"},
                    "answers": {"type": "object", "additionalProperties": {"type": "string"}, "description": "answers to {{?question}} templates in the values"},
                    "keys": {"type": "array", "items": {"type": "string"}, "description": "optional: only these keys (or variable names) become variables — pass the ones the command needs"},
                    "stdin": {"type": "string", "description": "optional: a key of the secret (or its variable name) whose value is written to the command's stdin — exactly the value, no new line added. For programs that read a password from stdin (docker login --password-stdin, a script run over ssh) instead of piping a variable through a shell"},
                    "timeout_seconds": {"type": "integer", "minimum": 1, "maximum": MAX_TIMEOUT}
                }}
            },
            {
                "name": "render_template",
                "description": "Write a file from a template, filling in {{Secret:key}}, {{folder/Secret:key}} and {{totp:Name}} from JFSecure (anything else in {{ }} stays as written). The user approves it, seeing the names and the output path. You get the names filled in, never the content — don't read the written file back into the conversation. Use absolute paths.",
                "inputSchema": {"type": "object", "required": ["template", "output"], "properties": {
                    "template": {"type": "string", "description": "path of the template file, e.g. /project/.env.tpl"},
                    "output": {"type": "string", "description": "path of the file to write, e.g. /project/.env (only the user can read it)"},
                    "answers": {"type": "object", "additionalProperties": {"type": "string"}}
                }}
            }
        ])
    }

    fn text(t: impl Into<String>, error: bool) -> Value {
        json!({"content": [{"type": "text", "text": t.into()}], "isError": error})
    }

    fn base(cmd: &str, path: &str, answers: &Value) -> Value {
        json!({"v": PROTOCOL, "cmd": cmd, "path": path, "answers": if answers.is_object() { answers.clone() } else { json!({}) }})
    }

    fn call(params: &Value) -> Value {
        let a = &params["arguments"];
        let s = |k: &str| a[k].as_str().unwrap_or_default().to_string();
        match params["name"].as_str().unwrap_or_default() {
            "list_secrets" => match request(&base("ls", &s("path"), &Value::Null)) {
                Ok(r) => text(r["lines"].as_array().into_iter().flatten().filter_map(Value::as_str).collect::<Vec<_>>().join("\n"), false),
                Err((_, e)) => text(e, true),
            },
            "run_with_secrets" => {
                let command: Vec<String> = a["command"].as_array().into_iter().flatten().filter_map(|x| x.as_str().map(String::from)).collect();
                if s("secret").trim().is_empty() || command.is_empty() {
                    return text("secret and command are required", true);
                }
                let mut req = base("run", &s("secret"), &a["answers"]);
                let stdin_key = a["stdin"].as_str().filter(|k| !k.trim().is_empty());
                let keys = only_keys(&a["keys"], stdin_key);
                req["keys"] = json!(keys);
                req["command"] = json!(shown_run(&command, stdin_key, true));
                let mut vars: Vec<(String, String)> = match request(&req) {
                    Ok(r) => r["vars"].as_object().into_iter().flatten().map(|(k, v)| (k.clone(), v.as_str().unwrap_or_default().to_string())).collect(),
                    Err((_, e)) => return text(e, true),
                };
                // an app before `keys` sends every key: keep the asked ones only
                if !keys.is_empty() {
                    vars.retain(|(name, _)| keys.iter().any(|k| env_name(k) == *name));
                }
                let input = match stdin_key.map(|k| stdin_value(&vars, k)).transpose() {
                    Ok(i) => i,
                    Err(e) => return text(e, true),
                };
                let timeout = a["timeout_seconds"].as_u64().unwrap_or(DEFAULT_TIMEOUT).clamp(1, MAX_TIMEOUT);
                let cwd = a["cwd"].as_str();
                match run_captured(&command, &vars, input, cwd, Duration::from_secs(timeout)) {
                    Ok(r) => {
                        let head = match (r.code, r.timed_out) {
                            (_, true) => format!("stopped after {timeout} s"),
                            (Some(c), _) => format!("exit code {c}"),
                            (None, _) => "ended without an exit code".into(),
                        };
                        let names: Vec<&str> = vars.iter().map(|(k, _)| k.as_str()).collect();
                        let body = format!("{head}\nvariables set: {}\n--- stdout ---\n{}\n--- stderr ---\n{}",
                            names.join(", "), redact(&r.stdout, &vars), redact(&r.stderr, &vars));
                        text(body, r.timed_out || r.code != Some(0))
                    }
                    Err(e) => text(e, true),
                }
            }
            "render_template" => {
                let (template, output) = (s("template"), s("output"));
                if template.is_empty() || output.is_empty() {
                    return text("template and output are required", true);
                }
                if std::fs::canonicalize(&template).ok().is_some_and(|t| std::fs::canonicalize(&output).ok() == Some(t)) {
                    return text("output must not be the template itself", true);
                }
                let content = match read_template(&template) {
                    Ok(c) => c,
                    Err(e) => return text(e, true),
                };
                let mut req = base("render", "", &a["answers"]);
                req["text"] = json!(content);
                req["output"] = json!(shown_path(&output));
                match request(&req) {
                    Ok(r) => match write_private(&output, r["text"].as_str().unwrap_or_default()) {
                        Ok(()) => {
                            let names: Vec<&str> = r["names"].as_array().into_iter().flatten().filter_map(Value::as_str).collect();
                            text(format!("Wrote {output} — filled in: {}. The values are in that file only; don't print it.", names.join(", ")), false)
                        }
                        Err(e) => text(format!("{output}: {e}"), true),
                    },
                    Err((_, e)) => text(e, true),
                }
            }
            other => text(format!("unknown tool {other}"), true),
        }
    }

    // the keys asked for (+ the one stdin reads, so it is there); none = every key
    pub fn only_keys(keys: &Value, stdin_key: Option<&str>) -> Vec<String> {
        let mut out: Vec<String> = keys.as_array().into_iter().flatten().filter_map(Value::as_str).map(str::trim).filter(|k| !k.is_empty()).map(String::from).collect();
        if let (false, Some(k)) = (out.is_empty(), stdin_key) {
            if !out.iter().any(|o| env_name(o) == env_name(k)) {
                out.push(k.trim().to_string());
            }
        }
        out
    }

    // what the approval window shows: the arguments, quoted where they hold spaces
    pub fn shown_command(command: &[String]) -> String {
        command.iter().map(|c| if c.is_empty() || c.contains([' ', '"', '\'']) { format!("\"{}\"", c.replace('"', "\\\"")) } else { c.clone() }).collect::<Vec<_>>().join(" ")
    }

    pub struct Ran {
        pub code: Option<i32>,
        pub timed_out: bool,
        pub stdout: String,
        pub stderr: String,
    }

    // the command with the variables, its output captured (capped), stopped at the timeout.
    // Windows: a .cmd / .bat (npm…) through cmd /C, like `jfs run`; no console window pops up.
    pub fn run_captured(command: &[String], vars: &[(String, String)], input: Option<&str>, cwd: Option<&str>, timeout: Duration) -> Result<Ran, String> {
        let spawn = |program: &str, args: &[String]| {
            let mut c = Command::new(program);
            c.args(args).envs(vars.iter().cloned()).stdin(if input.is_some() { Stdio::piped() } else { Stdio::null() }).stdout(Stdio::piped()).stderr(Stdio::piped());
            if let Some(d) = cwd.filter(|d| !d.is_empty()) {
                c.current_dir(d);
            }
            #[cfg(windows)]
            std::os::windows::process::CommandExt::creation_flags(&mut c, 0x0800_0000); // CREATE_NO_WINDOW
            c.spawn()
        };
        let mut child = spawn(&command[0], &command[1..]);
        if cfg!(windows) && matches!(&child, Err(e) if e.kind() == std::io::ErrorKind::NotFound) {
            let mut via_cmd = vec!["/C".to_string()];
            via_cmd.extend(command.iter().cloned());
            child = spawn("cmd", &via_cmd);
        }
        let mut child = child.map_err(|e| format!("can't run {}: {e}", command[0]))?;
        if let (Some(text), Some(mut pipe)) = (input, child.stdin.take()) {
            let text = text.to_string();
            std::thread::spawn(move || {
                let _ = pipe.write_all(text.as_bytes());
            });
        }
        let read = |pipe: Option<Box<dyn Read + Send>>| {
            std::thread::spawn(move || {
                let mut all = Vec::new();
                if let Some(mut p) = pipe {
                    let mut buf = [0u8; 8192];
                    while let Ok(n) = p.read(&mut buf) {
                        if n == 0 {
                            break;
                        }
                        if all.len() < MAX_OUTPUT {
                            all.extend_from_slice(&buf[..n.min(MAX_OUTPUT - all.len())]);
                        }
                    }
                }
                let mut s = String::from_utf8_lossy(&all).to_string();
                if all.len() >= MAX_OUTPUT {
                    s.push_str("\n[… cut at 100 KB]");
                }
                s
            })
        };
        let out = read(child.stdout.take().map(|p| Box::new(p) as Box<dyn Read + Send>));
        let err = read(child.stderr.take().map(|p| Box::new(p) as Box<dyn Read + Send>));
        let until = Instant::now() + timeout;
        let mut timed_out = false;
        let status = loop {
            if let Some(s) = child.try_wait().map_err(|e| e.to_string())? {
                break Some(s);
            }
            if Instant::now() >= until {
                timed_out = true;
                let _ = child.kill();
                break child.wait().ok();
            }
            std::thread::sleep(Duration::from_millis(50));
        };
        Ok(Ran {
            code: status.and_then(|s| s.code()),
            timed_out,
            stdout: out.join().unwrap_or_default(),
            stderr: err.join().unwrap_or_default(),
        })
    }

    // one JSON-RPC message → its answer (None for a notification)
    pub fn answer(msg: &Value) -> Option<Value> {
        let id = msg.get("id")?.clone();
        let result = match msg["method"].as_str().unwrap_or_default() {
            "initialize" => {
                let asked = msg["params"]["protocolVersion"].as_str().unwrap_or_default();
                let version = VERSIONS.iter().find(|v| **v == asked).copied().unwrap_or(VERSIONS[0]);
                json!({"protocolVersion": version, "capabilities": {"tools": {}},
                       "serverInfo": {"name": "jfsecure", "version": env!("CARGO_PKG_VERSION")}, "instructions": INSTRUCTIONS})
            }
            "ping" => json!({}),
            "tools/list" => json!({"tools": tools()}),
            "tools/call" => call(&msg["params"]),
            _ => return Some(json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32601, "message": "method not found"}})),
        };
        Some(json!({"jsonrpc": "2.0", "id": id, "result": result}))
    }

    pub fn serve() -> ExitCode {
        let stdin = std::io::stdin();
        let mut stdout = std::io::stdout();
        for line in stdin.lock().lines() {
            let Ok(line) = line else { break };
            if line.trim().is_empty() {
                continue;
            }
            let reply = match serde_json::from_str::<Value>(&line) {
                Ok(msg) => answer(&msg),
                Err(_) => Some(json!({"jsonrpc": "2.0", "id": null, "error": {"code": -32700, "message": "parse error"}})),
            };
            if let Some(r) = reply {
                if writeln!(stdout, "{r}").and_then(|_| stdout.flush()).is_err() {
                    break;
                }
            }
        }
        ExitCode::SUCCESS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn git_credential_input() {
        let f = credential_fields("protocol=https\nhost=github.com\nusername=octo\npassword=x=y\nhost=evil\n");
        assert_eq!(f["host"], "github.com", "the first host wins");
        assert_eq!(f["username"], "octo");
        assert_eq!(f["password"], "x=y", "split at the first =");
    }

    #[test]
    fn mcp_masks_every_value_in_the_output() {
        let vars = vec![("TOKEN".to_string(), "ghp_secret123".to_string()), ("KEY".to_string(), "-----BEGIN-----\nline-one-of-it\nline-two-of-it\n".to_string()), ("N".to_string(), "1".into())];
        let out = redact("got ghp_secret123 and line-two-of-it, 1 thing", &vars);
        assert_eq!(out, "got [JFSecure: TOKEN] and [JFSecure: KEY], 1 thing", "short values (\"1\") aren't masked: they'd mangle everything");
    }

    #[test]
    fn mcp_protocol() {
        let init = mcp::answer(&json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-03-26"}})).unwrap();
        assert_eq!(init["result"]["protocolVersion"], "2025-03-26");
        assert_eq!(init["result"]["serverInfo"]["name"], "jfsecure");
        assert!(mcp::answer(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"})).is_none(), "no answer to a notification");
        let list = mcp::answer(&json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})).unwrap();
        let names: Vec<&str> = list["result"]["tools"].as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap()).collect();
        assert_eq!(names, ["list_secrets", "run_with_secrets", "render_template"]);
        // nothing that would return a value
        assert!(!names.iter().any(|n| n.contains("get")));
        assert_eq!(mcp::answer(&json!({"jsonrpc": "2.0", "id": 3, "method": "nope"})).unwrap()["error"]["code"], -32601);
        let bad = mcp::answer(&json!({"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "run_with_secrets", "arguments": {"secret": "x", "command": []}}})).unwrap();
        assert_eq!(bad["result"]["isError"], true);
    }

    #[test]
    fn mcp_runs_with_variables_and_a_timeout() {
        let vars = vec![("TOKEN".to_string(), "s3cr3t-value".to_string())];
        let (prog, args): (&str, Vec<&str>) = if cfg!(windows) { ("cmd", vec!["/C", "echo %TOKEN%"]) } else { ("sh", vec!["-c", "echo $TOKEN"]) };
        let cmd: Vec<String> = std::iter::once(prog).chain(args).map(String::from).collect();
        let r = mcp::run_captured(&cmd, &vars, None, None, std::time::Duration::from_secs(20)).unwrap();
        assert_eq!(r.code, Some(0));
        assert_eq!(redact(r.stdout.trim(), &vars), "[JFSecure: TOKEN]");
        let slow: Vec<String> = if cfg!(windows) { ["powershell", "-NoProfile", "-Command", "Start-Sleep 30"].map(String::from).to_vec() } else { ["sleep", "30"].map(String::from).to_vec() };
        let t = mcp::run_captured(&slow, &[], None, None, std::time::Duration::from_secs(1)).unwrap();
        assert!(t.timed_out);
        assert_eq!(mcp::shown_command(&["bash".into(), "-c".into(), "echo \"$X\"".into()]), "bash -c \"echo \\\"$X\\\"\"");
    }

    #[test]
    fn stdin_and_masking() {
        let vars = vec![("WG_ADMIN".to_string(), "pa ss".to_string()), ("TOKEN".to_string(), "t0ken-value".to_string())];
        assert_eq!(env_name("wg-admin"), "WG_ADMIN");
        assert_eq!(env_name("2fa"), "_2FA");
        // the same rule as src/utils/cli.js envName (tests/unit/cli.mjs)
        assert_eq!(env_name("психолог линк"), "PSIKHOLOG_LINK");
        assert_eq!(env_name("Щётка-ъ"), "SHCHYOTKA_");
        assert_eq!(env_name("їжак"), "YIZHAK");
        assert_eq!(env_name("ключ€"), "KLYUCH_");
        // MCP keys: the stdin key joins a list; no list = every key
        assert_eq!(mcp::only_keys(&json!(["token"]), Some("wg-admin")), vec!["token", "wg-admin"]);
        assert_eq!(mcp::only_keys(&json!(["WG_ADMIN"]), Some("wg-admin")), vec!["WG_ADMIN"]);
        assert!(mcp::only_keys(&Value::Null, Some("wg-admin")).is_empty());
        assert_eq!(stdin_value(&vars, "wg-admin"), Ok("pa ss"));
        assert_eq!(stdin_value(&vars, "TOKEN"), Ok("t0ken-value"));
        assert!(stdin_value(&vars, "nope").unwrap_err().contains("WG_ADMIN, TOKEN"));
        let cmd = ["ssh".to_string(), "host".to_string(), "bash /root/x.sh".to_string()];
        assert_eq!(shown_run(&cmd, Some("wg-admin"), true), "ssh host \"bash /root/x.sh\" < $WG_ADMIN");
        assert_eq!(shown_run(&cmd[..1], None, false), "ssh   (output NOT masked)");
        // the value reaches the command's stdin exactly (no new line, no BOM)
        let (prog, args): (&str, Vec<&str>) = if cfg!(windows) {
            ("powershell", vec!["-NoProfile", "-Command", "$i = [Console]::In.ReadToEnd(); 'len=' + $i.Length + ' same=' + ($i -eq $env:TOKEN)"])
        } else {
            ("sh", vec!["-c", "i=$(cat); echo \"len=${#i} same=$([ \"$i\" = \"$TOKEN\" ] && echo True || echo False)\""])
        };
        let cmd: Vec<String> = std::iter::once(prog).chain(args).map(String::from).collect();
        let r = mcp::run_captured(&cmd, &vars, Some("t0ken-value"), None, std::time::Duration::from_secs(30)).unwrap();
        assert_eq!(r.stdout.trim(), "len=11 same=True");
        assert!(p("get a --stdin x").is_err(), "--stdin is for jfs run only");
        let r = p("run deploy --stdin wg-admin --no-mask -- ssh h").unwrap();
        assert_eq!((r.stdin.as_deref(), r.no_mask), (Some("wg-admin"), true));
    }

    fn p(s: &str) -> Result<Args, String> {
        parse(&s.split_whitespace().map(String::from).collect::<Vec<_>>())
    }

    #[test]
    fn arguments() {
        let a = p("get work/github/token -a port=2222 --answer user=me -n").unwrap();
        assert_eq!((a.cmd.as_str(), a.path.as_str(), a.no_newline), ("get", "work/github/token", true));
        assert_eq!(a.answers["port"], "2222");
        assert_eq!(a.answers["user"], "me");
        assert!(p("get a b").is_err());
        assert!(p("get a --answer nope").is_err());
        assert!(p("get a --bogus").is_err());
        assert_eq!(p("").unwrap().cmd, "help");
        // after "--" everything is the command, options included
        let r = p("run deploy -a env=prod -- git push -n --force").unwrap();
        assert_eq!((r.path.as_str(), r.no_newline), ("deploy", false));
        assert_eq!(r.command, ["git", "push", "-n", "--force"]);
        assert_eq!(r.answers["env"], "prod");
    }
}
