// Tauri shell: one window showing the same web bundle that runs in a
// browser tab. The UI reaches rk-daemon over HTTP (Connect protocol); there
// is deliberately no Tauri IPC in the data path.
//
// Which daemon (docs/packaging.md, "Desktop app"):
//
//   - REVKIT_UI_URL set: load that URL instead of the bundled assets (for
//     example a daemon's own copy: http://127.0.0.1:50052/).
//   - REVKIT_DAEMON set: the bundled UI talks to that daemon, which must
//     allow this origin (rk-daemon --allow-origin tauri://localhost).
//   - Otherwise the shell starts its own rk-daemon: $REVKIT_DAEMON_BIN, else
//     the one the app bundles (the AppImage carries the portable bundle as
//     resources/revkit.tar.gz, unpacked once into the app's data directory),
//     else rk-daemon beside this executable or on PATH (the desktop .deb
//     depends on the revkit package's /usr/bin/rk-daemon). It listens on free loopback ports with
//     accounts on: projects and the credential file live in the app's data
//     directory (~/.local/share/dev.revkit.ui/projects), the shell makes an
//     admin account named after $USER once and a fresh API token for it at
//     every start, and hands the token to the UI, so edits are stamped
//     user:<you> and no other local user can call the daemon. The Open
//     dialog browses the home directory. The daemon stops with the window.
//   - No rk-daemon found: http://127.0.0.1:50052, as before.
//
// Downloads (File → Export project…, an exported program) ask where to save
// with the desktop's native dialog (GTK's on Linux; elsewhere they go to
// ~/Downloads). Opening a file is the webview's own file input, which is
// native already.
//
// Daemon control (docs/ui.md, "Daemon status"): the UI's status chip asks
// the shell about the daemon it started and starts, stops or restarts it
// through the daemon_* commands below, the only Tauri IPC the UI uses. They
// are granted to the bundled page of the main window only
// (capabilities/default.json; build.rs declares them), never to remote
// content. A restart keeps the HTTP port when it is free, and the account
// token the shell made at launch, so the page carries on; the daemon stays
// on loopback with accounts on.
//
// Environment:
//   REVKIT_DAEMON      daemon HTTP URL
//   REVKIT_DAEMON_BIN  rk-daemon to start
//   REVKIT_UI_QUERY    extra query string for index.html, e.g.
//                      "program=default/prog&autobench=tauri-dpr1"
//   REVKIT_UI_URL      load this URL instead of the bundled assets
//   REVKIT_WIDTH/HEIGHT  inner window size in logical px (default 1600x1000)
//   REVKIT_UNDECORATED=1 no window decorations (benchmarks under Xvfb)

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tauri::{AppHandle, Manager, RunEvent, WebviewUrl, WebviewWindowBuilder};

/// The daemon the shell starts (None in `Daemon` when it uses another).
struct Managed {
    bin: PathBuf,
    /// The app's data directory: projects/, daemon.log, daemon-ports.json.
    data: PathBuf,
    /// The admin account's API token, made at launch; restarts reuse it.
    token: String,
    /// The HTTP port of the last start (0 before the first): a restart
    /// asks for it again, so the page's address stays the same.
    port: u16,
    child: Option<Child>,
    /// How the last daemon ended, if it did.
    exit: Option<String>,
    /// A start or stop is under way.
    busy: bool,
}

struct Daemon(Mutex<Option<Managed>>);

/// What the UI's status chip is told (ui/src/ui/daemon.ts, DesktopDaemon).
#[derive(serde::Serialize, Default)]
#[serde(rename_all = "camelCase")]
struct DaemonStatus {
    managed: bool,
    running: bool,
    pid: Option<u32>,
    url: Option<String>,
    exit: Option<String>,
    log_path: Option<String>,
    log_tail: Vec<String>,
    /// The API token, after a start (for a page that follows the daemon to
    /// another address).
    token: Option<String>,
}

#[derive(serde::Serialize)]
struct DaemonLog {
    path: String,
    text: String,
}

/// The portable bundle the app carries (resources/revkit.tar.gz), unpacked
/// into <data>/runtime/<version>-<size> on first use; its rk-daemon.
fn unpack_bundled(app: &tauri::App) -> Option<PathBuf> {
    let tarball = app.path().resource_dir().ok()?.join("revkit.tar.gz");
    let size = std::fs::metadata(&tarball).ok()?.len();
    let runtime = app.path().app_data_dir().ok()?.join("runtime");
    // The app's version is the build's (packaging/desktop/build.sh), so each
    // build unpacks its own bundle.
    let dest = runtime.join(format!("{}-{size}", app.package_info().version));
    let daemon = dest.join("bin/rk-daemon");
    if daemon.is_file() {
        return Some(daemon);
    }
    let tmp = runtime.join(format!(".unpack-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).ok()?;
    let ok = Command::new("tar")
        .arg("-xzf")
        .arg(&tarball)
        .arg("-C")
        .arg(&tmp)
        .arg("--strip-components=1")
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !ok || std::fs::rename(&tmp, &dest).is_err() {
        eprintln!("revkit: could not unpack {}", tarball.display());
        let _ = std::fs::remove_dir_all(&tmp);
        return None;
    }
    // Older versions' runtimes are no longer needed.
    if let Ok(entries) = std::fs::read_dir(&runtime) {
        for e in entries.flatten() {
            if e.path() != dest {
                let _ = std::fs::remove_dir_all(e.path());
            }
        }
    }
    daemon.is_file().then_some(daemon)
}

/// The rk-daemon to start, if any.
fn find_daemon(app: &tauri::App) -> Option<PathBuf> {
    if let Ok(p) = std::env::var("REVKIT_DAEMON_BIN") {
        return Some(PathBuf::from(p));
    }
    if let Some(p) = unpack_bundled(app) {
        return Some(p);
    }
    let mut candidates = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            candidates.push(dir.join("rk-daemon"));
        }
    }
    if let Some(path) = std::env::var_os("PATH") {
        candidates.extend(std::env::split_paths(&path).map(|d| d.join("rk-daemon")));
    }
    candidates.into_iter().find(|p| p.is_file())
}

fn account_name() -> String {
    let user = std::env::var("USER").unwrap_or_default();
    let ok = !user.is_empty() && user.chars().all(|c| c.is_ascii_alphanumeric() || "._@-".contains(c));
    if ok { user } else { "desktop".into() }
}

fn random_password() -> String {
    use std::io::Read;
    let mut b = [0u8; 24];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        let _ = f.read_exact(&mut b);
    }
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Runs `rk-daemon <args>` (an admin subcommand) and returns its stdout.
fn admin(bin: &Path, args: &[&str], stdin: Option<&str>) -> Result<String, String> {
    use std::io::Write;
    let mut child = Command::new(bin)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("{}: {e}", bin.display()))?;
    if let Some(s) = stdin {
        let _ = child.stdin.take().unwrap().write_all(format!("{s}\n").as_bytes());
    }
    let out = child.wait_with_output().map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// The account (once; an existing one is kept) and a fresh API token for it.
fn mint_token(bin: &Path, pdir: &str) -> Result<String, String> {
    let user = account_name();
    let _ = admin(bin, &["user", "add", &user, "--role", "admin", "--password-stdin", "--project-dir", pdir], Some(&random_password()));
    let _ = admin(bin, &["token", "revoke", "desktop", "--project-dir", pdir], None);
    let token = admin(
        bin,
        &["token", "create", "--name", "desktop", "--role", "admin", "--user", &user, "--ttl-days", "30", "--project-dir", pdir],
        None,
    )?;
    Ok(token.lines().last().unwrap_or("").to_string())
}

fn projects_dir(data: &Path) -> String {
    data.join("projects").to_string_lossy().to_string()
}

fn log_path(data: &Path) -> PathBuf {
    data.join("daemon.log")
}

/// The last `max` bytes of the daemon's log, from a line start.
fn read_log_tail(path: &Path, max: u64) -> String {
    use std::io::{Read, Seek, SeekFrom};
    let Ok(mut f) = std::fs::File::open(path) else { return String::new() };
    let len = f.metadata().map(|m| m.len()).unwrap_or(0);
    let from = len.saturating_sub(max);
    let _ = f.seek(SeekFrom::Start(from));
    let mut buf = Vec::new();
    let _ = f.read_to_end(&mut buf);
    let text = String::from_utf8_lossy(&buf).to_string();
    if from > 0 {
        if let Some(nl) = text.find('\n') {
            return text[nl + 1..].to_string();
        }
    }
    text
}

/// The log's last `n` lines.
fn last_lines(text: &str, n: usize) -> Vec<String> {
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    lines[lines.len().saturating_sub(n)..].iter().map(|l| l.to_string()).collect()
}

/// The HTTP port in a --port-file: {"grpc": N, "http": M, "tls": false}.
fn http_port_of(port_file_text: &str) -> Option<u16> {
    let rest = port_file_text.split("\"http\":").nth(1)?;
    rest.trim_start().split(|c: char| !c.is_ascii_digit()).next()?.parse().ok()
}

/// Notes how the daemon ended, if it has.
fn reap(m: &mut Managed) {
    if let Some(child) = m.child.as_mut() {
        if let Ok(Some(status)) = child.try_wait() {
            m.exit = Some(status.to_string());
            m.child = None;
        }
    }
}

fn status_of(m: &mut Managed) -> DaemonStatus {
    reap(m);
    let log = log_path(&m.data);
    DaemonStatus {
        managed: true,
        running: m.child.is_some(),
        pid: m.child.as_ref().map(|c| c.id()),
        url: (m.port != 0).then(|| format!("http://127.0.0.1:{}", m.port)),
        exit: m.exit.clone(),
        log_path: Some(log.to_string_lossy().to_string()),
        log_tail: last_lines(&read_log_tail(&log, 16 * 1024), 20),
        token: None,
    }
}

/// Starts `rk-daemon` on loopback with accounts on, on HTTP `port` (0: any
/// free one). Returns the port file to wait for.
fn spawn_daemon(m: &mut Managed, port: u16) -> Result<PathBuf, String> {
    let pdir = projects_dir(&m.data);
    std::fs::create_dir_all(&pdir).map_err(|e| e.to_string())?;
    let port_file = m.data.join("daemon-ports.json");
    let _ = std::fs::remove_file(&port_file);
    let home = std::env::var("HOME").unwrap_or_else(|_| "/".into());
    let log = std::fs::File::create(log_path(&m.data)).map_err(|e| e.to_string())?;
    let child = Command::new(&m.bin)
        .args(["--grpc", "127.0.0.1:0", "--http", &format!("127.0.0.1:{port}"), "--allow-origin", "tauri://localhost"])
        .args(["--project-dir", &pdir, "--browse-root", &home])
        .arg("--port-file")
        .arg(&port_file)
        .stdout(Stdio::null())
        .stderr(log)
        .spawn()
        .map_err(|e| format!("{}: {e}", m.bin.display()))?;
    m.child = Some(child);
    m.exit = None;
    Ok(port_file)
}

enum Ready {
    Port(u16),
    /// It exited before listening; with "cannot listen" in its log.
    Exited { busy_port: bool },
    Timeout,
}

/// Waits (without holding the lock) until the daemon writes its port file.
fn wait_ready(app: &AppHandle, port_file: &Path) -> Ready {
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if let Some(port) = std::fs::read_to_string(port_file).ok().as_deref().and_then(http_port_of) {
            return Ready::Port(port);
        }
        {
            let state = app.state::<Daemon>();
            let mut guard = state.0.lock().unwrap();
            if let Some(m) = guard.as_mut() {
                reap(m);
                if m.child.is_none() {
                    let log = read_log_tail(&log_path(&m.data), 4096);
                    return Ready::Exited { busy_port: log.contains("cannot listen") };
                }
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Ready::Timeout
}

/// Starts the app's daemon unless it runs; its status after.
fn start_managed(app: &AppHandle) -> Result<DaemonStatus, String> {
    let state = app.state::<Daemon>();
    let previous_port;
    let port_file;
    {
        let mut guard = state.0.lock().unwrap();
        let m = guard.as_mut().ok_or("this daemon was not started by the app")?;
        reap(m);
        if m.child.is_some() {
            return Ok(status_of(m));
        }
        if m.busy {
            return Err("the daemon is starting or stopping".into());
        }
        m.busy = true;
        previous_port = m.port;
        port_file = spawn_daemon(m, previous_port);
    }
    let finish = |result: Result<u16, String>| -> Result<DaemonStatus, String> {
        let mut guard = state.0.lock().unwrap();
        let m = guard.as_mut().unwrap();
        m.busy = false;
        let port = result?;
        m.port = port;
        // The page needs the token when the address changed (a first
        // start after a failed launch, or the old port taken).
        let mut st = status_of(m);
        st.token = Some(m.token.clone());
        Ok(st)
    };
    let port_file = match port_file {
        Ok(p) => p,
        Err(e) => return finish(Err(e)),
    };
    let mut ready = wait_ready(app, &port_file);
    // Its old port taken meanwhile: any free one (the page follows it).
    if previous_port != 0 {
        if let Ready::Exited { busy_port: true } = ready {
            let retry = {
                let mut guard = state.0.lock().unwrap();
                spawn_daemon(guard.as_mut().unwrap(), 0)
            };
            ready = match retry {
                Ok(p) => wait_ready(app, &p),
                Err(e) => return finish(Err(e)),
            };
        }
    }
    let data = state.0.lock().unwrap().as_ref().map(|m| m.data.clone()).unwrap_or_default();
    finish(match ready {
        Ready::Port(p) => Ok(p),
        Ready::Exited { .. } => Err(format!("rk-daemon exited; see {}", log_path(&data).display())),
        Ready::Timeout => Err("rk-daemon did not start within 30 s".into()),
    })
}

/// Stops the app's daemon: SIGTERM (it saves and closes its projects), then
/// SIGKILL after 10 s.
fn stop_managed(app: &AppHandle) -> Result<DaemonStatus, String> {
    let state = app.state::<Daemon>();
    let child = {
        let mut guard = state.0.lock().unwrap();
        let m = guard.as_mut().ok_or("this daemon was not started by the app")?;
        if m.busy {
            return Err("the daemon is starting or stopping".into());
        }
        reap(m);
        m.busy = true;
        m.child.take()
    };
    let exit = child.map(|c| terminate(c, Duration::from_secs(10)));
    let mut guard = state.0.lock().unwrap();
    let m = guard.as_mut().unwrap();
    m.busy = false;
    if let Some(e) = exit {
        m.exit = Some(format!("stopped from the app; {e}"));
    }
    Ok(status_of(m))
}

/// SIGTERM, then SIGKILL after `grace`; how it ended.
fn terminate(mut child: Child, grace: Duration) -> String {
    #[cfg(unix)]
    unsafe {
        libc::kill(child.id() as libc::pid_t, libc::SIGTERM);
    }
    let deadline = Instant::now() + grace;
    while Instant::now() < deadline {
        if let Ok(Some(status)) = child.try_wait() {
            return status.to_string();
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    child.wait().map(|s| s.to_string()).unwrap_or_else(|e| e.to_string())
}

fn not_managed() -> DaemonStatus {
    DaemonStatus::default()
}

// The UI's daemon controls. Blocking work runs off the main thread.

#[tauri::command]
async fn daemon_status(app: AppHandle) -> Result<DaemonStatus, String> {
    let state = app.state::<Daemon>();
    let mut guard = state.0.lock().unwrap();
    Ok(guard.as_mut().map(status_of).unwrap_or_else(not_managed))
}

#[tauri::command]
async fn daemon_start(app: AppHandle) -> Result<DaemonStatus, String> {
    tauri::async_runtime::spawn_blocking(move || start_managed(&app)).await.map_err(|e| e.to_string())?
}

#[tauri::command]
async fn daemon_stop(app: AppHandle) -> Result<DaemonStatus, String> {
    tauri::async_runtime::spawn_blocking(move || stop_managed(&app)).await.map_err(|e| e.to_string())?
}

#[tauri::command]
async fn daemon_restart(app: AppHandle) -> Result<DaemonStatus, String> {
    tauri::async_runtime::spawn_blocking(move || {
        stop_managed(&app)?;
        start_managed(&app)
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn daemon_log(app: AppHandle) -> Result<DaemonLog, String> {
    let state = app.state::<Daemon>();
    let data = state.0.lock().unwrap().as_ref().map(|m| m.data.clone()).ok_or("this daemon was not started by the app")?;
    let path = log_path(&data);
    Ok(DaemonLog { text: read_log_tail(&path, 256 * 1024), path: path.to_string_lossy().to_string() })
}

/// Starts the app's own daemon at launch; returns its HTTP URL and an API
/// token. The daemon stays managed even when this fails, so the UI can show
/// why and start it again.
fn start_daemon(app: &tauri::App, bin: &Path) -> Result<(String, String), String> {
    let data = app.path().app_data_dir().map_err(|e| e.to_string())?;
    std::fs::create_dir_all(data.join("projects")).map_err(|e| e.to_string())?;
    let token = mint_token(bin, &projects_dir(&data))?;
    app.state::<Daemon>().0.lock().unwrap().replace(Managed {
        bin: bin.to_path_buf(),
        data,
        token: token.clone(),
        port: 0,
        child: None,
        exit: None,
        busy: false,
    });
    let st = start_managed(app.handle())?;
    Ok((st.url.ok_or("rk-daemon gave no port")?, token))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_file() {
        assert_eq!(http_port_of("{\"grpc\": 4100, \"http\": 4101, \"tls\": false}\n"), Some(4101));
        assert_eq!(http_port_of("{\"grpc\": 4100,"), None);
        assert_eq!(http_port_of(""), None);
    }

    #[test]
    fn log_tail_lines() {
        assert_eq!(last_lines("a\n\nb\nc\n", 2), vec!["b", "c"]);
        assert_eq!(last_lines("a\n", 5), vec!["a"]);
        assert!(last_lines("", 5).is_empty());
    }

    #[test]
    fn log_tail_starts_at_a_line() {
        let dir = std::env::temp_dir().join(format!("rk-shell-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("daemon.log");
        std::fs::write(&p, "first line\nsecond line\nthird\n").unwrap();
        assert_eq!(read_log_tail(&p, 1024), "first line\nsecond line\nthird\n");
        assert_eq!(read_log_tail(&p, 10), "third\n");
        assert_eq!(read_log_tail(&dir.join("none"), 10), "");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Start, stop and restart a stand-in daemon (a shell script that
    /// writes its port file and waits), without a window.
    #[cfg(unix)]
    #[test]
    fn spawn_and_terminate_a_stand_in() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("rk-shell-spawn-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let bin = dir.join("fake-daemon");
        // Writes {"http": <port or 53999>} to --port-file, then waits for SIGTERM.
        std::fs::write(
            &bin,
            "#!/bin/sh\nwhile [ $# -gt 0 ]; do case $1 in --port-file) pf=$2; shift;; --http) h=$2; shift;; esac; shift; done\n\
             p=${h##*:}; [ \"$p\" = 0 ] && p=53999\necho \"listening on $p\" >&2\n\
             printf '{\"grpc\": 1, \"http\": %s, \"tls\": false}' $p > $pf\ntrap 'echo bye >&2; exit 0' TERM\nwhile :; do sleep 0.1; done\n",
        )
        .unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        let mut m = Managed { bin, data: dir.clone(), token: "t".into(), port: 0, child: None, exit: None, busy: false };
        let pf = spawn_daemon(&mut m, 0).unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut port = None;
        while Instant::now() < deadline && port.is_none() {
            port = std::fs::read_to_string(&pf).ok().as_deref().and_then(http_port_of);
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(port, Some(53999));
        m.port = 53999;
        let st = status_of(&mut m);
        assert!(st.running && st.pid.is_some());
        assert_eq!(st.url.as_deref(), Some("http://127.0.0.1:53999"));
        let how = terminate(m.child.take().unwrap(), Duration::from_secs(5));
        assert!(how.contains("exit status: 0"), "{how}");
        let st = status_of(&mut m);
        assert!(!st.running);
        assert!(st.log_tail.iter().any(|l| l == "bye"), "{:?}", st.log_tail);
        // A restart asks for the same port.
        let pf = spawn_daemon(&mut m, 53999).unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline && !pf.exists() {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(read_log_tail(&log_path(&dir), 1024).contains("listening on 53999"));
        terminate(m.child.take().unwrap(), Duration::from_secs(5));
        // Died by itself: its status says how.
        std::fs::write(&m.bin, "#!/bin/sh\necho 'rk-daemon: cannot listen on 127.0.0.1:53999' >&2\nexit 1\n").unwrap();
        spawn_daemon(&mut m, 53999).unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline && status_of(&mut m).running {
            std::thread::sleep(Duration::from_millis(20));
        }
        let st = status_of(&mut m);
        assert!(!st.running);
        assert_eq!(st.exit.as_deref(), Some("exit status: 1"));
        assert_eq!(st.log_tail, vec!["rk-daemon: cannot listen on 127.0.0.1:53999"]);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

/// Where to save a download: the native save dialog, starting at the
/// webview's suggestion (its file name in the downloads directory). None:
/// cancelled.
#[cfg(target_os = "linux")]
fn ask_save_path(suggested: &Path) -> Option<PathBuf> {
    use gtk::prelude::*;
    let dialog = gtk::FileChooserNative::new(
        Some("Save"),
        None::<&gtk::Window>,
        gtk::FileChooserAction::Save,
        Some("_Save"),
        Some("_Cancel"),
    );
    dialog.set_do_overwrite_confirmation(true);
    if let Some(name) = suggested.file_name().and_then(|n| n.to_str()) {
        dialog.set_current_name(name);
    }
    let folder = suggested
        .parent()
        .filter(|d| d.is_absolute() && d.is_dir())
        .map(Path::to_path_buf)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join("Downloads")).filter(|d| d.is_dir()));
    if let Some(dir) = folder {
        let _ = dialog.set_current_folder(&dir);
    }
    let path = if dialog.run() == gtk::ResponseType::Accept { dialog.filename() } else { None };
    dialog.destroy();
    path
}

/// Elsewhere: the downloads directory, under the suggested name.
#[cfg(not(target_os = "linux"))]
fn ask_save_path(suggested: &Path) -> Option<PathBuf> {
    if suggested.is_absolute() {
        return Some(suggested.to_path_buf());
    }
    let home = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE"))?;
    Some(PathBuf::from(home).join("Downloads").join(suggested.file_name()?))
}

fn main() {
    let app = tauri::Builder::default()
        .manage(Daemon(Mutex::new(None)))
        .invoke_handler(tauri::generate_handler![daemon_status, daemon_start, daemon_stop, daemon_restart, daemon_log])
        .setup(|app| {
            let mut init_script = String::new();
            let url = match std::env::var("REVKIT_UI_URL") {
                Ok(u) => WebviewUrl::External(u.parse().expect("REVKIT_UI_URL")),
                Err(_) => {
                    let mut daemon = std::env::var("REVKIT_DAEMON").ok();
                    if daemon.is_none() {
                        if let Some(bin) = find_daemon(app) {
                            match start_daemon(app, &bin) {
                                Ok((url, token)) => {
                                    // The UI keeps a cross-origin daemon's token under this key (ui/src/api/client.ts).
                                    init_script = format!(
                                        "try {{ localStorage.setItem({:?}, {:?}); }} catch (e) {{}}",
                                        format!("rk.session:{url}"),
                                        token
                                    );
                                    daemon = Some(url);
                                }
                                Err(e) => eprintln!("revkit: could not start rk-daemon: {e}"),
                            }
                        }
                    }
                    let daemon = daemon.unwrap_or_else(|| "http://127.0.0.1:50052".into());
                    let mut q = format!("api={daemon}");
                    if let Ok(extra) = std::env::var("REVKIT_UI_QUERY") {
                        if !extra.is_empty() {
                            q = format!("{q}&{extra}");
                        }
                    }
                    WebviewUrl::App(format!("index.html?{q}").into())
                }
            };
            let w: f64 = std::env::var("REVKIT_WIDTH").ok().and_then(|v| v.parse().ok()).unwrap_or(1600.0);
            let h: f64 = std::env::var("REVKIT_HEIGHT").ok().and_then(|v| v.parse().ok()).unwrap_or(1000.0);
            let undecorated = std::env::var("REVKIT_UNDECORATED").map(|v| v == "1").unwrap_or(false);
            let mut b = WebviewWindowBuilder::new(app, "main", url).title("revkit").inner_size(w, h);
            if !init_script.is_empty() {
                b = b.initialization_script(&init_script);
            }
            if undecorated {
                b = b.decorations(false).position(0.0, 0.0);
            }
            // Downloads (a project archive, an exported program): ask where
            // to save with the desktop's own dialog; cancelling it cancels
            // the download.
            b = b.on_download(|_webview, event| match event {
                tauri::webview::DownloadEvent::Requested { destination, .. } => match ask_save_path(destination) {
                    Some(path) => {
                        *destination = path;
                        true
                    }
                    None => false,
                },
                _ => true,
            });
            b.build()?;
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error while building tauri application");
    app.run(|app, event| {
        if let RunEvent::Exit = event {
            let child = app.state::<Daemon>().0.lock().unwrap().as_mut().and_then(|m| m.child.take());
            if let Some(child) = child {
                terminate(child, Duration::from_secs(5));
            }
        }
    });
}
