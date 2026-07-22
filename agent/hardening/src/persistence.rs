//! Persistence mechanism implementations.
//!
//! Research / educational reference implementations of common
//! persistence techniques used by operating systems for background
//! services and startup automation. All install/uninstall operations
//! are scoped to the **user** context (`~/.config/...`) — no system
//! paths are touched at any point.
//!
//! # Supported mechanisms
//!
//! | Mechanism   | Linux | Windows |
//! |-------------|-------|---------|
//! | systemd     |  ✅   |  N/A    |
//! | crontab     |  ✅   |  N/A    |
//! | Autostart   |  ✅   |  N/A    |
//! | Registry    |  N/A  |  🚧     |
//! | Task Sched. |  N/A  |  🚧     |
//!
//! 🚧 = stub only — not tested, returned as "not yet implemented".

use std::path::PathBuf;
use std::process::Command;

// ---------------------------------------------------------------------------
// Helper: resolve XDG/config home
// ---------------------------------------------------------------------------

/// Returns the user's config directory (`~/.config`).
///
/// Respects `$XDG_CONFIG_HOME` if set; falls back to `$HOME/.config`.
#[must_use]
fn config_dir() -> PathBuf {
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        PathBuf::from(xdg)
    } else if let Ok(home) = std::env::var("HOME") {
        PathBuf::from(home).join(".config")
    } else {
        // Last-resort fallback; unlikely in practice.
        PathBuf::from(".config")
    }
}

// ---------------------------------------------------------------------------
// systemd – user-scoped service unit
// ---------------------------------------------------------------------------

/// Result type returned by persistence operations.
pub type PersistenceResult<T> = Result<T, Box<dyn std::error::Error>>;

/// Install a user-scoped systemd service.
///
/// # Research example
///
/// Writes a `.service` unit file to `~/.config/systemd/user/` and
/// calls `systemctl --user daemon-reload` so the unit is recognised.
/// The service is **not** started or enabled — the caller should
/// decide whether to `systemctl --user start` and `enable` it.
///
/// # Errors
///
/// Returns an error if the unit file cannot be written or if
/// `systemctl --user daemon-reload` fails.
///
/// # Paths used
///
/// - `$XDG_CONFIG_HOME/systemd/user/<name>.service` (default
///   `~/.config/systemd/user/<name>.service`)
#[cfg(target_os = "linux")]
pub fn install_systemd_service(name: &str, exec_start: &str, description: &str) -> PersistenceResult<()> {
    let unit_dir = config_dir().join("systemd").join("user");
    std::fs::create_dir_all(&unit_dir)?;

    let unit_content = format!(
        r#"[Unit]
Description={desc}
After=network.target

[Service]
Type=simple
ExecStart={exec}
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
"#,
        desc = description,
        exec = exec_start,
    );

    let unit_path = unit_dir.join(format!("{name}.service"));
    std::fs::write(&unit_path, unit_content.as_bytes())?;

    // Tell the user manager to re-read unit files.
    Command::new("systemctl")
        .args(["--user", "daemon-reload"])
        .status()?;

    Ok(())
}

/// Remove a previously installed user-scoped systemd service.
///
/// # Research example
///
/// Stops the service (if running), disables it, deletes the unit file,
/// and invokes `systemctl --user daemon-reload`.
///
/// # Errors
///
/// Returns an error if any of the stop, disable, file removal, or
/// daemon-reload steps fail. Does **not** return an error if the unit
/// file did not exist in the first place.
///
/// # Paths used
///
/// - `$XDG_CONFIG_HOME/systemd/user/<name>.service`
#[cfg(target_os = "linux")]
pub fn uninstall_systemd_service(name: &str) -> PersistenceResult<()> {
    let unit_path = config_dir()
        .join("systemd")
        .join("user")
        .join(format!("{name}.service"));

    // Stop & disable (best-effort — ignore if unit doesn't exist).
    let _ = Command::new("systemctl")
        .args(["--user", "stop", name])
        .status();
    let _ = Command::new("systemctl")
        .args(["--user", "disable", name])
        .status();

    // Remove the unit file.
    if unit_path.exists() {
        std::fs::remove_file(&unit_path)?;
    }

    // Reload so the unit disappears from the manager.
    Command::new("systemctl")
        .args(["--user", "daemon-reload"])
        .status()?;

    Ok(())
}

/// Generate the content of a systemd unit file as a `String`.
///
/// Pure function — no filesystem access. Useful for testing or
/// previewing the unit before writing.
#[must_use]
#[cfg(target_os = "linux")]
pub fn generate_systemd_unit(_name: &str, exec_start: &str, description: &str) -> String {
    format!(
        r#"[Unit]
Description={desc}
After=network.target

[Service]
Type=simple
ExecStart={exec}
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
"#,
        desc = description,
        exec = exec_start,
    )
}

// ---------------------------------------------------------------------------
// systemd – stub for non-Linux
// ---------------------------------------------------------------------------

#[cfg(not(target_os = "linux"))]
pub fn install_systemd_service(_name: &str, _exec_start: &str, _description: &str) -> PersistenceResult<()> {
    Err("systemd is only available on Linux".into())
}

#[cfg(not(target_os = "linux"))]
pub fn uninstall_systemd_service(_name: &str) -> PersistenceResult<()> {
    Err("systemd is only available on Linux".into())
}

#[cfg(not(target_os = "linux"))]
#[must_use]
pub fn generate_systemd_unit(_name: &str, _exec_start: &str, _description: &str) -> String {
    String::new()
}

// ---------------------------------------------------------------------------
// crontab – user crontab entry management
// ---------------------------------------------------------------------------

/// Install a crontab entry for the current user.
///
/// # Research example
///
/// Reads the current crontab (via `crontab -l`), appends the new
/// line if it isn't already present, and writes it back with
/// `crontab -`. Operates on the **user's** crontab only.
///
/// # Errors
///
/// Returns an error if `crontab` is not installed, the existing
/// crontab cannot be read, or the updated crontab cannot be written.
#[cfg(target_os = "linux")]
pub fn install_crontab_entry(expr: &str, command: &str) -> PersistenceResult<()> {
    let new_line = format!("{expr} {command}\n");

    // Read existing crontab (may be empty).
    let existing = Command::new("crontab")
        .arg("-l")
        .output()
        .ok()
        .and_then(|o| o.status.success().then(|| String::from_utf8_lossy(&o.stdout).to_string()))
        .unwrap_or_default();

    // If the line is already present, do nothing.
    if existing.contains(&new_line) {
        return Ok(());
    }

    let updated = existing + &new_line;

    // Write back via stdin.
    let mut child = Command::new("crontab")
        .arg("-")
        .stdin(std::process::Stdio::piped())
        .spawn()?;

    use std::io::Write;
    child
        .stdin
        .take()
        .ok_or("failed to open crontab stdin")?
        .write_all(updated.as_bytes())?;

    let status = child.wait()?;
    if !status.success() {
        return Err(format!("crontab exited with: {status:?}").into());
    }

    Ok(())
}

/// Remove all crontab lines matching a given command substring.
///
/// # Research example
///
/// Reads the user's crontab, filters out every line containing the
/// `command_fragment`, and writes the result back with `crontab -`.
///
/// # Errors
///
/// Returns an error if the crontab cannot be read or written.
#[cfg(target_os = "linux")]
pub fn uninstall_crontab_entry(command_fragment: &str) -> PersistenceResult<()> {
    let output = Command::new("crontab").arg("-l").output()?;

    if !output.status.success() {
        // No crontab exists — nothing to remove.
        return Ok(());
    }

    let stdout_str = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<&str> = stdout_str
        .lines()
        .filter(|l| !l.contains(command_fragment))
        .collect();

    let updated = lines.join("\n") + "\n";

    let mut child = Command::new("crontab")
        .arg("-")
        .stdin(std::process::Stdio::piped())
        .spawn()?;

    use std::io::Write;
    child
        .stdin
        .take()
        .ok_or("failed to open crontab stdin")?
        .write_all(updated.as_bytes())?;

    let status = child.wait()?;
    if !status.success() {
        return Err(format!("crontab exited with: {status:?}").into());
    }

    Ok(())
}

/// Format a crontab line without touching the filesystem.
///
/// Pure function for testing and preview.
#[must_use]
pub fn format_crontab_line(expr: &str, command: &str) -> String {
    format!("{expr} {command}\n")
}

// ---------------------------------------------------------------------------
// crontab – stub for non-Linux
// ---------------------------------------------------------------------------

#[cfg(not(target_os = "linux"))]
pub fn install_crontab_entry(_expr: &str, _command: &str) -> PersistenceResult<()> {
    Err("crontab is only available on Linux".into())
}

#[cfg(not(target_os = "linux"))]
pub fn uninstall_crontab_entry(_command_fragment: &str) -> PersistenceResult<()> {
    Err("crontab is only available on Linux".into())
}

// ---------------------------------------------------------------------------
// Autostart – XDG desktop entry
// ---------------------------------------------------------------------------

/// Install a desktop autostart entry.
///
/// # Research example
///
/// Writes a `.desktop` file to `~/.config/autostart/`. The desktop
/// environment will launch the application at every login.
///
/// # Errors
///
/// Returns an error if the `autostart` directory cannot be created or
/// the `.desktop` file cannot be written.
///
/// # Paths used
///
/// - `$XDG_CONFIG_HOME/autostart/<name>.desktop` (default
///   `~/.config/autostart/<name>.desktop`)
#[cfg(target_os = "linux")]
pub fn install_autostart_entry(name: &str, exec: &str, comment: &str) -> PersistenceResult<()> {
    let autostart_dir = config_dir().join("autostart");
    std::fs::create_dir_all(&autostart_dir)?;

    let desktop_content = format!(
        r#"[Desktop Entry]
Type=Application
Name={name}
Exec={exec}
Comment={comment}
X-GNOME-Autostart-enabled=true
"#,
        name = name,
        exec = exec,
        comment = comment,
    );

    let desktop_path = autostart_dir.join(format!("{name}.desktop"));
    std::fs::write(&desktop_path, desktop_content.as_bytes())?;

    Ok(())
}

/// Remove a previously installed desktop autostart entry.
///
/// # Research example
///
/// Deletes the `.desktop` file from `~/.config/autostart/`.
///
/// # Errors
///
/// Returns an error only if the file exists but cannot be deleted.
/// Does **not** return an error if the file was already removed.
///
/// # Paths used
///
/// - `$XDG_CONFIG_HOME/autostart/<name>.desktop`
#[cfg(target_os = "linux")]
pub fn uninstall_autostart_entry(name: &str) -> PersistenceResult<()> {
    let desktop_path = config_dir()
        .join("autostart")
        .join(format!("{name}.desktop"));

    if desktop_path.exists() {
        std::fs::remove_file(&desktop_path)?;
    }

    Ok(())
}

/// Generate the content of a `.desktop` autostart file as a `String`.
///
/// Pure function — no filesystem access.
#[must_use]
pub fn generate_autostart_entry(name: &str, exec: &str, comment: &str) -> String {
    format!(
        r#"[Desktop Entry]
Type=Application
Name={name}
Exec={exec}
Comment={comment}
X-GNOME-Autostart-enabled=true
"#,
        name = name,
        exec = exec,
        comment = comment,
    )
}

// ---------------------------------------------------------------------------
// Windows stubs – research-only, not testable without a Windows host
// ---------------------------------------------------------------------------

/// Install a Windows Registry Run key (HKCU).
///
/// # Research example
///
/// Adds a value under `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
/// so the program starts automatically at user login. Only available on
/// Windows.
///
/// # Note
///
/// This is a **stub** — the implementation requires the `winreg` crate
/// or raw Win32 API calls and has not been tested on a Windows host.
#[cfg(windows)]
pub fn install_registry_run(name: &str, path: &str) -> PersistenceResult<()> {
    Err(format!(
        "not yet implemented: install_registry_run({name:?}, {path:?}) — requires winreg crate"
    )
    .into())
}

/// Remove a Windows Registry Run key (HKCU).
///
/// # Research example
///
/// Deletes the value under `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`.
///
/// # Note
///
/// This is a **stub** — not yet implemented.
#[cfg(windows)]
pub fn uninstall_registry_run(name: &str) -> PersistenceResult<()> {
    Err(format!("not yet implemented: uninstall_registry_run({name:?})").into())
}

/// Install a Windows Scheduled Task.
///
/// # Research example
///
/// Creates a scheduled task via `schtasks.exe` that runs the given
/// executable at user logon.
///
/// # Note
///
/// This is a **stub** — the implementation requires `schtasks.exe`
/// to be present and has not been tested.
#[cfg(windows)]
pub fn install_scheduled_task(name: &str, path: &str) -> PersistenceResult<()> {
    Err(format!(
        "not yet implemented: install_scheduled_task({name:?}, {path:?}) — requires schtasks.exe"
    )
    .into())
}

/// Remove a Windows Scheduled Task.
///
/// # Research example
///
/// Deletes the scheduled task via `schtasks.exe /delete`.
///
/// # Note
///
/// This is a **stub** — not yet implemented.
#[cfg(windows)]
pub fn uninstall_scheduled_task(name: &str) -> PersistenceResult<()> {
    Err(format!("not yet implemented: uninstall_scheduled_task({name:?})").into())
}

// ---------------------------------------------------------------------------
// Windows stubs – non-Windows builds (do nothing)
// ---------------------------------------------------------------------------

/// Stub for non-Windows: registry operations are meaningless here.
#[cfg(not(windows))]
pub fn install_registry_run(_name: &str, _path: &str) -> PersistenceResult<()> {
    Err("Registry Run keys are only relevant on Windows".into())
}

/// Stub for non-Windows.
#[cfg(not(windows))]
pub fn uninstall_registry_run(_name: &str) -> PersistenceResult<()> {
    Err("Registry Run keys are only relevant on Windows".into())
}

/// Stub for non-Windows.
#[cfg(not(windows))]
pub fn install_scheduled_task(_name: &str, _path: &str) -> PersistenceResult<()> {
    Err("Scheduled tasks are only relevant on Windows".into())
}

/// Stub for non-Windows.
#[cfg(not(windows))]
pub fn uninstall_scheduled_task(_name: &str) -> PersistenceResult<()> {
    Err("Scheduled tasks are only relevant on Windows".into())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn systemd_unit_content_format() {
        let content = generate_systemd_unit(
            "my-agent",
            "/usr/local/bin/my-agent --daemon",
            "My Remote Admin Agent",
        );

        assert!(content.contains("[Unit]"));
        assert!(content.contains("[Service]"));
        assert!(content.contains("[Install]"));
        assert!(content.contains("Description=My Remote Admin Agent"));
        assert!(content.contains("ExecStart=/usr/local/bin/my-agent --daemon"));
        assert!(content.contains("Type=simple"));
        assert!(content.contains("WantedBy=default.target"));

        // Verify the unit path is user-scoped (no mention of /etc/systemd)
        assert!(!content.contains("/etc/systemd"));
    }

    #[test]
    fn crontab_line_format() {
        let line = format_crontab_line("0 5 * * *", "/usr/local/bin/agent --checkin");

        assert_eq!(line, "0 5 * * * /usr/local/bin/agent --checkin\n");

        // Edge: every-minute schedule
        let every_min = format_crontab_line("* * * * *", "true");
        assert_eq!(every_min, "* * * * * true\n");
    }

    #[test]
    fn autostart_desktop_entry_format() {
        let content = generate_autostart_entry(
            "agent-tray",
            "/opt/agent/agent-tray",
            "System management tray icon",
        );

        assert!(content.contains("[Desktop Entry]"));
        assert!(content.contains("Type=Application"));
        assert!(content.contains("Name=agent-tray"));
        assert!(content.contains("Exec=/opt/agent/agent-tray"));
        assert!(content.contains("Comment=System management tray icon"));
        assert!(content.contains("X-GNOME-Autostart-enabled=true"));

        // Verify no system paths leak
        assert!(!content.contains("/etc/xdg"));
        assert!(!content.contains("/usr/share"));
    }

    #[test]
    fn config_dir_resolves_to_user_home() {
        let dir = config_dir();
        // The path should contain `.config` but NOT any system prefix
        // like `/etc`.
        let s = dir.to_string_lossy();
        assert!(s.contains(".config"), "config dir should contain .config");
        assert!(
            !s.contains("/etc/"),
            "config dir should NOT be a system path: {s}"
        );
    }

    #[test]
    fn systemd_unit_no_system_paths() {
        // The unit string must never reference /etc/systemd or /usr/lib/systemd.
        let content = generate_systemd_unit("test", "/bin/true", "test unit");
        assert!(
            !content.contains("/etc/systemd"),
            "unit content must not reference system paths"
        );
        assert!(
            !content.contains("/usr/lib/systemd"),
            "unit content must not reference system paths"
        );
    }

    #[test]
    fn autostart_entry_no_system_paths() {
        let content = generate_autostart_entry("test", "/bin/true", "test entry");
        assert!(
            !content.contains("/etc/xdg"),
            "autostart content must not reference system paths"
        );
    }

    #[test]
    fn windows_stubs_return_error_on_linux() {
        let r1 = install_registry_run("test", "test.exe");
        assert!(r1.is_err(), "registry install should fail on non-Windows");

        let r2 = uninstall_registry_run("test");
        assert!(r2.is_err(), "registry uninstall should fail on non-Windows");

        let r3 = install_scheduled_task("test", "test.exe");
        assert!(r3.is_err(), "scheduled task install should fail on non-Windows");

        let r4 = uninstall_scheduled_task("test");
        assert!(r4.is_err(), "scheduled task uninstall should fail on non-Windows");
    }
}
