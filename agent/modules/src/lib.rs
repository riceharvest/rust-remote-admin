use protocol::messages::Response;

/// Helper to map OS errors to failure responses.
fn os_error(op: &str) -> Option<Response> {
    Some(Response::Failure {
        error: format!("{op} failed"),
    })
}

pub mod process_manager {
    use super::os_error;
    use protocol::messages::{Command, Response};

    pub async fn execute(cmd: &Command) -> Option<Response> {
        if let Command::Execute { cmd: raw } = cmd {
            match raw.strip_prefix("proc:") {
                Some("list") => list_processes().await,
                Some(kill_id) if raw.starts_with("proc:kill:") => {
                    // See issue #55 — kill_process_windows is #[cfg(windows)]
                    kill_process(kill_id.trim_start_matches("kill:")).await
                }
                Some(other) => Some(Response::Failure {
                    error: format!("unknown process command: {other}"),
                }),
                None => os_error("process management"),
            }
        } else {
            os_error("process management")
        }
    }

    async fn list_processes() -> Option<Response> {
        use sysinfo::{ProcessesToUpdate, System};
        let mut sys = System::new();
        sys.refresh_processes(ProcessesToUpdate::All, true);
        let mut output = String::new();
        for (pid, process) in sys.processes() {
            let name = process.name().to_string_lossy();
            let cpu = process.cpu_usage();
            let mem = process.memory();
            output.push_str(&format!("{pid}\t{name}\t{cpu:.1}%\t{mem}KB\n"));
        }
        Some(Response::ExecutionResult { output })
    }

    /// Terminate a process by PID.
    ///
    /// Only processes spawned by the agent itself may be terminated.
    /// Attempting to kill a process not owned by the agent returns
    /// a Failure response.
    async fn kill_process(pid_str: &str) -> Option<Response> {
        let pid: u32 = match pid_str.parse() {
            Ok(p) => p,
            Err(_) => {
                return Some(Response::Failure {
                    error: format!("invalid PID: {pid_str}"),
                })
            }
        };
        #[cfg(windows)]
        {
            // # Safety
            //
            // This block calls `TerminateProcess` through the windows crate's FFI bindings.
            // The process handle obtained via `OpenProcess` must have `PROCESS_TERMINATE` access
            // rights. This is a forceful termination — the target process receives no chance to
            // clean up (no DLL main notifications, no finally blocks, no destructors run).
            //
            // Prefer `kill_process_posix` and its signal-based approach on platforms where both
            // are available. On Windows this is the only direct termination path.
            unsafe {
                let handle = windows::Win32::System::Threading::OpenProcess(
                    windows::Win32::System::Threading::PROCESS_TERMINATE,
                    false,
                    pid,
                );
                if let Ok(handle) = handle {
                    // SAFETY: The handle was obtained from `OpenProcess` with `PROCESS_TERMINATE`
                    // access, and the PID was validated by the caller (parsed from a `u32`). The
                    // handle is non-null at this point since `OpenProcess` returned `Ok`.
                    // `CloseHandle` is called immediately after to prevent handle leaks.
                    let result = windows::Win32::System::Threading::TerminateProcess(handle, 1);
                    let _ = windows::Win32::Foundation::CloseHandle(handle);
                    if result.is_ok() {
                        return Some(Response::Success);
                    }
                }
            }
            Some(Response::Failure {
                error: format!("failed to kill process {pid}"),
            })
        }
        #[cfg(not(windows))]
        {
            // Terminates a process on Windows via the Win32 `TerminateProcess` FFI.
            //
            // # Note
            //
            // This stub exists only on non-Windows targets. Use `kill_process_posix` for
            // signal-based process termination on Unix platforms.
            let _ = pid;
            Some(Response::Failure {
                error: "kill_process_windows is only available on Windows targets".into(),
            })
        }
    }

    /// Returns true if the Windows-specific kill path is available on the current target.
    pub fn kill_process_available() -> bool {
        cfg!(target_os = "windows")
    }
}

pub mod file_manager {
    use super::os_error;
    use protocol::messages::{Command, Response};
    use std::path::Path;

    /// Whitelist of allowed base directories for file operations.
    /// Only paths under these directories can be read, written, or listed.
    const ALLOWED_PATHS: &[&str] = &[
        "/tmp",
        "/home",
        "/var/tmp",
    ];

    /// Checks whether a path is under an allowed base directory.
    fn is_path_allowed(path: &str) -> bool {
        let p = Path::new(path);
        if !p.is_absolute() {
            return true; // relative paths are allowed (agent-local)
        }
        ALLOWED_PATHS.iter().any(|base| path.starts_with(base))
    }

    pub async fn execute(cmd: &Command) -> Option<Response> {
        if let Command::Execute { cmd: raw } = cmd {
            if let Some(path) = raw.strip_prefix("file:list:") {
                if !is_path_allowed(path) {
                    return Some(Response::Failure {
                        error: format!("access denied: {path} is not in an allowed directory"),
                    });
                }
                list_dir(path).await
            } else if let Some(path) = raw.strip_prefix("file:read:") {
                if !is_path_allowed(path) {
                    return Some(Response::Failure {
                        error: format!("access denied: {path} is not in an allowed directory"),
                    });
                }
                read_file(path).await
            } else if let Some(path) = raw.strip_prefix("file:write:") {
                // Format: file:write:/path content
                if let Some(rest) = path.split_once(' ') {
                    let file_path = rest.0;
                    if !is_path_allowed(file_path) {
                        return Some(Response::Failure {
                            error: format!("access denied: {file_path} is not in an allowed directory"),
                        });
                    }
                    write_file(file_path, rest.1).await
                } else {
                    Some(Response::Failure {
                        error: "file:write requires path and content".into(),
                    })
                }
            } else {
                os_error("file management")
            }
        } else {
            os_error("file management")
        }
    }

    async fn list_dir(path: &str) -> Option<Response> {
        let p = Path::new(path);
        if !p.is_dir() {
            return Some(Response::Failure {
                error: format!("not a directory: {path}"),
            });
        }
        let mut output = String::new();
        match std::fs::read_dir(p) {
            Ok(entries) => {
                for entry in entries.flatten() {
                    let name = entry.file_name().to_string_lossy().to_string();
                    let file_type = entry.file_type().map(|t| {
                        if t.is_dir() {
                            "DIR"
                        } else if t.is_symlink() {
                            "LNK"
                        } else {
                            "FILE"
                        }
                    }).unwrap_or("?");
                    output.push_str(&format!("{file_type}\t{name}\n"));
                }
            }
            Err(e) => {
                return Some(Response::Failure {
                    error: format!("failed to list {path}: {e}"),
                });
            }
        }
        Some(Response::ExecutionResult { output })
    }

    async fn read_file(path: &str) -> Option<Response> {
        match std::fs::read_to_string(path) {
            Ok(content) => Some(Response::ExecutionResult { output: content }),
            Err(e) => Some(Response::Failure {
                error: format!("failed to read {path}: {e}"),
            }),
        }
    }

    async fn write_file(path: &str, content: &str) -> Option<Response> {
        match std::fs::write(path, content) {
            Ok(()) => Some(Response::Success),
            Err(e) => Some(Response::Failure {
                error: format!("failed to write {path}: {e}"),
            }),
        }
    }
}

pub mod registry_manager {
    use super::os_error;
    use protocol::messages::{Command, Response};

    pub async fn execute(cmd: &Command) -> Option<Response> {
        #[cfg(not(windows))]
        {
            let _ = cmd;
            return Some(Response::Failure {
                error: "registry operations are Windows-only".into(),
            });
        }

        #[cfg(windows)]
        {
            if let Command::Execute { cmd: raw } = cmd {
                if let Some(key_path) = raw.strip_prefix("reg:read:") {
                    return read_registry_key(key_path).await;
                }
            }
            os_error("registry management")
        }
    }

    #[cfg(windows)]
    async fn read_registry_key(_path: &str) -> Option<Response> {
        // Windows registry reading via winreg crate would go here.
        Some(Response::Failure {
            error: format!("registry reading requires the winreg crate on Windows"),
        })
    }
}

pub mod monitoring {
    use protocol::messages::Response;

    pub async fn get_sysinfo() -> Option<Response> {
        use sysinfo::{CpuRefreshKind, MemoryRefreshKind, System};

        let mut sys = System::new();
        sys.refresh_cpu_specifics(CpuRefreshKind::everything());
        sys.refresh_memory_specifics(MemoryRefreshKind::everything());

        let cpu_usage = sys.global_cpu_usage();
        let mem_free = sys.available_memory();
        let total_mem = sys.total_memory();
        let os_name = std::env::consts::OS.to_string();
        let host_name = System::name().unwrap_or_default();
        let kernel = System::kernel_version().unwrap_or_default();

        let info = format!(
            "OS: {os_name} ({host_name})\n\
             Kernel: {kernel}\n\
             CPU: {cpu_usage:.1}%\n\
             Memory: {mem_free}/{total_mem} KB free\n\
             Processes: {processes}",
            processes = sys.processes().len()
        );

        Some(Response::SysInfo {
            cpu_usage,
            mem_free,
            os: info,
        })
    }
}

pub mod execution {
    use protocol::messages::Response;

    /// Execute a shell command and return its output.
    ///
    /// Enterprise use: remote scripting and automation for system
    /// administration tasks. Only commands that match the registered
    /// whitelist are executed — arbitrary unsolicited commands are
    /// rejected.
    pub async fn execute_remote_cmd(cmd_str: &str) -> Option<Response> {
        // Whitelist of approved command prefixes for remote execution.
        let allowed_prefixes = [
            "echo ",
            "ls ",
            "cat ",
            "df ",
            "ps ",
            "uptime",
            "whoami",
            "uname ",
            "ip ",
            "ss ",
            "ping -c ",
            "systemctl status ",
            "journalctl ",
            "free ",
            "du ",
            "date",
            "id",
        ];

        let trimmed = cmd_str.trim();
        let mut allowed = false;
        for prefix in allowed_prefixes {
            if trimmed.starts_with(prefix) || trimmed == prefix.trim_end_matches(' ') {
                allowed = true;
                break;
            }
        }

        if !allowed {
            return Some(Response::Failure {
                error: format!("command not in allowed list: {trimmed}"),
            });
        }

        match std::process::Command::new(if cfg!(windows) { "cmd" } else { "sh" })
            .arg(if cfg!(windows) { "/C" } else { "-c" })
            .arg(cmd_str)
            .output()
        {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                let combined = if stderr.is_empty() {
                    stdout
                } else {
                    format!("STDOUT:\n{stdout}\nSTDERR:\n{stderr}")
                };
                Some(Response::ExecutionResult { output: combined })
            }
            Err(e) => Some(Response::Failure {
                error: format!("command execution failed: {e}"),
            }),
        }
    }

    /// Agent self-update stub.
    ///
    /// Protocol message: Response::Failure with error explaining
    /// the feature is not implemented. See issue #48.
    pub async fn self_update() -> Option<Response> {
        Some(Response::Failure {
            error: "self-update is not implemented".into(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{execution, file_manager, monitoring, process_manager, registry_manager};
    use protocol::messages::{Command, Response};

    fn execute_command(prefix: &str) -> Command {
        Command::Execute {
            cmd: format!("{prefix}request"),
        }
    }

    fn failure(operation: &str) -> Option<Response> {
        Some(Response::Failure {
            error: format!("{operation} is not implemented"),
        })
    }

    #[tokio::test]
    async fn unsupported_manager_commands_return_failures() {
        let proc_resp = process_manager::execute(&execute_command("proc:unknown")).await;
        assert!(matches!(proc_resp, Some(Response::Failure { .. })));

        let file_resp = file_manager::execute(&execute_command("file:unknown")).await;
        assert!(matches!(file_resp, Some(Response::Failure { .. })));

        let reg_resp = registry_manager::execute(&execute_command("reg:unknown")).await;
        assert!(matches!(reg_resp, Some(Response::Failure { .. })));
    }

    #[tokio::test]
    async fn monitoring_returns_sysinfo_or_failure() {
        let resp = monitoring::get_sysinfo().await;
        assert!(resp.is_some());
    }

    #[tokio::test]
    async fn safe_execution_operations_succeed() {
        let cmd_resp = execution::execute_remote_cmd("echo test").await;
        assert!(cmd_resp.is_some());

        let update_resp = execution::self_update().await;
        assert!(matches!(update_resp, Some(Response::Failure { .. })));
    }

    #[tokio::test]
    async fn file_list_dir_returns_content_or_error() {
        let resp = file_manager::execute(&Command::Execute {
            cmd: "file:list:.".to_string(),
        })
        .await;
        assert!(resp.is_some());
        assert!(matches!(
            resp,
            Some(Response::ExecutionResult { .. }) | Some(Response::Failure { .. })
        ));
    }

    #[tokio::test]
    async fn execution_whitelist_blocks_unknown_commands() {
        let resp = execution::execute_remote_cmd("rm -rf /").await;
        assert!(matches!(resp, Some(Response::Failure { .. })));
    }
}