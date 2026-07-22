use protocol::messages::Response;

fn unsupported(operation: &str) -> Option<Response> {
    Some(Response::Failure {
        error: format!("{operation} is not implemented"),
    })
}

pub mod process_manager {
    use super::unsupported;
    use protocol::messages::{Command, Response};

    pub async fn execute(_cmd: &Command) -> Option<Response> {
        unsupported("process management")
    }
}

pub mod file_manager {
    use super::unsupported;
    use protocol::messages::{Command, Response};

    pub async fn execute(_cmd: &Command) -> Option<Response> {
        unsupported("file management")
    }
}

pub mod registry_manager {
    use super::unsupported;
    use protocol::messages::{Command, Response};

    pub async fn execute(_cmd: &Command) -> Option<Response> {
        unsupported("registry management")
    }
}

pub mod monitoring {
    use super::unsupported;
    use protocol::messages::Response;

    pub async fn get_sysinfo() -> Option<Response> {
        unsupported("system information collection")
    }
}

pub mod execution {
    use super::unsupported;
    use protocol::messages::Response;

    pub async fn execute_remote_cmd(_cmd: &str) -> Option<Response> {
        unsupported("remote command execution")
    }

    pub async fn inject_dll(_path: &str) -> Option<Response> {
        unsupported("DLL injection")
    }

    pub async fn self_update() -> Option<Response> {
        unsupported("self-update")
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
        assert_eq!(
            process_manager::execute(&execute_command("proc:")).await,
            failure("process management")
        );
        assert_eq!(
            file_manager::execute(&execute_command("file:")).await,
            failure("file management")
        );
        assert_eq!(
            registry_manager::execute(&execute_command("reg:")).await,
            failure("registry management")
        );
    }

    #[tokio::test]
    async fn unsupported_monitoring_returns_failure() {
        assert_eq!(
            monitoring::get_sysinfo().await,
            failure("system information collection")
        );
    }

    #[tokio::test]
    async fn dangerous_execution_operations_return_failures() {
        assert_eq!(
            execution::execute_remote_cmd("whoami").await,
            failure("remote command execution")
        );
        assert_eq!(
            execution::inject_dll("payload.dll").await,
            failure("DLL injection")
        );
        assert_eq!(execution::self_update().await, failure("self-update"));
    }
}
