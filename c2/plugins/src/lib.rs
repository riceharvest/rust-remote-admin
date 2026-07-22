pub trait C2Plugin {
    fn on_load(&mut self);
    fn on_command(&mut self, cmd: &protocol::messages::Command) -> Option<protocol::messages::Response>;
    fn get_commands(&self) -> Vec<String>;
}

// Example Plugin Implementation for a simple "Echo" command
pub struct EchoPlugin;

impl C2Plugin for EchoPlugin {
    fn on_load(&mut self) {}
    fn on_command(&mut self, cmd: &protocol::messages::Command) -> Option<protocol::messages::Response> {
        if let protocol::messages::Command::Execute { cmd } = cmd {
            return Some(protocol::messages::Response::ExecutionResult {
                output: format!("Echoing: {cmd}"),
            });
        }
        None
    }
    fn get_commands(&self) -> Vec<String> {
        vec!["echo".to_string()]
    }
}
