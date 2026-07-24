pub mod config;
pub mod messages {
    use serde::{Deserialize, Serialize};

    #[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
    pub enum Command {
        Heartbeat,
        Execute { cmd: String },
        GetSysInfo,
    }

    #[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
    pub enum Response {
        Success,
        Failure { error: String },
        SysInfo {
            cpu_usage: f32,
            mem_free: u64,
            os: String,
        },
        ExecutionResult {
            output: String,
        },
    }
}
