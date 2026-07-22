pub mod messages {
    #[derive(Clone, PartialEq, Debug)]
    pub enum Command {
        Heartbeat,
        Execute { cmd: String },
        GetSysInfo,
        StartRD { quality: u8 },
        InputEvent { key: String, x: i32, y: i32 },
        Custom(u32, Vec<u8>), 
    }

    #[derive(Clone, PartialEq, Debug)]
    pub enum Response {
        Success,
        Failure { error: String },
        SysInfo { 
            cpu_usage: f32, 
            mem_free: u64, 
            os: String 
        },
        ExecutionResult { output: String },
        Frame { data: Vec<u8> },
    }

    #[derive(Clone, PartialEq, Debug)]
    pub struct AgentEvent {
        pub timestamp: u64,
        pub source_id: u32,
        pub event_type: String,
        pub payload: Vec<u8>,
    }
}
