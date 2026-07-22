pub mod injection;

pub mod anti_debug {
    /// Checks if the process is currently being debugged.
    #[must_use]
    pub fn is_being_debugged() -> bool {
        // Placeholder for IsDebuggerPresent or similar logic
        false
    }

    /// Checks if the process is running in a virtual machine.
    #[must_use]
    pub fn is_in_vm() -> bool {
        // Placeholder for checking common VM artifacts (e.g., 'VMware', 'VirtualBox')
        false
    }
}

pub mod string_obfuscation {
    /// Example of a simple obfuscated string helper.
    pub const AGENT_ID: &str = "agent_v1"; // In production, this would be encrypted/obfuscated at compile time
}
