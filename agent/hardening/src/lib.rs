/// Compile-time macro: XOR-obfuscates a string literal.
/// Call `obf!()?` with the key as optional marker; expands to runtime deobfuscation.
macro_rules! obf {
    ($s:expr) => {{
        const KEY: u8 = 0xAB;
        const INPUT: &[u8] = $s.as_bytes();
        const OBF_LEN: usize = INPUT.len();
        const OBF_DATA: [u8; OBF_LEN] = {
            let mut buf = [0u8; OBF_LEN];
            let mut i = 0;
            while i < OBF_LEN {
                buf[i] = INPUT[i] ^ KEY;
                i += 1;
            }
            buf
        };
        // Deobfuscate at runtime
        let mut out = [0u8; OBF_LEN];
        let mut i = 0;
        while i < OBF_LEN {
            out[i] = OBF_DATA[i] ^ KEY;
            i += 1;
        }
        unsafe { std::str::from_utf8_unchecked(&out) }
    }};
}

pub mod anti_debug {
    /// Checks if the process is currently being debugged.
    pub fn is_being_debugged() -> bool {
        // Placeholder for IsDebuggerPresent or similar logic
        false
    }

    /// Checks if the process is running in a virtual machine.
    pub fn is_in_vm() -> bool {
        // Placeholder for checking common VM artifacts (e.g., 'VMware', 'VirtualBox')
        false
    }
}

pub mod string_obfuscation {
    /// Agent identifier; obfuscated at compile time.
    pub fn agent_id() -> &'static str {
        obf!("agent_v1")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn obf_string_matches_plaintext() {
        let s = obf!("hello");
        assert_eq!(s, "hello");
    }

    #[test]
    fn obf_includes_non_plain_bytes_in_binary() {
        const KEY: u8 = 0xAB;
        let plain = b"test";
        let expected_obf: [u8; 4] = [plain[0] ^ KEY, plain[1] ^ KEY, plain[2] ^ KEY, plain[3] ^ KEY];
        let decoded = obf!("test");
        assert_eq!(decoded, "test");
        // Verify we're not storing plaintext
        for (i, &b) in decoded.as_bytes().iter().enumerate() {
            assert_ne!(b, plain[i], "byte {} appears un-obfuscated at rest", i);
        }
    }
}
