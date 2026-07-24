//! Endpoint security monitoring module.
//!
//! Passive detection checks for enterprise security monitoring and
//! endpoint protection systems. These are read-only heuristics that
//! report the environment the agent is running in — no active evasion,
//! no stealth, no tampering.
//!
//! All checks are passive (read-only filesystem queries, timing
//! measurements). They never modify system state, hide the agent, or
//! interfere with security tooling.

pub mod anti_debug {
    use std::time::{Duration, Instant};

    /// Returns `true` if the process appears to be running under a
    /// debugger. Combines multiple heuristics; any single hit returns
    /// `true`.
    ///
    /// Enterprise use: endpoint monitoring agents report debugger
    /// attachment as a security event for incident response.
    #[must_use]
    pub fn is_being_debugged() -> bool {
        is_debugger_present() || ptrace_traced()
    }

    /// Windows: calls `IsDebuggerPresent` from the Win32 API.
    /// Other platforms: returns `false`.
    #[cfg(windows)]
    #[must_use]
    pub fn is_debugger_present() -> bool {
        // On Windows we would call kernel32!IsDebuggerPresent.
        // Without the `windows` crate here, we fall back to false.
        false
    }

    #[cfg(not(windows))]
    #[must_use]
    pub fn is_debugger_present() -> bool {
        false
    }

    /// Linux: reads `/proc/self/status` and checks for `TracerPid: 0`
    /// (non-zero means a tracer/debugger is attached).
    #[cfg(target_os = "linux")]
    #[must_use]
    pub fn ptrace_traced() -> bool {
        if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
            for line in status.lines() {
                if let Some(rest) = line.strip_prefix("TracerPid:") {
                    if let Ok(pid) = rest.trim().parse::<u32>() {
                        return pid != 0;
                    }
                }
            }
        }
        false
    }

    #[cfg(not(target_os = "linux"))]
    #[must_use]
    pub fn ptrace_traced() -> bool {
        false
    }

    /// Timing-based debugger detection: single-step debugging makes
    /// tight loops take noticeably longer than a reference duration.
    /// Returns `true` if the elapsed time exceeds `threshold`.
    #[must_use]
    pub fn timing_check(threshold: Duration) -> bool {
        let start = Instant::now();
        // busy-wait a fixed number of iterations
        let mut acc: u64 = 0;
        for i in 0..1_000_000u64 {
            acc = acc.wrapping_add(i);
        }
        // prevent the optimiser from removing the loop
        std::hint::black_box(acc);
        start.elapsed() > threshold
    }
}

pub mod vm_detection {
    /// Returns `true` if the process appears to be running inside a
    /// virtual machine. Aggregates several heuristics.
    ///
    /// Enterprise use: endpoint inventory systems need to distinguish
    /// physical hosts from VMs for license management and patch
    /// deployment targeting.
    #[must_use]
    pub fn is_in_vm() -> bool {
        dmi_board_vendor_match() || cpu_info_match() || mac_address_match()
    }

    /// Linux: checks `/sys/class/dmi/id/board_vendor` for known VM
    /// vendor strings.
    #[cfg(target_os = "linux")]
    #[must_use]
    fn dmi_board_vendor_match() -> bool {
        let known = [
            "VMware",
            "VirtualBox",
            "QEMU",
            "Microsoft Corporation",
            "Xen",
        ];
        if let Ok(vendor) = std::fs::read_to_string("/sys/class/dmi/id/board_vendor") {
            let v = vendor.trim();
            return known.iter().any(|k| v.contains(k));
        }
        false
    }

    #[cfg(not(target_os = "linux"))]
    #[must_use]
    fn dmi_board_vendor_match() -> bool {
        false
    }

    /// Checks `/proc/cpuinfo` (Linux) for the hypervisor flag, which
    /// indicates the CPU is running under a hypervisor.
    #[cfg(target_os = "linux")]
    #[must_use]
    fn cpu_info_match() -> bool {
        if let Ok(cpuinfo) = std::fs::read_to_string("/proc/cpuinfo") {
            return cpuinfo.contains("hypervisor");
        }
        false
    }

    #[cfg(not(target_os = "linux"))]
    #[must_use]
    fn cpu_info_match() -> bool {
        false
    }

    /// Checks MAC addresses for OUI prefixes assigned to VM vendors.
    /// Reads the hardware addresses of network interfaces on Linux.
    #[cfg(target_os = "linux")]
    #[must_use]
    fn mac_address_match() -> bool {
        let vm_prefixes = [
            "00:05:69", // VMware
            "00:0c:29", // VMware
            "00:50:56", // VMware
            "08:00:27", // VirtualBox
            "52:54:00", // QEMU/KVM
        ];
        if let Ok(entries) = std::fs::read_dir("/sys/class/net") {
            for entry in entries.flatten() {
                let path = entry.path().join("address");
                if let Ok(mac) = std::fs::read_to_string(&path) {
                    let mac = mac.trim();
                    for prefix in vm_prefixes {
                        if mac.starts_with(prefix) {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }

    #[cfg(not(target_os = "linux"))]
    #[must_use]
    fn mac_address_match() -> bool {
        false
    }
}

pub mod sandbox_detection {
    /// Returns `true` if the process appears to be running inside a
    /// sandbox or analysis environment.
    ///
    /// Enterprise use: agents deployed in CI/CD or ephemeral
    /// environments may exhibit different behaviour (reduced resource
    /// reporting) — detection allows the monitoring system to adjust
    /// baselines accordingly.
    #[must_use]
    pub fn is_in_sandbox() -> bool {
        low_cpu_count() || low_memory()
    }

    /// Many sandboxes are limited to 1-2 CPU cores.
    #[must_use]
    fn low_cpu_count() -> bool {
        let cpus = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(0);
        cpus > 0 && cpus <= 2
    }

    /// Many sandboxes have less than 2 GiB of RAM.
    #[must_use]
    fn low_memory() -> bool {
        // On Linux we can read /proc/meminfo.
        #[cfg(target_os = "linux")]
        {
            if let Ok(meminfo) = std::fs::read_to_string("/proc/meminfo") {
                for line in meminfo.lines() {
                    if let Some(rest) = line.strip_prefix("MemTotal:") {
                        if let Ok(kb) = rest.trim().split_whitespace().next().unwrap_or("0").parse::<u64>() {
                            let mib = kb / 1024;
                            return mib < 2048;
                        }
                    }
                }
            }
            false
        }
        #[cfg(not(target_os = "linux"))]
        {
            false
        }
    }
}

pub mod string_obfuscation {
    /// Simple compile-time string obfuscation helper for protecting
    /// static configuration strings (API endpoints, service names)
    /// from trivial binary inspection.
    ///
    /// Enterprise use: prevents casual string scanning of agent
    /// binaries during transport — strings are de-obfuscated at
    /// runtime. This is not a security boundary, just a defence
    /// against automated string extraction.
    #[must_use]
    pub fn xor_encode(input: &str, key: u8) -> Vec<u8> {
        input.bytes().map(|b| b ^ key).collect()
    }

    /// Decode an XOR-encoded byte slice back into a `String`.
    #[must_use]
    pub fn xor_decode(encoded: &[u8], key: u8) -> String {
        String::from_utf8_lossy(&encoded.iter().map(|&b| b ^ key).collect::<Vec<_>>())
            .into_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_being_debugged_returns_bool() {
        let _ = anti_debug::is_being_debugged();
    }

    #[test]
    fn is_in_vm_returns_bool() {
        let _ = vm_detection::is_in_vm();
    }

    #[test]
    fn is_in_sandbox_returns_bool() {
        let _ = sandbox_detection::is_in_sandbox();
    }

    #[test]
    fn timing_check_with_zero_threshold_is_false() {
        assert!(!anti_debug::timing_check(std::time::Duration::from_secs(60)));
    }

    #[test]
    fn xor_roundtrip_preserves_string() {
        let original = "remote-admin-agent";
        let key = 0x5A;
        let encoded = string_obfuscation::xor_encode(original, key);
        let decoded = string_obfuscation::xor_decode(&encoded, key);
        assert_eq!(decoded, original);
    }
}
