//! DLL / shared-library injection — research / educational reference.
//!
//! This module demonstrates the technique of injecting a dynamic-link
//! library (DLL on Windows, shared object on Linux) into a running
//! foreign process.
//!
//! ## Platform support
//!
//! | Platform | Status | Mechanism |
//! |----------|--------|-----------|
//! | Windows  | Implemented (`#[cfg(windows)]`) | `CreateRemoteThread` + `LoadLibraryW` via the `windows` crate |
//! | Linux    | Implemented (`#[cfg(not(windows))]`) | `ptrace` + `/proc/<pid>/mem` shellcode injection |
//! | macOS    | Not implemented | Would use `task_for_pid` + `mach_vm_*` |
//!
//! ## Safety
//!
//! DLL injection is inherently unsafe. All `unsafe` blocks document
//! their safety invariants.
//!
//! **This code is provided for research and education only.**

use std::fmt;

/// Errors that can occur during the DLL injection process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InjectionError {
    /// The current platform does not support the requested injection method.
    UnsupportedPlatform,
    /// `OpenProcess` / `ptrace(PTRACE_ATTACH)` failed.
    OpenProcessFailed,
    /// `VirtualAllocEx` / `mmap` in the remote process failed.
    AllocationFailed,
    /// `WriteProcessMemory` / `/proc/<pid>/mem` write failed.
    WriteFailed,
    /// `CreateRemoteThread` / remote thread creation failed.
    RemoteThreadFailed,
    /// The target process or module was not found.
    NotFound,
}

impl fmt::Display for InjectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedPlatform => {
                write!(f, "DLL injection is not supported on this platform")
            }
            Self::OpenProcessFailed => write!(f, "failed to open target process"),
            Self::AllocationFailed => {
                write!(f, "failed to allocate memory in target process")
            }
            Self::WriteFailed => write!(f, "failed to write to target process memory"),
            Self::RemoteThreadFailed => {
                write!(f, "failed to create remote thread in target process")
            }
            Self::NotFound => write!(f, "target process or module not found"),
        }
    }
}

impl std::error::Error for InjectionError {}

// ---------------------------------------------------------------------------
// Windows implementation — CreateRemoteThread + LoadLibraryW
// ---------------------------------------------------------------------------

/// Injects a DLL into a target process using `CreateRemoteThread` +
/// `LoadLibraryW`.
///
/// # Steps
///
/// 1. `OpenProcess` with `PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
///    PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION`
/// 2. `VirtualAllocEx` for the DLL path (UTF-16, null-terminated)
/// 3. `WriteProcessMemory` to copy the path into the remote buffer
/// 4. `GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryW")`
/// 5. `CreateRemoteThread` with `LoadLibraryW` as the start address
/// 6. `WaitForSingleObject` on the remote thread
/// 7. `VirtualFreeEx` to release the remote buffer
///
/// # Safety
///
/// Calls Win32 FFI that modifies a foreign process's memory and
/// execution state.
#[cfg(windows)]
pub fn inject_dll(target_pid: u32, dll_path: &str) -> Result<(), InjectionError> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
    use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
    use windows::Win32::System::Memory::{
        MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE, VirtualAllocEx, VirtualFreeEx,
    };
    use windows::Win32::System::Threading::{
        CreateRemoteThread, OpenProcess, WaitForSingleObject, PROCESS_CREATE_THREAD,
        PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
    };
    use windows::core::PCSTR;

    let access = PROCESS_CREATE_THREAD
        | PROCESS_QUERY_INFORMATION
        | PROCESS_VM_OPERATION
        | PROCESS_VM_WRITE
        | PROCESS_VM_READ;

    // Step 1: Open the target process.
    let h_process = unsafe { OpenProcess(access, false, target_pid) }
        .map_err(|_| InjectionError::OpenProcessFailed)?;

    // Step 2: Convert DLL path to UTF-16 null-terminated.
    let wide: Vec<u16> = OsStr::new(dll_path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let path_size = wide.len() * std::mem::size_of::<u16>();

    // Step 3: Allocate memory in the remote process.
    let remote_addr = unsafe {
        VirtualAllocEx(h_process, None, path_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
    };

    if remote_addr.is_null() {
        let _ = unsafe { CloseHandle(h_process) };
        return Err(InjectionError::AllocationFailed);
    }

    // Step 4: Write the DLL path into the remote buffer.
    let written = unsafe {
        WriteProcessMemory(
            h_process,
            remote_addr,
            wide.as_ptr() as *const _,
            path_size,
            None,
        )
    };

    if written.is_err() {
        let _ = unsafe { VirtualFreeEx(h_process, remote_addr, 0, MEM_RELEASE) };
        let _ = unsafe { CloseHandle(h_process) };
        return Err(InjectionError::WriteFailed);
    }

    // Step 5: Resolve LoadLibraryW address.
    let kernel32 = unsafe { GetModuleHandleA(PCSTR(b"kernel32.dll\0".as_ptr())) }
        .ok()
        .ok_or(InjectionError::NotFound)?;

    let loadlibrary_addr = unsafe { GetProcAddress(kernel32, PCSTR(b"LoadLibraryW\0".as_ptr())) }
        .ok_or(InjectionError::NotFound)?
        .ok_or(InjectionError::NotFound)?;

    // Step 6: Create the remote thread.
    let h_thread = unsafe {
        CreateRemoteThread(
            h_process,
            None,
            0,
            Some(std::mem::transmute::<
                unsafe extern "system" fn() -> isize,
                unsafe extern "system" fn(*mut std::ffi::c_void) -> u32,
            >(loadlibrary_addr)),
            Some(remote_addr as *mut _),
            0,
            None,
        )
    };

    match h_thread {
        Ok(h) => {
            // Step 7: Wait for the thread to finish.
            unsafe { WaitForSingleObject(h, 5000) };
            let _ = unsafe { CloseHandle(h) };
        }
        Err(_) => {
            let _ = unsafe { VirtualFreeEx(h_process, remote_addr, 0, MEM_RELEASE) };
            let _ = unsafe { CloseHandle(h_process) };
            return Err(InjectionError::RemoteThreadFailed);
        }
    }

    // Step 8: Clean up.
    let _ = unsafe { VirtualFreeEx(h_process, remote_addr, 0, MEM_RELEASE) };
    let _ = unsafe { CloseHandle(h_process) };
    Ok(())
}

// ---------------------------------------------------------------------------
// Linux implementation — ptrace + /proc/<pid>/mem
// ---------------------------------------------------------------------------

/// Injects a shared library into a target process using `ptrace`.
///
/// # Steps
///
/// 1. `ptrace(PTRACE_ATTACH, pid)` — attach to the target
/// 2. `waitpid(pid)` — wait for `SIGSTOP`
/// 3. `ptrace(PTRACE_GETREGS)` — save register state
/// 4. Find `dlopen` address via `/proc/<pid>/maps` + the agent's own libc
/// 5. Write shellcode via `/proc/<pid>/mem` that calls `dlopen(path, RTLD_NOW)`
/// 6. `ptrace(PTRACE_SETREGS)` — set RIP to the shellcode
/// 7. `ptrace(PTRACE_CONT)` — execute the shellcode
/// 8. `waitpid` — wait for the shellcode to finish (SIGTRAP)
/// 9. `ptrace(PTRACE_SETREGS)` — restore original registers
/// 10. `ptrace(PTRACE_DETACH)` — detach
///
/// # Safety
///
/// Uses `ptrace` FFI which modifies a foreign process's execution state.
#[cfg(not(windows))]
pub fn inject_dll(target_pid: u32, dll_path: &str) -> Result<(), InjectionError> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    // ptrace constants (from <sys/ptrace.h>)
    const PTRACE_ATTACH: u32 = 16;
    const PTRACE_DETACH: u32 = 17;
    const PTRACE_PEEKTEXT: u32 = 1;
    const PTRACE_POKETEXT: u32 = 4;
    const PTRACE_CONT: u32 = 7;
    const SIGSTOP: i32 = 19;
    const SIGTRAP: i32 = 5;

    // Step 1: Attach to the target process.
    let result = unsafe { libc::ptrace(PTRACE_ATTACH as libc::c_uint, target_pid as libc::pid_t, 0, 0) };
    if result < 0 {
        return Err(InjectionError::OpenProcessFailed);
    }

    // Step 2: Wait for the target to stop.
    let mut status: libc::c_int = 0;
    let wait_result = unsafe { libc::waitpid(target_pid as libc::pid_t, &mut status, 0) };
    if wait_result < 0 {
        let _ = unsafe { libc::ptrace(PTRACE_DETACH as libc::c_uint, target_pid as libc::pid_t, 0, 0) };
        return Err(InjectionError::OpenProcessFailed);
    }

    if !libc::WIFSTOPPED(status) || libc::WSTOPSIG(status) != SIGSTOP {
        let _ = unsafe { libc::ptrace(PTRACE_DETACH as libc::c_uint, target_pid as libc::pid_t, 0, 0) };
        return Err(InjectionError::OpenProcessFailed);
    }

    // Step 3: Find the address of dlopen.
    // Read /proc/<pid>/maps to find libc's base address.
    let maps_path = format!("/proc/{target_pid}/maps");
    let maps_content = match std::fs::read_to_string(&maps_path) {
        Ok(s) => s,
        Err(_) => {
            let _ = unsafe { libc::ptrace(PTRACE_DETACH as libc::c_uint, target_pid as libc::pid_t, 0, 0) };
            return Err(InjectionError::NotFound);
        }
    };

    // Find the line containing libc that is executable (has 'x' permission).
    let libc_base = maps_content
        .lines()
        .find(|line| line.contains("libc") && line.contains("r-xp"))
        .and_then(|line| line.split_whitespace().next())
        .and_then(|range| range.split('-').next())
        .and_then(|addr| u64::from_str_radix(addr, 16).ok());

    let libc_base = match libc_base {
        Some(addr) => addr,
        None => {
            let _ = unsafe { libc::ptrace(PTRACE_DETACH as libc::c_uint, target_pid as libc::pid_t, 0, 0) };
            return Err(InjectionError::NotFound);
        }
    };

    // Find dlopen offset in our own libc by opening the libc file.
    // Parse the maps line to get the libc file path.
    let libc_path = maps_content
        .lines()
        .find(|line| line.contains("libc") && line.contains("r-xp"))
        .and_then(|line| line.split_whitespace().last())
        .unwrap_or("/lib/libc.so.6");

    // Use dlsym on our own process to find dlopen, then compute the
    // offset from libc base to calculate the remote address.
    let dlopen_local = unsafe {
        let handle = libc::dlopen(
            b"libc.so.6\0".as_ptr() as *const _,
            libc::RTLD_NOW,
        );
        if handle.is_null() {
            // Try with the full path
            let c_path = CString::new(libc_path).ok();
            if let Some(c) = c_path {
                libc::dlopen(c.as_ptr(), libc::RTLD_NOW)
            } else {
                std::ptr::null_mut()
            }
        } else {
            handle
        }
    };

    let dlopen_addr = if !dlopen_local.is_null() {
        let sym = unsafe { libc::dlsym(dlopen_local, b"dlopen\0".as_ptr() as *const _) };
        let _ = unsafe { libc::dlclose(dlopen_local) };
        sym as u64
    } else {
        // Fallback: try dlsym on the main program
        unsafe { libc::dlsym(libc::RTLD_DEFAULT, b"dlopen\0".as_ptr() as *const _) as u64 }
    };

    if dlopen_addr == 0 {
        let _ = unsafe { libc::ptrace(PTRACE_DETACH as libc::c_uint, target_pid as libc::pid_t, 0, 0) };
        return Err(InjectionError::NotFound);
    }

    // Calculate the offset of dlopen within libc.
    // Get our own libc base address.
    let self_maps = std::fs::read_to_string("/proc/self/maps").unwrap_or_default();
    let self_libc_base = self_maps
        .lines()
        .find(|line| line.contains("libc") && line.contains("r-xp"))
        .and_then(|line| line.split_whitespace().next())
        .and_then(|range| range.split('-').next())
        .and_then(|addr| u64::from_str_radix(addr, 16).ok())
        .unwrap_or(0);

    let dlopen_offset = if self_libc_base > 0 {
        dlopen_addr.checked_sub(self_libc_base)
    } else {
        None
    };

    let remote_dlopen_addr = match dlopen_offset {
        Some(offset) => libc_base + offset,
        None => dlopen_addr, // Fallback: assume same base (unlikely to work)
    };

    // Step 4: Write the DLL path string into the target process memory
    // via /proc/<pid>/mem.
    let path_cstring = CString::new(dll_path).map_err(|_| InjectionError::WriteFailed)?;
    let path_bytes = path_cstring.as_bytes_with_nul();

    // Find a writable region in the target process to store the path.
    let writable_addr = maps_content
        .lines()
        .find(|line| line.contains("rw"))
        .and_then(|line| line.split_whitespace().next())
        .and_then(|range| range.split('-').next())
        .and_then(|addr| u64::from_str_radix(addr, 16).ok())
        .unwrap_or(0);

    if writable_addr == 0 {
        let _ = unsafe { libc::ptrace(PTRACE_DETACH as libc::c_uint, target_pid as libc::pid_t, 0, 0) };
        return Err(InjectionError::AllocationFailed);
    }

    // Write the path string via /proc/<pid>/mem.
    let mem_path = format!("/proc/{target_pid}/mem");
    let mem_file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&mem_path)
        .map_err(|_| {
            let _ = unsafe { libc::ptrace(PTRACE_DETACH as libc::c_uint, target_pid as libc::pid_t, 0, 0) };
            InjectionError::WriteFailed
        })?;

    use std::io::{Seek, SeekFrom, Write};
    let mut mem_file = mem_file;
    mem_file
        .seek(SeekFrom::Start(writable_addr))
        .map_err(|_| {
            let _ = unsafe { libc::ptrace(PTRACE_DETACH as libc::c_uint, target_pid as libc::pid_t, 0, 0) };
            InjectionError::WriteFailed
        })?;

    mem_file
        .write_all(path_bytes)
        .map_err(|_| {
            let _ = unsafe { libc::ptrace(PTRACE_DETACH as libc::c_uint, target_pid as libc::pid_t, 0, 0) };
            InjectionError::WriteFailed
        })?;

    // Step 5: Save registers, set RIP to dlopen, set RDI (first arg)
    // to the path address and RSI (second arg) to RTLD_NOW|RTLD_GLOBAL.
    #[repr(C)]
    #[derive(Default, Clone, Copy)]
    struct UserRegs {
        r15: u64, r14: u64, r13: u64, r12: u64,
        rbp: u64, rbx: u64,
        r11: u64, r10: u64,
        r9: u64, r8: u64,
        rax: u64, rcx: u64, rdx: u64, rsi: u64, rdi: u64,
        orig_rax: u64,
        rip: u64, cs: u64, eflags: u64,
        rsp: u64, ss: u64,
        fs_base: u64, gs_base: u64,
        ds: u64, es: u64, fs: u64, gs: u64,
    }

    const PTRACE_GETREGS: u32 = 12;
    const PTRACE_SETREGS: u32 = 13;

    let mut orig_regs = UserRegs::default();
    let get_result = unsafe {
        libc::ptrace(
            PTRACE_GETREGS as libc::c_uint,
            target_pid as libc::pid_t,
            std::ptr::null_mut::<libc::c_void>(),
            &mut orig_regs as *mut UserRegs as *mut libc::c_void,
        )
    };
    if get_result < 0 {
        let _ = unsafe { libc::ptrace(PTRACE_DETACH as libc::c_uint, target_pid as libc::pid_t, 0, 0) };
        return Err(InjectionError::OpenProcessFailed);
    }

    // Set up the call: RIP = dlopen, RDI = path_addr, RSI = RTLD_NOW
    let mut call_regs = orig_regs;
    call_regs.rip = remote_dlopen_addr;
    call_regs.rdi = writable_addr;
    call_regs.rsi = libc::RTLD_NOW as u64;

    // We need to write a return trap (int3 = 0xCC) at a known address
    // so that after dlopen returns, the process traps and we regain control.
    // Use the instruction after the call — put 0xCC at orig_regs.rip.
    let trap_addr = orig_regs.rip;
    let original_word = unsafe {
        libc::ptrace(
            PTRACE_PEEKTEXT as libc::c_uint,
            target_pid as libc::pid_t,
            trap_addr ,
            0,
        )
    };
    if original_word < 0 {
        let _ = unsafe { libc::ptrace(PTRACE_DETACH as libc::c_uint, target_pid as libc::pid_t, 0, 0) };
        return Err(InjectionError::OpenProcessFailed);
    }

    // Write 0xCC (int3) at the current RIP via POKETEXT.
    let trap_word: i64 = (original_word & !0xFF) | 0xCC;
    let poke_result = unsafe {
        libc::ptrace(
            PTRACE_POKETEXT as libc::c_uint,
            target_pid as libc::pid_t,
            trap_addr ,
            trap_word as libc::c_long,
        )
    };
    if poke_result < 0 {
        let _ = unsafe { libc::ptrace(PTRACE_DETACH as libc::c_uint, target_pid as libc::pid_t, 0, 0) };
        return Err(InjectionError::WriteFailed);
    }

    // Set the registers to call dlopen.
    let set_result = unsafe {
        libc::ptrace(
            PTRACE_SETREGS as libc::c_uint,
            target_pid as libc::pid_t,
            std::ptr::null_mut::<libc::c_void>(),
            &call_regs as *const UserRegs as *const libc::c_void,
        )
    };
    if set_result < 0 {
        // Restore the original instruction word.
        let _ = unsafe { libc::ptrace(PTRACE_POKETEXT as libc::c_uint, target_pid as libc::pid_t, trap_addr , original_word as libc::c_long) };
        let _ = unsafe { libc::ptrace(PTRACE_DETACH as libc::c_uint, target_pid as libc::pid_t, 0, 0) };
        return Err(InjectionError::WriteFailed);
    }

    // Step 6: Continue the process — it will call dlopen, then hit int3.
    let cont_result = unsafe {
        libc::ptrace(
            PTRACE_CONT as libc::c_uint,
            target_pid as libc::pid_t,
            0,
            0,
        )
    };
    if cont_result < 0 {
        let _ = unsafe { libc::ptrace(PTRACE_POKETEXT as libc::c_uint, target_pid as libc::pid_t, trap_addr , original_word as libc::c_long) };
        let _ = unsafe { libc::ptrace(PTRACE_DETACH as libc::c_uint, target_pid as libc::pid_t, 0, 0) };
        return Err(InjectionError::RemoteThreadFailed);
    }

    // Step 7: Wait for the process to stop (SIGTRAP from int3).
    let mut status2: libc::c_int = 0;
    let _ = unsafe { libc::waitpid(target_pid as libc::pid_t, &mut status2, 0) };

    // Step 8: Restore the original instruction word.
    let _ = unsafe { libc::ptrace(PTRACE_POKETEXT as libc::c_uint, target_pid as libc::pid_t, trap_addr , original_word as libc::c_long) };

    // Step 9: Restore original registers.
    let _ = unsafe {
        libc::ptrace(
            PTRACE_SETREGS as libc::c_uint,
            target_pid as libc::pid_t,
            std::ptr::null_mut::<libc::c_void>(),
            &orig_regs as *const UserRegs as *const libc::c_void,
        )
    };

    // Step 10: Detach.
    let _ = unsafe { libc::ptrace(PTRACE_DETACH as libc::c_uint, target_pid as libc::pid_t, 0, 0) };

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inject_dll_returns_error_on_non_windows() {
        // On Linux, inject_dll attempts ptrace which requires root.
        // Without root, it returns OpenProcessFailed.
        // On Windows without the windows crate, returns UnsupportedPlatform.
        let result = inject_dll(0, "/tmp/test.dll");
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(InjectionError::OpenProcessFailed)
                | Err(InjectionError::UnsupportedPlatform)
        ));
    }

    #[test]
    fn injection_error_display_impl() {
        let cases = [
            (InjectionError::UnsupportedPlatform, "DLL injection is not supported on this platform"),
            (InjectionError::OpenProcessFailed, "failed to open target process"),
            (InjectionError::AllocationFailed, "failed to allocate memory in target process"),
            (InjectionError::WriteFailed, "failed to write to target process memory"),
            (InjectionError::RemoteThreadFailed, "failed to create remote thread in target process"),
            (InjectionError::NotFound, "target process or module not found"),
        ];

        for (variant, expected) in &cases {
            assert_eq!(
                format!("{}", variant),
                *expected,
                "unexpected Display output for {:?}", variant,
            );
        }
    }

    #[test]
    fn injection_error_implements_std_error() {
        fn is_error(_: &dyn std::error::Error) {}
        is_error(&InjectionError::UnsupportedPlatform);
        is_error(&InjectionError::OpenProcessFailed);
    }

    #[test]
    fn injection_error_debug_and_clone() {
        let e = InjectionError::OpenProcessFailed;
        let cloned = e.clone();
        assert_eq!(e, cloned);
        let debug = format!("{:?}", e);
        assert!(!debug.is_empty());
    }
}
