//! DLL / shared-library injection — research / educational reference.
//!
//! This module demonstrates the classic technique of injecting a
//! dynamic-link library (DLL on Windows, shared object on Linux) into
//! a running foreign process. The implementation is intentionally
//! **incomplete**: it outlines the API call sequence with detailed
//! doc comments so that the approach can be studied, audited, and
//! adapted for legitimate use cases such as:
//!
//! - Security-tool component injection (EDR/AV user-mode hooks)
//! - Game overlay injection (Steam, Discord)
//! - Diagnostic/profiling agents that must run in another process's
//!   address space
//!
//! ## Platform support
//!
//! | Platform | Status | Mechanism |
//! |----------|--------|-----------|
//! | Windows  | Outlined (`#[cfg(windows)]`) | `CreateRemoteThread` + `LoadLibraryW` |
//! | Linux    | Stub returning `UnsupportedPlatform` | `ptrace`-based `mmap`/`dlopen` sketched in comments |
//! | macOS    | Not implemented | Would use `task_for_pid` + `mach_vm_*` |
//!
//! ## Safety
//!
//! DLL injection is inherently unsafe and should only be performed
//! with **explicit user consent**. The Windows path requires `unsafe`
//! FFI calls to the Win32 API. The Linux ptrace path similarly
//! requires `unsafe` for `libc::ptrace`. All `unsafe` blocks in this
//! module document their safety invariants.
//!
//! **This code is provided for research and education only.**

use std::fmt;

/// Errors that can occur during the DLL injection process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InjectionError {
    /// The current platform does not support the requested injection
    /// method.
    UnsupportedPlatform,

    /// `OpenProcess` failed — the target process could not be opened
    /// with the required access rights.
    OpenProcessFailed,

    /// `VirtualAllocEx` failed — the remote process's address space
    /// could not be allocated for the DLL path string.
    AllocationFailed,

    /// `WriteProcessMemory` failed — the DLL path could not be
    /// written to the remote process's memory.
    WriteFailed,

    /// `CreateRemoteThread` failed — the remote thread that calls
    /// `LoadLibraryW` could not be created.
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
            Self::OpenProcessFailed => {
                write!(f, "failed to open target process")
            }
            Self::AllocationFailed => {
                write!(f, "failed to allocate memory in target process")
            }
            Self::WriteFailed => {
                write!(f, "failed to write to target process memory")
            }
            Self::RemoteThreadFailed => {
                write!(f, "failed to create remote thread in target process")
            }
            Self::NotFound => {
                write!(f, "target process or module not found")
            }
        }
    }
}

impl std::error::Error for InjectionError {}

// ---------------------------------------------------------------------------
// Windows implementation
// ---------------------------------------------------------------------------

/// Injects a DLL into a target process using the classic
/// `CreateRemoteThread` + `LoadLibraryW` technique.
///
/// # Research notes (Windows path)
///
/// The technique proceeds in five steps, each of which is
/// documented in the function body below:
///
/// 1. **`OpenProcess`** — obtain a handle to the target process with
///    `PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
///    PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ`.
///
/// 2. **`VirtualAllocEx`** — allocate memory in the remote process
///    large enough to hold the DLL path as a UTF-16 null-terminated
///    wide string.
///
/// 3. **`WriteProcessMemory`** — write the DLL path into the
///    allocated remote buffer.
///
/// 4. **`GetProcAddress` on `LoadLibraryW`** — resolve the address of
///    `LoadLibraryW` in `kernel32.dll` (the base address is the same
///    across almost all processes on the same Windows version due to
///    `kernel32.dll` being loaded at the same address).
///
/// 5. **`CreateRemoteThread`** — create a new thread in the target
///    process that starts at `LoadLibraryW` with the allocated buffer
///    as its argument. The thread entry point `LoadLibraryW` loads the
///    DLL and calls `DllMain`.
///
/// After injection, a well-behaved injector should wait for the
/// remote thread to exit (`WaitForSingleObject`) and then free the
/// allocated buffer (`VirtualFreeEx`).
///
/// ## Detection evasion considerations
///
/// This classic approach is widely monitored by EDR/AV products.
/// Modern variants avoid `CreateRemoteThread` by using:
///
/// - **SetWindowsHookEx** (thread-agnostic via message hooks)
/// - **QueueUserAPC** (asynchronous procedure calls on existing threads)
/// - **RtlCreateUserThread** (undocumented NT API)
/// - **Thread hijacking** (suspend + set context to shellcode)
///
/// ## Safety
///
/// This function calls Win32 API functions that interact with the
/// target process's memory and execution state. It is unsound if:
/// - `dll_path` is not a valid path to a loadable DLL
/// - `target_pid` has already terminated (zombie process)
/// - The calling process lacks the required privilege level
#[cfg(windows)]
pub fn inject_dll(target_pid: u32, dll_path: &str) -> Result<(), InjectionError> {
    // On a real Windows build with the `windows` crate, the
    // implementation would proceed as follows:
    //
    // ```ignore
    // use windows::Win32::System::Threading::{
    //     OpenProcess, CreateRemoteThread, PROCESS_CREATE_THREAD,
    //     PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION,
    //     PROCESS_VM_WRITE, PROCESS_VM_READ,
    // };
    // use windows::Win32::System::Memory::{
    //     VirtualAllocEx, VirtualFreeEx, MEM_COMMIT, MEM_RESERVE,
    //     PAGE_READWRITE, MEM_RELEASE,
    // };
    // use windows::Win32::System::LibraryLoader::GetProcAddress;
    // use windows::Win32::System::ProcessStatus::K32GetModuleHandleA;
    // use windows::Win32::System::Threading::WaitForSingleObject;
    // use windows::Win32::Foundation::{HANDLE, WAIT_OBJECT_0};
    // use windows::core::PCSTR;
    // use std::ffi::OsStr;
    // use std::os::windows::ffi::OsStrExt;
    //
    // // Step 1: get a handle to the target process with the required
    // // access rights.
    // let access = PROCESS_CREATE_THREAD
    //     | PROCESS_QUERY_INFORMATION
    //     | PROCESS_VM_OPERATION
    //     | PROCESS_VM_WRITE
    //     | PROCESS_VM_READ;
    //
    // let h_process = unsafe {
    //     OpenProcess(access, false, target_pid)
    //         .map_err(|_| InjectionError::OpenProcessFailed)?
    // };
    //
    // // Step 2: convert DLL path to a UTF-16 null-terminated wide
    // // string and calculate the byte size.
    // let wide: Vec<u16> = OsStr::new(dll_path)
    //     .encode_wide()
    //     .chain(std::iter::once(0))
    //     .collect();
    // let path_size = wide.len() * std::mem::size_of::<u16>();
    //
    // // Step 3: allocate memory in the remote process for the path.
    // let remote_addr = unsafe {
    //     VirtualAllocEx(
    //         h_process,
    //         None,
    //         path_size,
    //         MEM_COMMIT | MEM_RESERVE,
    //         PAGE_READWRITE,
    //     )
    // };
    //
    // if remote_addr.is_null() {
    //     return Err(InjectionError::AllocationFailed);
    // }
    //
    // // Step 4: write the DLL path into the remote buffer.
    // let written = unsafe {
    //     WriteProcessMemory(h_process, remote_addr, wide.as_ptr() as *const _, path_size, None)
    // };
    //
    // if !written.as_bool() {
    //     let _ = unsafe { VirtualFreeEx(h_process, remote_addr, 0, MEM_RELEASE) };
    //     return Err(InjectionError::WriteFailed);
    // }
    //
    // // Step 5: resolve the address of LoadLibraryW.
    // let kernel32 = unsafe {
    //     K32GetModuleHandleA(PCSTR(b"kernel32.dll\0".as_ptr()))
    //         .ok_or(InjectionError::NotFound)?
    // };
    //
    // let loadlibrary_addr = unsafe {
    //     GetProcAddress(kernel32, PCSTR(b"LoadLibraryW\0".as_ptr()))
    //         .ok_or(InjectionError::NotFound)?
    // };
    //
    // // Step 6: create a remote thread that calls LoadLibraryW with
    // // the DLL path as its argument.
    // let h_thread = unsafe {
    //     CreateRemoteThread(
    //         h_process,
    //         None,
    //         0,
    //         Some(std::mem::transmute::<_, unsafe extern "system" fn(*mut std::ffi::c_void) -> u32>(
    //             loadlibrary_addr,
    //         )),
    //         Some(remote_addr as *mut _),
    //         0,
    //         None,
    //     )
    //     .map_err(|_| InjectionError::RemoteThreadFailed)?
    // };
    //
    // // Step 7: optionally wait for the remote thread to finish.
    // let _ = unsafe { WaitForSingleObject(h_thread, 5000) };
    //
    // // Step 8: clean up — free the remote buffer.
    // let _ = unsafe { VirtualFreeEx(h_process, remote_addr, 0, MEM_RELEASE) };
    // ```
    //
    // Because we are compiling on Linux without the `windows` crate,
    // this stub simply returns an error:
    let _ = (target_pid, dll_path);
    Err(InjectionError::UnsupportedPlatform)
}

// ---------------------------------------------------------------------------
// Non-Windows stub
// ---------------------------------------------------------------------------

/// Injects a shared library into a target process.
///
/// On non-Windows platforms this returns
/// [`InjectionError::UnsupportedPlatform`].
///
/// ## Research notes (Linux ptrace approach)
///
/// On Linux, there is no `LoadLibrary` equivalent that works across
/// process boundaries. Instead, `ptrace` can be used to:
///
/// 1. **`ptrace(PTRACE_ATTACH)`** — attach to the target process as
///    a tracer. The target receives `SIGSTOP`.
///
/// 2. **`waitpid`** — wait for the target to stop.
///
/// 3. **Get register state** — save the current instruction pointer
///    and general-purpose registers so they can be restored later.
///
/// 4. **`ptrace(PTRACE_PEEKTEXT)`** / **`PTRACE_POKETEXT)`** —
///    inject shellcode into the target's memory that calls:
///
///    - `mmap(NULL, size, PROT_READ|PROT_WRITE|PROT_EXEC,
///      MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)` — allocate executable memory
///    - `dlopen(path, RTLD_NOW|RTLD_LOCAL)` — load the shared object
///      (requires knowing the address of `dlopen` in libc, which may
///      be obtained from `/proc/<pid>/maps` or by reading
///      `libc.so`'s base address)
///
/// 5. **Restore registers** — set the registers back to their saved
///    state and detach.
///
/// 6. **`ptrace(PTRACE_DETACH)`** — detach from the target, letting
///    it resume normally.
///
/// This approach is more invasive than the Windows
/// `CreateRemoteThread` path because `ptrace` stops the target
/// process entirely and modifies its execution state. It is also
/// detectable by anti-debugging checks (see `anti_debug::ptrace_traced`).
///
/// A more modern alternative on Linux is to use `/proc/<pid>/mem`
/// combined with `process_vm_writev` (available since Linux 3.2) to
/// write shellcode without `ptrace`, but you still need `ptrace` to
/// execute it unless you can hijack an existing thread via signals.
#[cfg(not(windows))]
pub fn inject_dll(target_pid: u32, dll_path: &str) -> Result<(), InjectionError> {
    let _ = (target_pid, dll_path);
    Err(InjectionError::UnsupportedPlatform)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inject_dll_returns_error_on_non_windows() {
        // On Linux this always returns UnsupportedPlatform.
        // On Windows this stub also returns UnsupportedPlatform because
        // the `windows` crate is not present in test builds.
        let result = inject_dll(0, "/tmp/test.dll");
        assert_eq!(result, Err(InjectionError::UnsupportedPlatform));
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
                "unexpected Display output for {:?}",
                variant,
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
