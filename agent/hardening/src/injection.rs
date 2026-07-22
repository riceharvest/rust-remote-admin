/// DLL injection research module (stub).
/// On non-Windows platforms all operations return an error.
use std::fmt;

#[derive(Debug, Clone)]
pub enum InjectionError {
    UnsupportedPlatform,
    OpenProcessFailed,
    AllocationFailed,
    WriteFailed,
    RemoteThreadFailed,
    NotFound,
}

impl fmt::Display for InjectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedPlatform => write!(f, "DLL injection is not supported on this platform"),
            Self::OpenProcessFailed => write!(f, "failed to open target process"),
            Self::AllocationFailed => write!(f, "failed to allocate memory in target process"),
            Self::WriteFailed => write!(f, "failed to write to target process memory"),
            Self::RemoteThreadFailed => write!(f, "failed to create remote thread in target process"),
            Self::NotFound => write!(f, "target process or module not found"),
        }
    }
}

impl std::error::Error for InjectionError {}
