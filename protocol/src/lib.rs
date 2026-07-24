pub mod config;
pub mod messages {
    use serde::{Deserialize, Serialize};

    #[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
    pub enum Command {
        Heartbeat,
        Execute { cmd: String },
        GetSysInfo,
        SelfUpdate { url: String, expected_hash: String },
    }

    #[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
    pub enum Response {
        Success,
        HeartbeatAck,
        Failure { error: String },
        SysInfo {
            cpu_usage: f32,
            mem_free: u64,
            os: String,
        },
        ExecutionResult {
            output: String,
        },
        SelfUpdateResult { success: bool, message: String },
    }
}

/// Framing helpers for length-prefixed JSON messages over async I/O.
pub mod framing {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use std::marker::Unpin;

    const MAX_MESSAGE_SIZE: u32 = 16 * 1024 * 1024; // 16 MiB

    /// Read a JSON-deserializable message from an async reader.
    ///
    /// Wire format: 4-byte little-endian length prefix, then
    /// that many bytes of JSON.
    pub async fn read_message<T, R>(reader: &mut R) -> Result<T, FramingError>
    where
        T: serde::de::DeserializeOwned,
        R: AsyncReadExt + Unpin,
    {
        let mut len_buf = [0u8; 4];
        reader.read_exact(&mut len_buf).await?;
        let len = u32::from_le_bytes(len_buf) as usize;

        if len > MAX_MESSAGE_SIZE as usize {
            return Err(FramingError::TooLarge(len));
        }

        let mut buf = vec![0u8; len];
        reader.read_exact(&mut buf).await?;

        let value: T = serde_json::from_slice(&buf)?;
        Ok(value)
    }

    /// Write a JSON-serializable message to an async writer, length-prefixed.
    pub async fn write_message<T, W>(writer: &mut W, value: &T) -> Result<(), FramingError>
    where
        T: serde::Serialize,
        W: AsyncWriteExt + Unpin,
    {
        let json = serde_json::to_vec(value)?;
        let len = json.len();
        if len > MAX_MESSAGE_SIZE as usize {
            return Err(FramingError::TooLarge(len));
        }
        let len_bytes = (len as u32).to_le_bytes();
        writer.write_all(&len_bytes).await?;
        writer.write_all(&json).await?;
        Ok(())
    }

    #[derive(Debug)]
    pub enum FramingError {
        Io(std::io::Error),
        Json(serde_json::Error),
        TooLarge(usize),
    }

    impl std::fmt::Display for FramingError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::Io(e) => write!(f, "I/O error: {e}"),
                Self::Json(e) => write!(f, "JSON error: {e}"),
                Self::TooLarge(n) => write!(f, "message too large ({n} bytes)"),
            }
        }
    }

    impl std::error::Error for FramingError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            match self {
                Self::Io(e) => Some(e),
                Self::Json(e) => Some(e),
                Self::TooLarge(_) => None,
            }
        }
    }

    impl From<std::io::Error> for FramingError {
        fn from(e: std::io::Error) -> Self { Self::Io(e) }
    }

    impl From<serde_json::Error> for FramingError {
        fn from(e: serde_json::Error) -> Self { Self::Json(e) }
    }
}
