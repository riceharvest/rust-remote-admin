/// Screen/audio capture research module (stub).
use std::fmt;

#[derive(Debug, Clone)]
pub enum CaptureError {
    UnsupportedPlatform,
    DeviceNotFound,
    ReadFailed(String),
}

impl fmt::Display for CaptureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedPlatform => write!(f, "platform not supported"),
            Self::DeviceNotFound => write!(f, "device not found"),
            Self::ReadFailed(msg) => write!(f, "read failed: {msg}"),
        }
    }
}

impl std::error::Error for CaptureError {}

#[derive(Debug, Clone)]
pub struct VideoFrame {
    pub data: Vec<u8>,
    pub width: u32,
    pub height: u32,
}

#[derive(Debug, Clone)]
pub struct AudioChunk {
    pub data: Vec<u8>,
    pub sample_rate: u32,
    pub channels: u8,
}

pub fn capture_webcam_frame() -> Result<VideoFrame, CaptureError> {
    Err(CaptureError::UnsupportedPlatform)
}

pub fn capture_microphone() -> Result<Vec<String>, CaptureError> {
    Err(CaptureError::UnsupportedPlatform)
}

pub fn capture_audio_chunk(_device: &str) -> Result<AudioChunk, CaptureError> {
    Err(CaptureError::UnsupportedPlatform)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_error_display_works() {
        assert_eq!(CaptureError::UnsupportedPlatform.to_string(), "platform not supported");
        assert_eq!(CaptureError::DeviceNotFound.to_string(), "device not found");
        assert_eq!(CaptureError::ReadFailed("io".into()).to_string(), "read failed: io");
    }

    #[test]
    fn video_frame_construction() {
        let frame = VideoFrame { data: vec![0u8; 100], width: 10, height: 10 };
        assert_eq!(frame.data.len(), 100);
    }

    #[test]
    fn audio_chunk_construction() {
        let chunk = AudioChunk { data: vec![0u8; 100], sample_rate: 44100, channels: 2 };
        assert_eq!(chunk.sample_rate, 44100);
    }

    #[test]
    fn webcam_capture_returns_unsupported_or_devices() {
        let result = capture_webcam_frame();
        assert!(result.is_err());
    }

    #[test]
    fn microphone_capture_returns_unsupported_or_devices() {
        let result = capture_microphone();
        assert!(result.is_err());
    }

    #[test]
    fn capture_audio_chunk_returns_error_on_stub() {
        let result = capture_audio_chunk("default");
        assert!(result.is_err());
    }
}
