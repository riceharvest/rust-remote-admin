//! Webcam and microphone capture module — research / educational reference.
//!
//! Implements device enumeration and capture-frame helpers for media
//! input devices. All captures are documented research examples and
//! require appropriate permissions (root on Linux for raw device
//! access, Media Foundation on Windows).

use std::fmt;
use std::path::PathBuf;

/// Error type for media capture operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaptureError {
    /// The platform does not support this capture method.
    UnsupportedPlatform,
    /// No device matching the request was found.
    DeviceNotFound,
    /// Device enumeration failed.
    EnumerationFailed,
    /// Opening the device failed (permissions, busy, etc.).
    OpenFailed(String),
    /// Reading a frame/sample failed.
    ReadFailed(String),
    /// Writing output failed.
    WriteFailed(String),
}

impl fmt::Display for CaptureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedPlatform => write!(f, "platform not supported"),
            Self::DeviceNotFound => write!(f, "device not found"),
            Self::EnumerationFailed => write!(f, "device enumeration failed"),
            Self::OpenFailed(msg) => write!(f, "open failed: {msg}"),
            Self::ReadFailed(msg) => write!(f, "read failed: {msg}"),
            Self::WriteFailed(msg) => write!(f, "write failed: {msg}"),
        }
    }
}

impl std::error::Error for CaptureError {}

/// A captured video frame (raw RGB24 pixels).
#[derive(Debug, Clone)]
pub struct VideoFrame {
    pub width: u32,
    pub height: u32,
    pub data: Vec<u8>, // RGB24, length = width*height*3
}

/// A captured audio chunk (raw 16-bit PCM, mono).
#[derive(Debug, Clone)]
pub struct AudioChunk {
    pub sample_rate: u32,
    pub samples: Vec<i16>,
}

/// Information about a discovered media device.
#[derive(Debug, Clone)]
pub struct DeviceInfo {
    pub name: String,
    pub path: PathBuf,
    pub kind: DeviceKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceKind {
    Webcam,
    Microphone,
}

/// Enumerate video capture devices on the system.
///
/// On Linux, looks for `/dev/video*` devices.
/// On Windows, would use Media Foundation's `IMFActivate` enumeration
/// (outlined in doc comments, stubbed here).
pub fn enumerate_webcams() -> Result<Vec<DeviceInfo>, CaptureError> {
    #[cfg(target_os = "linux")]
    {
        let mut devices = Vec::new();
        if let Ok(entries) = std::fs::read_dir("/dev") {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                if name_str.starts_with("video") {
                    devices.push(DeviceInfo {
                        name: format!("/dev/{}", name_str),
                        path: entry.path(),
                        kind: DeviceKind::Webcam,
                    });
                }
            }
        }
        if devices.is_empty() {
            return Err(CaptureError::DeviceNotFound);
        }
        Ok(devices)
    }

    #[cfg(not(target_os = "linux"))]
    {
        Err(CaptureError::UnsupportedPlatform)
    }
}

/// Enumerate audio capture devices on the system.
///
/// On Linux, looks for ALSA capture devices under `/dev/snd/`.
/// On Windows, would use WASAPI's `IMMDeviceEnumerator` (stubbed).
pub fn enumerate_microphones() -> Result<Vec<DeviceInfo>, CaptureError> {
    #[cfg(target_os = "linux")]
    {
        let mut devices = Vec::new();
        if let Ok(entries) = std::fs::read_dir("/dev/snd") {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                if name_str.starts_with("hw") || name_str.contains("pcmC") {
                    devices.push(DeviceInfo {
                        name: format!("/dev/snd/{}", name_str),
                        path: entry.path(),
                        kind: DeviceKind::Microphone,
                    });
                }
            }
        }
        // Always include the default ALSA device as a fallback
        if devices.is_empty() {
            devices.push(DeviceInfo {
                name: "default".into(),
                path: PathBuf::from("/dev/snd/pcmC0D0c"),
                kind: DeviceKind::Microphone,
            });
        }
        Ok(devices)
    }

    #[cfg(not(target_os = "linux"))]
    {
        Err(CaptureError::UnsupportedPlatform)
    }
}

/// Capture a single frame from a webcam.
///
/// On Linux, this would open the V4L2 device, set the format
/// (e.g. `V4L2_PIX_FMT_RGB24`), and call `VIDIOC_DQBUF` to read a
/// frame. This is a research stub — actual V4L2 ioctl calls require
/// the `nix` crate and are outlined in doc comments.
pub fn capture_webcam_frame(_device: &DeviceInfo) -> Result<VideoFrame, CaptureError> {
    // V4L2 capture flow (Linux):
    //   1. open(/dev/videoN) -> fd
    //   2. ioctl(VIDIOC_QUERYCAP) to verify V4L2_CAP_VIDEO_CAPTURE
    //   3. ioctl(VIDIOC_S_FMT) to set width/height/pixfmt = RGB24
    //   4. ioctl(VIDIOC_REQBUFS) to request mmap buffers
    //   5. ioctl(VIDIOC_QBUF) / VIDIOC_DQBUF to dequeue a frame
    //
    // On Windows, the equivalent flow uses Media Foundation:
    //   1. MFCreateDeviceActivation -> IMFActivate
    //   2. Activate -> IMFMediaSource
    //   3. MFCreateSourceReader -> IMFSourceReader
    //   4. ReadSample(MF_SOURCE_READER_FIRST_VIDEO_STREAM)
    Err(CaptureError::UnsupportedPlatform)
}

/// Capture a chunk of audio from a microphone.
///
/// On Linux, this would open the ALSA capture device and read PCM
/// samples. Research stub — actual ALSA calls require the `alsa`
/// crate.
pub fn capture_audio_chunk(_device: &DeviceInfo) -> Result<AudioChunk, CaptureError> {
    // ALSA capture flow (Linux):
    //   1. snd_pcm_open(&handle, "default", SND_PCM_STREAM_CAPTURE, 0)
    //   2. snd_pcm_hw_params_set_access(RW_INTERLEAVED)
    //   3. snd_pcm_hw_params_set_format(SND_PCM_FORMAT_S16_LE)
    //   4. snd_pcm_hw_params_set_channels(1)
    //   5. snd_pcm_hw_params_set_rate(44100)
    //   6. snd_pcm_hw_params / snd_pcm_prepare
    //   7. snd_pcm_readi(buf, frames)
    //
    // On Windows, WASAPI:
    //   1. CoCreateInstance(IMMDeviceEnumerator)
    //   2. GetDefaultAudioEndpoint(eCapture)
    //   3. GetAudioClient -> Initialize(AUDCLNT_STREAMFLAGS_EVENTCALLBACK)
    //   4. GetBuffer / ReleaseBuffer
    Err(CaptureError::UnsupportedPlatform)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_error_display_works() {
        assert_eq!(
            CaptureError::UnsupportedPlatform.to_string(),
            "platform not supported"
        );
        assert_eq!(
            CaptureError::DeviceNotFound.to_string(),
            "device not found"
        );
        assert_eq!(
            CaptureError::ReadFailed("io".into()).to_string(),
            "read failed: io"
        );
    }

    #[test]
    fn video_frame_construction() {
        let frame = VideoFrame {
            width: 2,
            height: 2,
            data: vec![0; 12], // 2*2*3 = 12 bytes
        };
        assert_eq!(frame.data.len(), 12);
        assert_eq!(frame.width * frame.height * 3, 12);
    }

    #[test]
    fn audio_chunk_construction() {
        let chunk = AudioChunk {
            sample_rate: 44100,
            samples: vec![0i16; 1024],
        };
        assert_eq!(chunk.samples.len(), 1024);
        assert_eq!(chunk.sample_rate, 44100);
    }

    #[test]
    fn webcam_capture_returns_unsupported_or_devices() {
        // On Linux this either finds devices or returns DeviceNotFound.
        // On other platforms, returns UnsupportedPlatform.
        let result = enumerate_webcams();
        match result {
            Ok(devices) => {
                // If devices found, they should all be Webcam kind
                for d in &devices {
                    assert_eq!(d.kind, DeviceKind::Webcam);
                }
            }
            Err(e) => {
                assert!(matches!(
                    e,
                    CaptureError::DeviceNotFound | CaptureError::UnsupportedPlatform
                ));
            }
        }
    }

    #[test]
    fn microphone_capture_returns_unsupported_or_devices() {
        let result = enumerate_microphones();
        match result {
            Ok(devices) => {
                for d in &devices {
                    assert_eq!(d.kind, DeviceKind::Microphone);
                }
            }
            Err(e) => {
                assert!(matches!(e, CaptureError::UnsupportedPlatform));
            }
        }
    }

    #[test]
    fn capture_webcam_frame_returns_error_on_stub() {
        let dev = DeviceInfo {
            name: "test".into(),
            path: PathBuf::from("/dev/video0"),
            kind: DeviceKind::Webcam,
        };
        assert!(matches!(
            capture_webcam_frame(&dev),
            Err(CaptureError::UnsupportedPlatform)
        ));
    }

    #[test]
    fn capture_audio_chunk_returns_error_on_stub() {
        let dev = DeviceInfo {
            name: "test".into(),
            path: PathBuf::from("/dev/snd/pcmC0D0c"),
            kind: DeviceKind::Microphone,
        };
        assert!(matches!(
            capture_audio_chunk(&dev),
            Err(CaptureError::UnsupportedPlatform)
        ));
    }
}
