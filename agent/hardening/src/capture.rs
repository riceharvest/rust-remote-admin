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
                        name: format!("/dev/{name_str}"),
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
                        name: format!("/dev/snd/{name_str}"),
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

// ─── V4L2 constants and structures (Linux only) ─────────────────────────────

#[cfg(target_os = "linux")]
mod v4l2 {
    #![allow(non_snake_case, non_camel_case_types, dead_code)]

    // V4L2 ioctl codes (from kernel headers on x86_64 Linux).
    // Computed from _IOR/_IOWR/_IOW using kernel struct sizes verified
    // via `sizeof` on this platform.
    pub const VIDIOC_QUERYCAP: libc::c_ulong = 0x80685600;
    pub const VIDIOC_S_FMT: libc::c_ulong = 0xc0d05605;
    pub const VIDIOC_REQBUFS: libc::c_ulong = 0xc0145608;
    pub const VIDIOC_QUERYBUF: libc::c_ulong = 0xc0585609;
    pub const VIDIOC_QBUF: libc::c_ulong = 0xc058560f;
    pub const VIDIOC_DQBUF: libc::c_ulong = 0xc0585611;
    pub const VIDIOC_STREAMON: libc::c_ulong = 0x40045612;
    pub const VIDIOC_STREAMOFF: libc::c_ulong = 0x40045613;

    // V4L2 constants
    pub const V4L2_CAP_VIDEO_CAPTURE: u32 = 0x00000001;
    pub const V4L2_BUF_TYPE_VIDEO_CAPTURE: u32 = 1;
    pub const V4L2_MEMORY_MMAP: u32 = 1;
    pub const V4L2_FIELD_NONE: u32 = 1;
    // v4l2_fourcc('R', 'G', 'B', '3') = 0x33424752
    pub const V4L2_PIX_FMT_RGB24: u32 = 0x33424752;

    /// Matches `struct v4l2_capability` (104 bytes on x86_64).
    #[repr(C)]
    #[derive(Default)]
    pub struct v4l2_capability {
        pub driver: [u8; 16],
        pub card: [u8; 32],
        pub bus_info: [u8; 32],
        pub version: u32,
        pub capabilities: u32,
        pub device_caps: u32,
        pub reserved: [u32; 3],
    }

    /// Matches `struct v4l2_pix_format` (48 bytes on x86_64).
    #[repr(C)]
    #[derive(Default, Clone)]
    pub struct v4l2_pix_format {
        pub width: u32,
        pub height: u32,
        pub pixelformat: u32,
        pub field: u32,
        pub bytesperline: u32,
        pub sizeimage: u32,
        pub colorspace: u32,
        pub priv_: u32,
        pub flags: u32,
        pub ycbcr_enc: u32,
        pub quantization: u32,
        pub xfer_func: u32,
    }

    /// Matches `struct v4l2_format` (208 bytes on x86_64).
    /// Layout: type (u32) + 4-byte pad + 200-byte union.
    #[repr(C)]
    pub struct v4l2_format {
        pub typ: u32,
        pub _pad: [u8; 4],
        pub fmt: v4l2_pix_format,
        pub _reserved: [u8; 152], // union filler: 200 - 48 = 152
    }

    /// Matches `struct v4l2_requestbuffers` (20 bytes on x86_64).
    #[repr(C)]
    #[derive(Default)]
    pub struct v4l2_requestbuffers {
        pub count: u32,
        pub typ: u32,
        pub memory: u32,
        pub capabilities: u32,
        pub reserved: [u32; 1],
    }

    /// Matches `struct v4l2_buffer` (88 bytes on x86_64).
    ///
    /// The kernel struct contains a `struct timeval` with two `long`
    /// fields (8 bytes each on LP64), and a union `m` whose largest
    /// member is `unsigned long userptr` (8 bytes).
    #[repr(C)]
    #[derive(Default)]
    pub struct v4l2_buffer {
        pub index: u32,
        pub typ: u32,
        pub bytesused: u32,
        pub flags: u32,
        pub field: u32,
        pub _pad1: [u8; 4],           // align timestamp to 8 bytes
        pub timestamp_sec: i64,       // struct timeval.tv_sec
        pub timestamp_usec: i64,      // struct timeval.tv_usec
        pub timecode_type: u32,       // struct v4l2_timecode (16 bytes)
        pub timecode_flags: u32,
        pub timecode_frames: u8,
        pub timecode_seconds: u8,
        pub timecode_minutes: u8,
        pub timecode_hours: u8,
        pub timecode_userbits: [u8; 4],
        pub sequence: u32,
        pub memory: u32,
        // union m { __u32 offset; unsigned long userptr; ... } — 8 bytes
        pub m_offset: u32,
        pub _m_pad: u32,
        pub length: u32,
        pub reserved2: u32,
        pub request_fd: i32,
        pub _reserved: u32,
    }
}

// ─── Implementation ─────────────────────────────────────────────────────────

/// Capture a single frame from a webcam.
///
/// On Linux, opens the V4L2 device, sets format to RGB24 at 640×480,
/// and dequeues one frame via `VIDIOC_DQBUF`.
#[cfg(target_os = "linux")]
pub fn capture_webcam_frame(device: &DeviceInfo) -> Result<VideoFrame, CaptureError> {
    use std::os::unix::io::IntoRawFd;
    use v4l2::*;

    // Open device – V4L2 needs read-write for S_FMT / REQBUFS / QBUF
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&device.path)
        .map_err(|e| CaptureError::OpenFailed(format!("{}: {}", device.path.display(), e)))?;

    let fd = file.into_raw_fd();

    // Helper: close `fd` then return an error
    macro_rules! bail {
        ($variant:ident, $msg:expr) => {{
            unsafe { libc::close(fd) };
            return Err(CaptureError::$variant(format!(
                "{} (device: {})",
                $msg,
                device.path.display()
            )));
        }};
    }

    // ── 1. VIDIOC_QUERYCAP – verify this is a video-capture device ──────────
    let mut cap: v4l2_capability = unsafe { std::mem::zeroed() };
    if unsafe { libc::ioctl(fd, VIDIOC_QUERYCAP, &mut cap) } < 0 {
        bail!(
            ReadFailed,
            format!("VIDIOC_QUERYCAP: {}", std::io::Error::last_os_error())
        );
    }
    if cap.capabilities & V4L2_CAP_VIDEO_CAPTURE == 0 {
        bail!(ReadFailed, "device does not support video capture".to_string());
    }

    // ── 2. VIDIOC_S_FMT – set format to RGB24, 640×480 ─────────────────────
    let mut fmt: v4l2_format = unsafe { std::mem::zeroed() };
    fmt.typ = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    fmt.fmt.width = 640;
    fmt.fmt.height = 480;
    fmt.fmt.pixelformat = V4L2_PIX_FMT_RGB24;
    fmt.fmt.field = V4L2_FIELD_NONE;

    if unsafe { libc::ioctl(fd, VIDIOC_S_FMT, &mut fmt) } < 0 {
        bail!(
            ReadFailed,
            format!("VIDIOC_S_FMT: {}", std::io::Error::last_os_error())
        );
    }

    // ── 3. VIDIOC_REQBUFS – request 1 mmap buffer ──────────────────────────
    let mut req: v4l2_requestbuffers = unsafe { std::mem::zeroed() };
    req.count = 1;
    req.typ = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    req.memory = V4L2_MEMORY_MMAP;

    if unsafe { libc::ioctl(fd, VIDIOC_REQBUFS, &mut req) } < 0 || req.count < 1 {
        bail!(
            ReadFailed,
            format!("VIDIOC_REQBUFS: {}", std::io::Error::last_os_error())
        );
    }

    // ── 4. VIDIOC_QUERYBUF – get the mmap offset and length ────────────────
    let mut buf: v4l2_buffer = unsafe { std::mem::zeroed() };
    buf.index = 0;
    buf.typ = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    buf.memory = V4L2_MEMORY_MMAP;

    if unsafe { libc::ioctl(fd, VIDIOC_QUERYBUF, &mut buf) } < 0 {
        bail!(
            ReadFailed,
            format!("VIDIOC_QUERYBUF: {}", std::io::Error::last_os_error())
        );
    }

    let map_len = buf.length as usize;
    let map_offset = buf.m_offset as libc::off_t;

    // ── 5. mmap the buffer ─────────────────────────────────────────────────
    let map_ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            map_len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd,
            map_offset,
        )
    };
    if map_ptr == libc::MAP_FAILED {
        bail!(
            ReadFailed,
            format!("mmap: {}", std::io::Error::last_os_error())
        );
    }

    // ── 6. VIDIOC_QBUF – queue the (empty) buffer into the driver ──────────
    let mut qbuf: v4l2_buffer = unsafe { std::mem::zeroed() };
    qbuf.index = 0;
    qbuf.typ = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    qbuf.memory = V4L2_MEMORY_MMAP;
    if unsafe { libc::ioctl(fd, VIDIOC_QBUF, &mut qbuf) } < 0 {
        unsafe { libc::munmap(map_ptr, map_len) };
        bail!(
            ReadFailed,
            format!("VIDIOC_QBUF: {}", std::io::Error::last_os_error())
        );
    }

    // ── 7. VIDIOC_STREAMON – start streaming ────────────────────────────────
    let type_val = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    if unsafe { libc::ioctl(fd, VIDIOC_STREAMON, &type_val) } < 0 {
        unsafe { libc::munmap(map_ptr, map_len) };
        bail!(
            ReadFailed,
            format!("VIDIOC_STREAMON: {}", std::io::Error::last_os_error())
        );
    }

    // ── 8. VIDIOC_DQBUF – dequeue a filled frame (blocks until ready) ──────
    let mut dqbuf: v4l2_buffer = unsafe { std::mem::zeroed() };
    dqbuf.typ = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    dqbuf.memory = V4L2_MEMORY_MMAP;
    if unsafe { libc::ioctl(fd, VIDIOC_DQBUF, &mut dqbuf) } < 0 {
        unsafe { libc::munmap(map_ptr, map_len) };
        let _ = unsafe { libc::ioctl(fd, VIDIOC_STREAMOFF, &type_val) };
        bail!(
            ReadFailed,
            format!("VIDIOC_DQBUF: {}", std::io::Error::last_os_error())
        );
    }

    // ── 9. Copy frame data from the mmap'd buffer ──────────────────────────
    let frame_size = (640 * 480 * 3) as usize;
    let rgb_data = unsafe {
        std::slice::from_raw_parts(map_ptr as *const u8, frame_size.min(map_len)).to_vec()
    };

    // ── 10. Clean up ────────────────────────────────────────────────────────
    let _ = unsafe { libc::ioctl(fd, VIDIOC_STREAMOFF, &type_val) };
    unsafe { libc::munmap(map_ptr, map_len) };
    unsafe { libc::close(fd) };

    Ok(VideoFrame {
        width: 640,
        height: 480,
        data: rgb_data,
    })
}

/// Capture a single frame from a webcam (non-Linux stub).
#[cfg(not(target_os = "linux"))]
pub fn capture_webcam_frame(_device: &DeviceInfo) -> Result<VideoFrame, CaptureError> {
    Err(CaptureError::UnsupportedPlatform)
}

/// Capture a chunk of audio from a microphone.
///
/// On Linux, shells out to `arecord` to capture 1 second of 16-bit
/// mono PCM at 44100 Hz, then parses the raw bytes into `i16` samples.
#[cfg(target_os = "linux")]
pub fn capture_audio_chunk(device: &DeviceInfo) -> Result<AudioChunk, CaptureError> {
    // Determine the ALSA device name.  The enumerated path may be under
    // /dev/snd/ but arecord expects ALSA names like "default" or "hw:0,0".
    let alsa_device = if device.name == "default" {
        "default"
    } else if device.path.starts_with("/dev/snd/") {
        device
            .path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("default")
    } else {
        &device.name
    };

    let output = std::process::Command::new("arecord")
        .args([
            "-D",
            alsa_device,
            "-d",
            "1",
            "-f",
            "S16_LE",
            "-r",
            "44100",
            "-c",
            "1",
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .map_err(|e| CaptureError::ReadFailed(format!("failed to spawn arecord: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(CaptureError::ReadFailed(format!(
            "arecord failed ({}): {}",
            output.status,
            stderr.trim()
        )));
    }

    // Parse raw bytes as little-endian i16 samples
    let raw = output.stdout;
    let samples: Vec<i16> = raw
        .chunks_exact(2)
        .map(|c| i16::from_le_bytes([c[0], c[1]]))
        .collect();

    if samples.is_empty() {
        return Err(CaptureError::ReadFailed(
            "arecord produced no audio data".into(),
        ));
    }

    Ok(AudioChunk {
        sample_rate: 44100,
        samples,
    })
}

/// Capture a chunk of audio from a microphone (non-Linux stub).
#[cfg(not(target_os = "linux"))]
pub fn capture_audio_chunk(_device: &DeviceInfo) -> Result<AudioChunk, CaptureError> {
    Err(CaptureError::UnsupportedPlatform)
}

// ─── Tests ──────────────────────────────────────────────────────────────────

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
    fn capture_webcam_frame_may_fail_or_succeed() {
        // On Linux this will try to open /dev/video0. If no webcam is
        // connected / accessible it returns an OpenFailed or ReadFailed
        // error. On other platforms it returns UnsupportedPlatform.
        let dev = DeviceInfo {
            name: "test".into(),
            path: PathBuf::from("/dev/video0"),
            kind: DeviceKind::Webcam,
        };
        let result = capture_webcam_frame(&dev);
        #[cfg(target_os = "linux")]
        {
            match result {
                Ok(frame) => {
                    assert_eq!(frame.width, 640);
                    assert_eq!(frame.height, 480);
                    assert_eq!(frame.data.len(), 640 * 480 * 3);
                }
                Err(e) => {
                    assert!(
                        matches!(e, CaptureError::OpenFailed(_) | CaptureError::ReadFailed(_)),
                        "expected OpenFailed or ReadFailed, got {e:?}"
                    );
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            assert!(matches!(result, Err(CaptureError::UnsupportedPlatform)));
        }
    }

    #[test]
    fn capture_audio_chunk_may_fail_or_succeed() {
        let dev = DeviceInfo {
            name: "default".into(),
            path: PathBuf::from("/dev/snd/pcmC0D0c"),
            kind: DeviceKind::Microphone,
        };
        let result = capture_audio_chunk(&dev);
        #[cfg(target_os = "linux")]
        {
            match result {
                Ok(chunk) => {
                    assert_eq!(chunk.sample_rate, 44100);
                    assert!(!chunk.samples.is_empty());
                }
                Err(e) => {
                    assert!(
                        matches!(e, CaptureError::ReadFailed(_)),
                        "expected ReadFailed, got {e:?}"
                    );
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            assert!(matches!(result, Err(CaptureError::UnsupportedPlatform)));
        }
    }
}
