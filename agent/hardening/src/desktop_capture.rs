//! Hidden desktop capture module — research / educational reference.
//!
//! Implements screen-capture helpers for collecting frames from the
//! active display. All captures are documented research examples.
//!
//! On Linux, the research path uses X11/XCB (`XGetImage` / `xcb_shm`)
//! or PipeWire (Wayland session capture via the `pipewire` crate).
//! On Windows, the research path uses GDI `BitBlt` from the desktop
//! DC (`GetDC(NULL)` → `BitBlt` into a DIB section) or the Desktop
//! Duplication API (`IDXGIOutputDuplication`).

use std::fmt;
use std::path::PathBuf;

/// Error type for desktop capture operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaptureError {
    /// The platform does not support desktop capture.
    UnsupportedPlatform,
    /// No display was found.
    NoDisplay,
    /// Opening the display failed.
    OpenFailed(String),
    /// Reading a frame failed.
    ReadFailed(String),
    /// Writing the output file failed.
    WriteFailed(String),
}

impl fmt::Display for CaptureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedPlatform => write!(f, "platform not supported"),
            Self::NoDisplay => write!(f, "no display found"),
            Self::OpenFailed(msg) => write!(f, "open failed: {msg}"),
            Self::ReadFailed(msg) => write!(f, "read failed: {msg}"),
            Self::WriteFailed(msg) => write!(f, "write failed: {msg}"),
        }
    }
}

impl std::error::Error for CaptureError {}

/// A captured screen frame (raw RGB24 pixels).
#[derive(Debug, Clone)]
pub struct ScreenFrame {
    pub width: u32,
    pub height: u32,
    pub data: Vec<u8>,
}

impl ScreenFrame {
    /// Width × height in pixels.
    #[must_use]
    pub fn pixel_count(&self) -> u64 {
        u64::from(self.width) * u64::from(self.height)
    }

    /// Expected data length (width × height × 3 bytes for RGB24).
    #[must_use]
    pub fn expected_data_len(&self) -> usize {
        usize::try_from(self.pixel_count()).unwrap_or(0) * 3
    }
}

/// Information about a discovered display.
#[derive(Debug, Clone)]
pub struct DisplayInfo {
    pub name: String,
    pub width: u32,
    pub height: u32,
    pub source: DisplaySource,
}

/// How the frame was obtained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisplaySource {
    /// X11 / XCB.
    X11,
    /// PipeWire (Wayland screen cast).
    PipeWire,
    /// GDI BitBlt (Windows desktop DC).
    Gdi,
    /// Desktop Duplication API (Windows DXGI).
    Dxgi,
    /// Unknown / not yet determined.
    Unknown,
}

/// Detect which display subsystem is active on the current system.
///
/// - On Linux, checks `$DISPLAY` (X11) and `$WAYLAND_DISPLAY` /
///   `$XDG_SESSION_TYPE` (PipeWire).
/// - On Windows, always returns `Gdi` (BitBlt is universally
///   available; DXGI Desktop Duplication is an upgrade path).
pub fn detect_display_subsystem() -> DisplaySource {
    #[cfg(target_os = "linux")]
    {
        if std::env::var("WAYLAND_DISPLAY").is_ok()
            || std::env::var("XDG_SESSION_TYPE")
                .map(|v| v.eq_ignore_ascii_case("wayland"))
                .unwrap_or(false)
        {
            return DisplaySource::PipeWire;
        }
        if std::env::var("DISPLAY").is_ok() {
            return DisplaySource::X11;
        }
        DisplaySource::Unknown
    }

    #[cfg(windows)]
    {
        DisplaySource::Gdi
    }

    #[cfg(not(any(target_os = "linux", windows)))]
    {
        DisplaySource::Unknown
    }
}

/// Enumerate available displays on the system.
///
/// On Linux, returns the `$DISPLAY` value (or `:0` fallback) if set.
/// On Windows, returns a single `\\.\DISPLAY1` entry (stub).
pub fn enumerate_displays() -> Result<Vec<DisplayInfo>, CaptureError> {
    let source = detect_display_subsystem();
    match source {
        DisplaySource::X11 => {
            let display_name = std::env::var("DISPLAY").unwrap_or_else(|_| ":0".into());
            Ok(vec![DisplayInfo {
                name: display_name,
                width: 0,
                height: 0,
                source,
            }])
        }
        DisplaySource::PipeWire => {
            let display_name =
                std::env::var("WAYLAND_DISPLAY").unwrap_or_else(|_| "wayland-0".into());
            Ok(vec![DisplayInfo {
                name: display_name,
                width: 0,
                height: 0,
                source,
            }])
        }
        DisplaySource::Gdi | DisplaySource::Dxgi => Ok(vec![DisplayInfo {
            name: "\\\\.\\DISPLAY1".into(),
            width: 0,
            height: 0,
            source,
        }]),
        DisplaySource::Unknown => Err(CaptureError::NoDisplay),
    }
}

/// Capture a single frame from the desktop.
///
/// On Linux X11, uses `x11rb` to capture the root window's pixels.
/// Other platforms currently return `Err(UnsupportedPlatform)`.
pub fn capture_desktop_frame() -> Result<ScreenFrame, CaptureError> {
    let source = detect_display_subsystem();
    match source {
        DisplaySource::X11 => capture_x11_frame(),
        DisplaySource::PipeWire
        | DisplaySource::Gdi
        | DisplaySource::Dxgi => Err(CaptureError::UnsupportedPlatform),
        DisplaySource::Unknown => Err(CaptureError::NoDisplay),
    }
}

/// Capture a frame on X11 using `x11rb`.
#[cfg(target_os = "linux")]
fn capture_x11_frame() -> Result<ScreenFrame, CaptureError> {
    use x11rb::connection::Connection;
    use x11rb::protocol::xproto::ConnectionExt;

    // Connect to the X server
    let (conn, screen_num) = x11rb::connect(None)
        .map_err(|e| CaptureError::OpenFailed(format!("X11 connect: {e}")))?;

    let screen = &conn.setup().roots[screen_num];
    let root = screen.root;
    let width = screen.width_in_pixels;
    let height = screen.height_in_pixels;

    // Grab the full-screen image
    let cookie = conn
        .get_image(
            x11rb::protocol::xproto::ImageFormat::Z_PIXMAP,
            root,
            0,   // x offset
            0,   // y offset
            width,
            height,
            !0,  // plane mask: all planes
        )
        .map_err(|e| CaptureError::ReadFailed(format!("get_image send: {e}")))?;

    let reply = cookie
        .reply()
        .map_err(|e| CaptureError::ReadFailed(format!("get_image reply: {e}")))?;

    let raw = reply.data;
    let depth = reply.depth;

    // The X11 GetImage reply is typically in the server's native byte
    // order (little-endian), which means BGR (depth 24) or BGRA (depth 32).
    // Convert to RGB24 by swapping the R and B bytes.
    let data: Vec<u8> = match depth {
        24 => {
            // BGR -> RGB (3 bytes per pixel)
            raw.chunks_exact(3)
                .flat_map(|p| [p[2], p[1], p[0]])
                .collect()
        }
        32 => {
            // BGRA -> RGB (4 bytes per pixel, drop alpha)
            raw.chunks_exact(4)
                .flat_map(|p| [p[2], p[1], p[0]])
                .collect()
        }
        other => {
            // Unknown depth — return as-is (may contain garbage)
            return Err(CaptureError::ReadFailed(format!(
                "unsupported bit depth: {other}"
            )));
        }
    };

    Ok(ScreenFrame {
        width: u32::from(width),
        height: u32::from(height),
        data,
    })
}

/// Stub for non-Linux platforms (x11rb unavailable).
#[cfg(not(target_os = "linux"))]
fn capture_x11_frame() -> Result<ScreenFrame, CaptureError> {
    Err(CaptureError::UnsupportedPlatform)
}

/// Save a `ScreenFrame` as a raw RGB24 file (`.raw`).
///
/// This is a research helper — a production build would encode to
/// PNG/JPEG via the `image` crate.
pub fn save_frame_raw(frame: &ScreenFrame, path: &PathBuf) -> Result<(), CaptureError> {
    use std::io::Write;
    let file = std::fs::File::create(path)
        .map_err(|e| CaptureError::WriteFailed(e.to_string()))?;
    let mut writer = std::io::BufWriter::new(file);
    writer
        .write_all(&frame.data)
        .map_err(|e| CaptureError::WriteFailed(e.to_string()))?;
    writer
        .flush()
        .map_err(|e| CaptureError::WriteFailed(e.to_string()))?;
    Ok(())
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
        assert_eq!(CaptureError::NoDisplay.to_string(), "no display found");
        assert_eq!(
            CaptureError::ReadFailed("io".into()).to_string(),
            "read failed: io"
        );
    }

    #[test]
    fn screen_frame_pixel_count_and_data_len() {
        let frame = ScreenFrame {
            width: 1920,
            height: 1080,
            data: vec![0; 1920 * 1080 * 3],
        };
        assert_eq!(frame.pixel_count(), 2_073_600);
        assert_eq!(frame.expected_data_len(), 6_220_800);
    }

    #[test]
    fn detect_display_subsystem_returns_known_variant() {
        let source = detect_display_subsystem();
        // On the test machine this will be X11, PipeWire, or Unknown.
        assert!(matches!(
            source,
            DisplaySource::X11
                | DisplaySource::PipeWire
                | DisplaySource::Gdi
                | DisplaySource::Dxgi
                | DisplaySource::Unknown
        ));
    }

    #[test]
    fn enumerate_displays_returns_displays_or_no_display() {
        let result = enumerate_displays();
        match result {
            Ok(displays) => assert!(!displays.is_empty()),
            Err(CaptureError::NoDisplay) => {}
            Err(e) => panic!("unexpected error: {e}"),
        }
    }

    #[test]
    fn capture_desktop_frame_returns_error_on_stub() {
        let result = capture_desktop_frame();
        // On a Linux X11 machine, this may now succeed (Ok) or fail to
        // open the X display (OpenFailed). On other platforms it still
        // returns UnsupportedPlatform or NoDisplay.
        assert!(matches!(
            result,
            Ok(_)
                | Err(CaptureError::UnsupportedPlatform)
                | Err(CaptureError::NoDisplay)
                | Err(CaptureError::OpenFailed(_))
        ));
    }

    #[test]
    fn save_frame_raw_writes_file() {
        let frame = ScreenFrame {
            width: 2,
            height: 2,
            data: vec![255; 12],
        };
        let path = PathBuf::from("/tmp/test_desktop_capture.raw");
        save_frame_raw(&frame, &path).unwrap();
        let content = std::fs::read(&path).unwrap();
        assert_eq!(content.len(), 12);
        assert_eq!(content, vec![255; 12]);
        std::fs::remove_file(&path).ok();
    }
}
