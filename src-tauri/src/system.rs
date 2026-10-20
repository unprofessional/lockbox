//! macOS hardening hooks (BRIEF §6.4, §9, M6), straight on AppKit/Carbon
//! (already in Tauri's tree), no plugins:
//! - lock when the Mac sleeps, the displays sleep, the screen locks, the
//!   screensaver starts, or another user session takes over;
//! - a global panic hotkey (⌃⌥⌘L) that locks from any app, via Carbon's
//!   RegisterEventHotKey, which needs no Accessibility permission;
//! - keep the window out of screenshots, recordings and screen sharing.

use block2::RcBlock;
use objc2_app_kit::{
    NSWindow, NSWindowSharingType, NSWorkspace, NSWorkspaceScreensDidSleepNotification,
    NSWorkspaceSessionDidResignActiveNotification, NSWorkspaceWillSleepNotification,
};
use objc2_foundation::{NSDistributedNotificationCenter, NSNotification, NSNotificationCenter, NSString};
use std::ffi::c_void;
use std::ptr::{NonNull, null_mut};
use std::sync::{Arc, OnceLock};
use tauri::{Runtime, WebviewWindow};

/// Distributed notifications posted by loginwindow and the screensaver.
const SCREEN_LOCKED: &str = "com.apple.screenIsLocked";
const SCREENSAVER_STARTED: &str = "com.apple.screensaver.didstart";

/// Calls `on_lock` on any of the system events above, for the app's lifetime.
pub fn lock_on_system_events(on_lock: impl Fn() + Send + Sync + 'static) {
    let on_lock: Arc<dyn Fn() + Send + Sync> = Arc::new(on_lock);
    let observe = |center: &NSNotificationCenter, name: &NSString| {
        let f = on_lock.clone();
        let block = RcBlock::new(move |_: NonNull<NSNotification>| f());
        // SAFETY: no object filter, no queue (delivered on the posting
        // thread), and the block only calls a Send + Sync closure.
        let token =
            unsafe { center.addObserverForName_object_queue_usingBlock(Some(name), None, None, &block) };
        // Observers live as long as the app; dropping the token is harmless,
        // keeping it avoids any doubt about the registration's lifetime.
        std::mem::forget(token);
    };

    let workspace = NSWorkspace::sharedWorkspace().notificationCenter();
    // SAFETY: immutable AppKit constants.
    let names = unsafe {
        [
            NSWorkspaceWillSleepNotification,
            NSWorkspaceScreensDidSleepNotification,
            NSWorkspaceSessionDidResignActiveNotification,
        ]
    };
    for name in names {
        observe(&workspace, name);
    }

    let distributed = NSDistributedNotificationCenter::defaultCenter();
    for name in [SCREEN_LOCKED, SCREENSAVER_STARTED] {
        observe(&distributed, &NSString::from_str(name));
    }
}

// ---- Carbon global hotkey ----

#[repr(C)]
struct EventTypeSpec {
    event_class: u32,
    event_kind: u32,
}

#[repr(C)]
struct EventHotKeyId {
    signature: u32,
    id: u32,
}

type EventHandler = unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void) -> i32;

#[link(name = "Carbon", kind = "framework")]
unsafe extern "C" {
    fn GetApplicationEventTarget() -> *mut c_void;
    fn InstallEventHandler(
        target: *mut c_void,
        handler: EventHandler,
        num_types: u32,
        types: *const EventTypeSpec,
        user_data: *mut c_void,
        out_ref: *mut *mut c_void,
    ) -> i32;
    fn RegisterEventHotKey(
        key_code: u32,
        modifiers: u32,
        id: EventHotKeyId,
        target: *mut c_void,
        options: u32,
        out_ref: *mut *mut c_void,
    ) -> i32;
}

const EVENT_CLASS_KEYBOARD: u32 = u32::from_be_bytes(*b"keyb");
const EVENT_HOTKEY_PRESSED: u32 = 5;
const KEY_L: u32 = 0x25; // kVK_ANSI_L
const CMD: u32 = 1 << 8;
const OPTION: u32 = 1 << 11;
const CONTROL: u32 = 1 << 12;
const HOTKEY_TAKEN: i32 = -9878; // eventHotKeyExistsErr

pub const PANIC_HOTKEY_LABEL: &str = "⌃⌥⌘L";

static PANIC: OnceLock<Box<dyn Fn() + Send + Sync>> = OnceLock::new();

unsafe extern "C" fn on_hotkey(_: *mut c_void, _: *mut c_void, _: *mut c_void) -> i32 {
    if let Some(f) = PANIC.get() {
        f();
    }
    0 // noErr
}

/// Registers ⌃⌥⌘L system-wide. Must run on the main thread (Tauri's setup
/// does). Fails if another app already owns the combination.
pub fn register_panic_hotkey(on_press: impl Fn() + Send + Sync + 'static) -> Result<(), String> {
    PANIC
        .set(Box::new(on_press))
        .map_err(|_| "panic hotkey already registered".to_string())?;
    let spec = EventTypeSpec {
        event_class: EVENT_CLASS_KEYBOARD,
        event_kind: EVENT_HOTKEY_PRESSED,
    };
    // SAFETY: plain Carbon calls with valid pointers; the handler is a
    // 'static fn and touches only the OnceLock above.
    unsafe {
        let target = GetApplicationEventTarget();
        let status = InstallEventHandler(target, on_hotkey, 1, &spec, null_mut(), null_mut());
        if status != 0 {
            return Err(format!("couldn't install the hotkey handler (error {status})"));
        }
        let mut hotkey = null_mut();
        let id = EventHotKeyId {
            signature: u32::from_be_bytes(*b"lkbx"),
            id: 1,
        };
        match RegisterEventHotKey(KEY_L, CMD | OPTION | CONTROL, id, target, 0, &mut hotkey) {
            0 => Ok(()),
            HOTKEY_TAKEN => Err(format!("{PANIC_HOTKEY_LABEL} is already used by another app")),
            status => Err(format!("couldn't register {PANIC_HOTKEY_LABEL} (error {status})")),
        }
    }
}

/// Keeps the window out of screenshots, screen recordings and screen
/// sharing: they show it blank. Must run on the main thread.
pub fn hide_from_capture<R: Runtime>(window: &WebviewWindow<R>) -> Result<(), String> {
    let ptr = window
        .ns_window()
        .map_err(|e| format!("couldn't reach the window: {e}"))?;
    // SAFETY: Tauri returns this window's live NSWindow, and setup runs on
    // the main thread as AppKit requires.
    let ns_window: &NSWindow = unsafe { &*(ptr as *const NSWindow) };
    ns_window.setSharingType(NSWindowSharingType::None);
    Ok(())
}
