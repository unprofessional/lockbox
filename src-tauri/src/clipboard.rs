//! Copying codes to the macOS clipboard (BRIEF §4, §9, §10).
//!
//! Written straight to NSPasteboard (via objc2, already in Tauri's tree)
//! instead of the clipboard plugin, so that:
//! - the webview gets no clipboard permission at all; Rust copies on `copy_code`;
//! - codes carry the nspasteboard.org Concealed/Transient markers, which
//!   clipboard managers (Raycast, Alfred, Paste, Maccy, …) honor by not
//!   recording them in their history;
//! - codes stay on this Mac: Universal Clipboard (Handoff) won't send them
//!   to the user's iPhone/iPad, where the wipe here could never clear them;
//! - the wipe only clears the clipboard if nothing else was copied since.

use objc2_app_kit::{NSPasteboard, NSPasteboardContentsOptions, NSPasteboardTypeString};
use objc2_foundation::NSString;
use std::time::Duration;

const CONCEALED: &str = "org.nspasteboard.ConcealedType";
const TRANSIENT: &str = "org.nspasteboard.TransientType";

/// Identifies one write of ours, so a later wipe can tell whether the
/// clipboard still holds it.
pub type Stamp = isize;

pub fn copy(text: &str) -> Stamp {
    copy_to(&NSPasteboard::generalPasteboard(), text)
}

pub fn clear_if_unchanged(stamp: Stamp) -> bool {
    clear_if_unchanged_on(&NSPasteboard::generalPasteboard(), stamp)
}

/// Clears our copy after `after`, unless something else was copied since.
pub fn schedule_wipe(stamp: Stamp, after: Duration) {
    std::thread::spawn(move || {
        std::thread::sleep(after);
        clear_if_unchanged(stamp);
    });
}

fn copy_to(pb: &NSPasteboard, text: &str) -> Stamp {
    // Clears the pasteboard like clearContents, and keeps the new contents off
    // Universal Clipboard.
    pb.prepareForNewContentsWithOptions(NSPasteboardContentsOptions::CurrentHostOnly);
    // SAFETY: NSPasteboardTypeString is an immutable AppKit constant.
    let string_type = unsafe { NSPasteboardTypeString };
    pb.setString_forType(&NSString::from_str(text), string_type);
    let empty = NSString::from_str("");
    for marker in [CONCEALED, TRANSIENT] {
        pb.setString_forType(&empty, &NSString::from_str(marker));
    }
    pb.changeCount()
}

fn clear_if_unchanged_on(pb: &NSPasteboard, stamp: Stamp) -> bool {
    if pb.changeCount() == stamp {
        pb.clearContents();
        true
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A private pasteboard, so tests never touch the user's real clipboard.
    fn scratch() -> objc2::rc::Retained<NSPasteboard> {
        NSPasteboard::pasteboardWithUniqueName()
    }

    fn text(pb: &NSPasteboard) -> Option<String> {
        pb.stringForType(unsafe { NSPasteboardTypeString })
            .map(|s| s.to_string())
    }

    fn types(pb: &NSPasteboard) -> Vec<String> {
        pb.types()
            .map(|a| a.iter().map(|t| t.to_string()).collect())
            .unwrap_or_default()
    }

    #[test]
    fn copy_writes_text_and_privacy_markers() {
        let pb = scratch();
        copy_to(&pb, "483920");
        assert_eq!(text(&pb).as_deref(), Some("483920"));
        let t = types(&pb);
        assert!(t.iter().any(|x| x == CONCEALED), "{t:?}");
        assert!(t.iter().any(|x| x == TRANSIENT), "{t:?}");
    }

    #[test]
    fn copy_replaces_previous_contents() {
        // prepareForNewContentsWithOptions must clear like clearContents did,
        // and each copy must get a new stamp.
        let pb = scratch();
        pb.clearContents();
        pb.setString_forType(&NSString::from_str("old"), unsafe { NSPasteboardTypeString });
        let before = pb.changeCount();
        let stamp = copy_to(&pb, "483920");
        assert_ne!(stamp, before);
        assert_eq!(text(&pb).as_deref(), Some("483920"));
        assert_ne!(copy_to(&pb, "111111"), stamp);
    }

    #[test]
    fn wipe_clears_our_copy() {
        let pb = scratch();
        let stamp = copy_to(&pb, "483920");
        assert!(clear_if_unchanged_on(&pb, stamp));
        assert_eq!(text(&pb), None);
    }

    #[test]
    fn wipe_leaves_later_copies_alone() {
        let pb = scratch();
        let stamp = copy_to(&pb, "483920");
        // The user copies something else before the wipe fires.
        pb.clearContents();
        pb.setString_forType(&NSString::from_str("my notes"), unsafe { NSPasteboardTypeString });
        assert!(!clear_if_unchanged_on(&pb, stamp));
        assert_eq!(text(&pb).as_deref(), Some("my notes"));
    }
}
