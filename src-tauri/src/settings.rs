//! Plaintext app settings (BRIEF §11 M1). Nothing secret ever goes in here.

use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{self, Write};
use std::path::Path;

pub const AUTO_LOCK_MINUTES: std::ops::RangeInclusive<u32> = 1..=120;
pub const CLIPBOARD_WIPE_SECONDS: std::ops::RangeInclusive<u32> = 5..=300;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Theme {
    #[default]
    System,
    Light,
    Dark,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub auto_lock_minutes: u32,
    pub clipboard_wipe_seconds: u32,
    pub theme: Theme,
    /// Lock when the window is minimized or the app is hidden (M6).
    pub lock_on_hide: bool,
    /// Keep codes out of the accessibility tree, so screen readers and
    /// accessibility-driven agents can't read them (M6, BRIEF §9).
    pub hide_codes_from_accessibility: bool,
    /// Ask for Touch ID before every copy (M6.1). Only applies while Touch ID
    /// unlock is set up.
    pub touch_id_to_copy: bool,
    /// Ask for Touch ID automatically when the user comes back to a locked
    /// lockbox (M6.1). Launch always asks.
    pub touch_id_on_return: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            auto_lock_minutes: 5,
            clipboard_wipe_seconds: 30,
            theme: Theme::System,
            lock_on_hide: false,
            hide_codes_from_accessibility: false,
            touch_id_to_copy: false,
            touch_id_on_return: true,
        }
    }
}

impl Settings {
    pub fn validate(&self) -> Result<(), String> {
        if !AUTO_LOCK_MINUTES.contains(&self.auto_lock_minutes) {
            return Err(format!(
                "auto-lock must be between {} and {} minutes",
                AUTO_LOCK_MINUTES.start(),
                AUTO_LOCK_MINUTES.end()
            ));
        }
        if !CLIPBOARD_WIPE_SECONDS.contains(&self.clipboard_wipe_seconds) {
            return Err(format!(
                "clipboard wipe must be between {} and {} seconds",
                CLIPBOARD_WIPE_SECONDS.start(),
                CLIPBOARD_WIPE_SECONDS.end()
            ));
        }
        Ok(())
    }
}

/// Missing, unreadable, malformed or out-of-range files all fall back to
/// defaults. The bad file is left on disk until the next successful save.
pub fn load(path: &Path) -> Settings {
    let Ok(raw) = fs::read_to_string(path) else {
        return Settings::default();
    };
    match serde_json::from_str::<Settings>(&raw) {
        Ok(s) if s.validate().is_ok() => s,
        _ => Settings::default(),
    }
}

/// Atomic write: tmp file → fsync → rename.
pub fn save(path: &Path, settings: &Settings) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("json.tmp");
    let json = serde_json::to_vec_pretty(settings)?;
    let mut f = fs::File::create(&tmp)?;
    f.write_all(&json)?;
    f.sync_all()?;
    fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_file_gives_defaults() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(load(&dir.path().join("settings.json")), Settings::default());
    }

    #[test]
    fn save_then_load_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested/settings.json");
        let s = Settings {
            auto_lock_minutes: 15,
            clipboard_wipe_seconds: 10,
            theme: Theme::Dark,
            lock_on_hide: true,
            hide_codes_from_accessibility: true,
            touch_id_to_copy: true,
            touch_id_on_return: false,
        };
        save(&path, &s).unwrap();
        assert_eq!(load(&path), s);
        assert!(!path.with_extension("json.tmp").exists());
    }

    #[test]
    fn malformed_file_gives_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        fs::write(&path, "{not json").unwrap();
        assert_eq!(load(&path), Settings::default());
    }

    #[test]
    fn out_of_range_file_gives_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        fs::write(&path, r#"{"auto_lock_minutes": 0}"#).unwrap();
        assert_eq!(load(&path), Settings::default());
    }

    #[test]
    fn missing_fields_take_defaults() {
        let s: Settings = serde_json::from_str(r#"{"theme": "light"}"#).unwrap();
        assert_eq!(s.theme, Theme::Light);
        assert_eq!(s.auto_lock_minutes, 5);
        assert_eq!(s.clipboard_wipe_seconds, 30);
        assert!(!s.lock_on_hide && !s.hide_codes_from_accessibility, "M4-era files get the M6 defaults");
        assert!(s.touch_id_on_return, "on unless turned off");
    }

    #[test]
    fn validate_enforces_ranges() {
        let mut s = Settings::default();
        assert!(s.validate().is_ok());
        s.auto_lock_minutes = 121;
        assert!(s.validate().is_err());
        s.auto_lock_minutes = 5;
        s.clipboard_wipe_seconds = 4;
        assert!(s.validate().is_err());
    }
}
