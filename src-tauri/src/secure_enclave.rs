//! Rust side of the Touch ID bridge (M6.1); see swift/secure_enclave.swift.
//!
//! Wrapping the vault key needs only the Secure Enclave key's public half
//! (no fingerprint). Unwrapping needs the chip, which asks for Touch ID.

use std::ffi::CString;
use zeroize::Zeroizing;

pub const PUBLIC_LEN: usize = 65;
pub type WrapKey = Zeroizing<[u8; 32]>;

unsafe extern "C" {
    fn lockbox_se_available() -> bool;
    fn lockbox_se_create(out_blob: *mut *mut u8, out_len: *mut usize, out_public: *mut u8) -> i32;
    fn lockbox_se_wrap_key(se_public: *const u8, out_ephemeral: *mut u8, out_key: *mut u8) -> i32;
    fn lockbox_se_unwrap_key(
        blob: *const u8,
        blob_len: usize,
        ephemeral: *const u8,
        reason: *const std::ffi::c_char,
        out_key: *mut u8,
    ) -> i32;
    fn lockbox_se_free(ptr: *mut u8);
}

#[derive(Debug, PartialEq, Eq)]
pub enum SeError {
    Unavailable,
    Failed,
    Cancelled,
    Lockout,
    /// Fingerprints changed since enrolment, or the key isn't from this Mac.
    KeyInvalid,
}

impl std::fmt::Display for SeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Unavailable => "Touch ID isn't available on this Mac.",
            Self::Failed => "Touch ID didn't work. Use your master password.",
            Self::Cancelled => "Touch ID was cancelled.",
            Self::Lockout => "Touch ID is locked after too many tries. Use your master password.",
            Self::KeyInvalid => {
                "Touch ID unlock stopped working because your fingerprints changed. Use your master password, then turn Touch ID on again in Settings."
            }
        })
    }
}

fn check(status: i32) -> Result<(), SeError> {
    match status {
        0 => Ok(()),
        1 => Err(SeError::Unavailable),
        3 => Err(SeError::Cancelled),
        4 => Err(SeError::Lockout),
        5 => Err(SeError::KeyInvalid),
        _ => Err(SeError::Failed),
    }
}

pub fn available() -> bool {
    // SAFETY: no arguments; pure query.
    unsafe { lockbox_se_available() }
}

/// A new fingerprint-gated Secure Enclave key: (chip-bound blob, public key).
pub fn create_key() -> Result<(Vec<u8>, [u8; PUBLIC_LEN]), SeError> {
    let mut blob = std::ptr::null_mut();
    let mut len = 0usize;
    let mut public = [0u8; PUBLIC_LEN];
    // SAFETY: out-pointers are valid; Swift mallocs `blob`, freed below.
    check(unsafe { lockbox_se_create(&mut blob, &mut len, public.as_mut_ptr()) })?;
    let out = unsafe { std::slice::from_raw_parts(blob, len) }.to_vec();
    unsafe { lockbox_se_free(blob) };
    Ok((out, public))
}

/// (ephemeral public key, wrapping key) for sealing to `se_public`. No prompt.
pub fn wrap_key(se_public: &[u8]) -> Result<([u8; PUBLIC_LEN], WrapKey), SeError> {
    if se_public.len() != PUBLIC_LEN {
        return Err(SeError::KeyInvalid);
    }
    let mut ephemeral = [0u8; PUBLIC_LEN];
    let mut key: WrapKey = Zeroizing::new([0u8; 32]);
    // SAFETY: input is 65 bytes; outputs are 65 and 32 bytes.
    check(unsafe { lockbox_se_wrap_key(se_public.as_ptr(), ephemeral.as_mut_ptr(), key.as_mut_ptr()) })?;
    Ok((ephemeral, key))
}

/// The wrapping key again, from the chip. Shows the Touch ID prompt with
/// `reason` and blocks until the user answers: never call on the main thread.
pub fn unwrap_key(se_blob: &[u8], ephemeral: &[u8], reason: &str) -> Result<WrapKey, SeError> {
    if ephemeral.len() != PUBLIC_LEN {
        return Err(SeError::KeyInvalid);
    }
    let reason = CString::new(reason).map_err(|_| SeError::Failed)?;
    let mut key: WrapKey = Zeroizing::new([0u8; 32]);
    // SAFETY: lengths checked above; reason is NUL-terminated.
    check(unsafe {
        lockbox_se_unwrap_key(
            se_blob.as_ptr(),
            se_blob.len(),
            ephemeral.as_ptr(),
            reason.as_ptr(),
            key.as_mut_ptr(),
        )
    })?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_and_wrap_without_a_prompt() {
        if !available() {
            eprintln!("skipping: no Secure Enclave with Touch ID");
            return;
        }
        let (blob, public) = create_key().unwrap();
        assert!(blob.len() > 100, "chip-bound blob");
        assert_eq!(public[0], 0x04, "uncompressed X9.63 point");
        let (eph1, k1) = wrap_key(&public).unwrap();
        let (eph2, k2) = wrap_key(&public).unwrap();
        assert_ne!(eph1, eph2, "fresh ephemeral key per wrap");
        assert_ne!(*k1, *k2, "so a fresh wrapping key too");
    }

    #[test]
    fn bad_inputs_are_rejected_before_ffi() {
        assert_eq!(wrap_key(&[4u8; 10]).unwrap_err(), SeError::KeyInvalid);
        assert_eq!(unwrap_key(b"blob", &[4u8; 10], "x").unwrap_err(), SeError::KeyInvalid);
    }

    /// Needs a finger on the sensor: `cargo test -- --ignored touch_id_round_trip`.
    #[test]
    #[ignore]
    fn touch_id_round_trip() {
        let (blob, public) = create_key().unwrap();
        let (eph, wrap) = wrap_key(&public).unwrap();
        let unwrapped = unwrap_key(&blob, &eph, "run the lockbox Touch ID test").unwrap();
        assert_eq!(*wrap, *unwrapped);
    }
}
