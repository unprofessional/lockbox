//! Encrypted vault (BRIEF §6).
//!
//! Key hierarchy, designed so Touch ID (§6.3) slots in without a migration:
//!
//!   master password --argon2id--> KEK --wraps--> VK --encrypts--> payload
//!
//! VK is a random 256-bit vault key. Today only the password-derived KEK
//! wraps it (`key_wrap`); a Keychain-held wrap can be added beside it later.
//! Both layers are AES-256-GCM with a fresh 96-bit random nonce per seal.

use aes_gcm::aead::{Aead, Generate, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use crate::otp::{self, Algo, Kind, NewEntry};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub const FORMAT_VERSION: u32 = 1;
pub const MIN_PASSWORD_CHARS: usize = 8;
pub const MAX_BACKUP_BYTES: usize = 10 * 1024 * 1024;

const KDF_ALGO: &str = "argon2id";
const CIPHER_ALGO: &str = "aes-256-gcm";
const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const SALT_LEN: usize = 16;
// Domain-separate the two GCM layers so one ciphertext can't stand in for the other.
const AAD_KEY_WRAP: &[u8] = b"lockbox/v1/key-wrap";
const AAD_PAYLOAD: &[u8] = b"lockbox/v1/payload";
const AAD_TOUCH_ID: &[u8] = b"lockbox/v1/touch-id";
const BIOMETRIC_ALGO: &str = "secure-enclave-p256-ecdh-hkdf-sha256+aes-256-gcm";

type Key = Zeroizing<[u8; KEY_LEN]>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

impl KdfParams {
    /// BRIEF §6.2. Recorded in every envelope, so changing this later only
    /// affects vaults created or re-keyed afterwards.
    pub const DEFAULT: Self = Self {
        m_kib: 64 * 1024,
        t: 3,
        p: 4,
    };

    /// Bounds on params read from disk, so a tampered file can't make unlock
    /// allocate gigabytes or spin for minutes before failing.
    fn check(&self) -> Result<(), VaultError> {
        let ok = (1..=16).contains(&self.p)
            && (8 * self.p..=1024 * 1024).contains(&self.m_kib)
            && (1..=20).contains(&self.t);
        if ok {
            Ok(())
        } else {
            Err(VaultError::Corrupt("KDF parameters out of range".into()))
        }
    }
}

/// A TOTP/HOTP account. Lives only inside the decrypted payload; never crosses
/// IPC with its seed (BRIEF §5).
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Entry {
    pub id: String,
    pub issuer: String,
    pub account: String,
    pub seed_b32: String,
    pub digits: u32,
    pub period: u32,
    #[zeroize(skip)]
    pub algorithm: Algo,
    #[zeroize(skip)]
    pub kind: Kind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counter: Option<u64>,
    pub added_at: u64,
    #[serde(default)]
    pub tags: Vec<String>,
}

// ---- on-disk envelope (BRIEF §6.1) ----

#[derive(Serialize, Deserialize)]
struct Envelope {
    version: u32,
    kdf: KdfHeader,
    key_wrap: SealedHeader,
    cipher: CipherHeader,
    payload: String,
    created_at: u64,
    updated_at: u64,
    /// Touch ID (M6.1, BRIEF §6.3): the vault key sealed again under a key
    /// only this Mac's Secure Enclave can re-derive, after a fingerprint.
    /// Older lockbox versions ignore the field; backups never carry it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    biometric: Option<BiometricWrap>,
}

#[derive(Clone, Serialize, Deserialize)]
struct BiometricWrap {
    algo: String,
    /// Opaque, chip-bound Secure Enclave key (useless on another Mac).
    se_key: String,
    /// Its public half, so a new vault key can be re-wrapped without a prompt.
    se_public: String,
    /// Ephemeral ECDH public key for this wrap.
    ephemeral: String,
    nonce: String,
    ciphertext: String,
}

#[derive(Serialize, Deserialize)]
struct KdfHeader {
    algo: String,
    m_kib: u32,
    t: u32,
    p: u32,
    salt: String,
}

#[derive(Clone, Serialize, Deserialize)]
struct SealedHeader {
    algo: String,
    nonce: String,
    ciphertext: String,
}

#[derive(Serialize, Deserialize)]
struct CipherHeader {
    algo: String,
    nonce: String,
}

#[derive(Debug)]
pub enum VaultError {
    AlreadyExists,
    NotFound,
    WrongPassword,
    WeakPassword,
    /// Payload failed GCM authentication even though the key unwrapped.
    Tampered,
    Corrupt(String),
    UnsupportedVersion(u32),
    NoSuchEntry,
    /// Touch ID unlock couldn't produce the vault key.
    Biometric(String),
    Invalid(String),
    Io(io::Error),
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyExists => write!(f, "a vault already exists"),
            Self::NotFound => write!(f, "no vault found"),
            Self::WrongPassword => write!(f, "wrong password"),
            Self::WeakPassword => write!(
                f,
                "password must be at least {MIN_PASSWORD_CHARS} characters"
            ),
            Self::Tampered => write!(f, "vault failed integrity check (modified or damaged)"),
            Self::Corrupt(why) => write!(f, "vault file is unreadable: {why}"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported vault version {v}"),
            Self::Biometric(why) => write!(f, "{why}"),
            Self::NoSuchEntry => write!(f, "no such account"),
            Self::Invalid(why) => write!(f, "{why}"),
            Self::Io(e) => write!(f, "vault I/O error: {e}"),
        }
    }
}

impl From<io::Error> for VaultError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// An unlocked vault. Dropping it is locking it: the vault key and every
/// entry (seeds included) are zeroized.
pub struct Vault {
    path: PathBuf,
    vault_key: Key,
    kdf: KdfParams,
    salt: [u8; SALT_LEN],
    key_wrap: SealedHeader,
    created_at: u64,
    entries: Vec<Entry>,
    biometric: Option<BiometricWrap>,
}

impl Vault {
    pub fn exists(path: &Path) -> bool {
        path.exists()
    }

    pub fn create(path: &Path, password: &str, kdf: KdfParams) -> Result<Self, VaultError> {
        check_password(password)?;
        if path.exists() {
            return Err(VaultError::AlreadyExists);
        }
        let vault_key: Key = Zeroizing::new(<[u8; KEY_LEN]>::generate());
        let salt = <[u8; SALT_LEN]>::generate();
        let key_wrap = wrap_key(&vault_key, password, &salt, &kdf)?;
        let mut vault = Self {
            path: path.to_path_buf(),
            vault_key,
            kdf,
            salt,
            key_wrap,
            created_at: now(),
            entries: Vec::new(),
            biometric: None,
        };
        vault.save()?;
        Ok(vault)
    }

    pub fn unlock(path: &Path, password: &str) -> Result<Self, VaultError> {
        let raw = match fs::read(path) {
            Ok(raw) => raw,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(VaultError::NotFound),
            Err(e) => return Err(e.into()),
        };
        let mut vault = Self::open_raw(&raw, password)?;
        vault.path = path.to_path_buf();
        Ok(vault)
    }

    /// Decrypts an envelope (a vault file or a backup) held in memory. The
    /// returned vault has no path; callers set one or only read entries.
    fn open_raw(raw: &[u8], password: &str) -> Result<Self, VaultError> {
        let (env, kdf, salt) = Self::parse_envelope(raw)?;
        let vault_key = unwrap_key(&env.key_wrap, password, &salt, &kdf)?;
        Self::finish_open(env, kdf, salt, vault_key)
    }

    /// Parses and sanity-checks an envelope without decrypting anything.
    fn parse_envelope(raw: &[u8]) -> Result<(Envelope, KdfParams, [u8; SALT_LEN]), VaultError> {
        let env: Envelope =
            serde_json::from_slice(&raw).map_err(|e| VaultError::Corrupt(e.to_string()))?;
        if env.version != FORMAT_VERSION {
            return Err(VaultError::UnsupportedVersion(env.version));
        }
        if env.kdf.algo != KDF_ALGO
            || env.key_wrap.algo != CIPHER_ALGO
            || env.cipher.algo != CIPHER_ALGO
        {
            return Err(VaultError::Corrupt("unknown algorithm".into()));
        }
        let kdf = KdfParams {
            m_kib: env.kdf.m_kib,
            t: env.kdf.t,
            p: env.kdf.p,
        };
        kdf.check()?;
        let salt: [u8; SALT_LEN] = decode_fixed(&env.kdf.salt, "salt")?;
        Ok((env, kdf, salt))
    }

    fn finish_open(
        env: Envelope,
        kdf: KdfParams,
        salt: [u8; SALT_LEN],
        vault_key: Key,
    ) -> Result<Self, VaultError> {
        let nonce: [u8; NONCE_LEN] = decode_fixed(&env.cipher.nonce, "payload nonce")?;
        let ciphertext = decode(&env.payload, "payload")?;
        let plaintext =
            open(&vault_key, &nonce, AAD_PAYLOAD, &ciphertext).ok_or(VaultError::Tampered)?;
        let entries: Vec<Entry> = serde_json::from_slice(&plaintext)
            .map_err(|e| VaultError::Corrupt(format!("payload: {e}")))?;

        Ok(Self {
            path: PathBuf::new(),
            vault_key,
            kdf,
            salt,
            key_wrap: env.key_wrap,
            created_at: env.created_at,
            entries,
            biometric: env.biometric,
        })
    }

    // ---- Touch ID (M6.1) ----

    /// Whether the vault file at `path` has Touch ID set up. Reads only the
    /// unencrypted envelope header.
    pub fn has_biometric(path: &Path) -> bool {
        fs::read(path)
            .ok()
            .and_then(|raw| serde_json::from_slice::<Envelope>(&raw).ok())
            .is_some_and(|env| env.biometric.is_some())
    }

    #[cfg(test)]
    pub fn biometric_enabled(&self) -> bool {
        self.biometric.is_some()
    }

    #[cfg(test)]
    pub fn biometric_public(&self) -> Option<Vec<u8>> {
        self.biometric.as_ref().and_then(|b| B64.decode(&b.se_public).ok())
    }

    /// (chip-bound key, public key, ephemeral key) of the current Touch ID
    /// setup: enough to re-wrap without a prompt, or to ask for a fingerprint.
    pub fn biometric_material(&self) -> Option<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        let b = self.biometric.as_ref()?;
        Some((
            B64.decode(&b.se_key).ok()?,
            B64.decode(&b.se_public).ok()?,
            B64.decode(&b.ephemeral).ok()?,
        ))
    }

    /// Unlocks with Touch ID. `unwrap(se_key, ephemeral)` must return the
    /// wrapping key from the Secure Enclave (which asks for a fingerprint).
    pub fn unlock_biometric(
        path: &Path,
        unwrap: impl FnOnce(&[u8], &[u8]) -> Result<Key, String>,
    ) -> Result<Self, VaultError> {
        let raw = match fs::read(path) {
            Ok(raw) => raw,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(VaultError::NotFound),
            Err(e) => return Err(e.into()),
        };
        let (env, kdf, salt) = Self::parse_envelope(&raw)?;
        let bio = env
            .biometric
            .clone()
            .ok_or_else(|| VaultError::Biometric("Touch ID isn't set up for this vault.".into()))?;
        if bio.algo != BIOMETRIC_ALGO {
            return Err(VaultError::Biometric("Unknown Touch ID format.".into()));
        }
        let se_key = decode(&bio.se_key, "Touch ID key")?;
        let ephemeral = decode(&bio.ephemeral, "Touch ID ephemeral key")?;
        let nonce: [u8; NONCE_LEN] = decode_fixed(&bio.nonce, "Touch ID nonce")?;
        let ciphertext = decode(&bio.ciphertext, "Touch ID key wrap")?;
        let wrap = unwrap(&se_key, &ephemeral).map_err(VaultError::Biometric)?;
        let raw_key = open(&wrap, &nonce, AAD_TOUCH_ID, &ciphertext).ok_or_else(|| {
            VaultError::Biometric(
                "Touch ID data doesn't match this vault. Use your master password, then turn Touch ID on again.".into(),
            )
        })?;
        if raw_key.len() != KEY_LEN {
            return Err(VaultError::Corrupt("vault key has wrong length".into()));
        }
        let mut vault_key: Key = Zeroizing::new([0u8; KEY_LEN]);
        vault_key.copy_from_slice(&raw_key);
        let mut vault = Self::finish_open(env, kdf, salt, vault_key)?;
        vault.path = path.to_path_buf();
        Ok(vault)
    }

    /// Seals the vault key under `wrap` (derived from the Secure Enclave key)
    /// and saves. Replaces any previous Touch ID setup.
    pub fn set_biometric(
        &mut self,
        se_key: &[u8],
        se_public: &[u8],
        ephemeral: &[u8],
        wrap: &Key,
    ) -> Result<(), VaultError> {
        let (nonce, ciphertext) = seal(wrap, AAD_TOUCH_ID, self.vault_key.as_ref());
        let next = Some(BiometricWrap {
            algo: BIOMETRIC_ALGO.into(),
            se_key: B64.encode(se_key),
            se_public: B64.encode(se_public),
            ephemeral: B64.encode(ephemeral),
            nonce: B64.encode(nonce),
            ciphertext: B64.encode(ciphertext),
        });
        let previous = std::mem::replace(&mut self.biometric, next);
        if let Err(e) = self.save() {
            self.biometric = previous;
            return Err(e);
        }
        Ok(())
    }

    pub fn clear_biometric(&mut self) -> Result<(), VaultError> {
        let previous = self.biometric.take();
        if let Err(e) = self.save() {
            self.biometric = previous;
            return Err(e);
        }
        Ok(())
    }

    /// Re-checks the master password against this vault (for actions that
    /// need fresh proof of the password, like installing an update).
    pub fn verify_password(&self, password: &str) -> Result<(), VaultError> {
        unwrap_key(&self.key_wrap, password, &self.salt, &self.kdf).map(drop)
    }

    /// Verifies `old`, then re-keys everything: new vault key, new salt,
    /// current default KDF params, payload re-encrypted (BRIEF §8).
    pub fn change_password(&mut self, old: &str, new: &str) -> Result<(), VaultError> {
        self.change_password_with(old, new, KdfParams::DEFAULT)
    }

    fn change_password_with(
        &mut self,
        old: &str,
        new: &str,
        kdf: KdfParams,
    ) -> Result<(), VaultError> {
        check_password(new)?;
        self.verify_password(old)?;

        let vault_key: Key = Zeroizing::new(<[u8; KEY_LEN]>::generate());
        let salt = <[u8; SALT_LEN]>::generate();
        let key_wrap = wrap_key(&vault_key, new, &salt, &kdf)?;

        // The Touch ID wrap seals the old vault key, so it goes in the same
        // save; the caller re-wraps the new key (no prompt needed).
        let previous = (
            std::mem::replace(&mut self.vault_key, vault_key),
            std::mem::replace(&mut self.kdf, kdf),
            std::mem::replace(&mut self.salt, salt),
            std::mem::replace(&mut self.key_wrap, key_wrap),
            self.biometric.take(),
        );
        if let Err(e) = self.save() {
            // Disk still holds the old vault; keep memory consistent with it.
            (self.vault_key, self.kdf, self.salt, self.key_wrap, self.biometric) = previous;
            return Err(e);
        }
        Ok(())
    }

    fn save(&mut self) -> Result<(), VaultError> {
        let json = self.envelope_json(true)?;
        write_atomic_with_backup(&self.path, &json)?;
        Ok(())
    }

    /// An encrypted backup (BRIEF §7): the same envelope as vault.enc, sealed
    /// with a fresh nonce and opened with the current master password.
    /// Never includes the Touch ID wrap: it's useless on another Mac, and a
    /// backup must open with the master password alone.
    pub fn export_bytes(&self) -> Result<Vec<u8>, VaultError> {
        self.envelope_json(false)
    }

    fn envelope_json(&self, include_biometric: bool) -> Result<Vec<u8>, VaultError> {
        let plaintext = Zeroizing::new(
            serde_json::to_vec(&self.entries).map_err(|e| VaultError::Corrupt(e.to_string()))?,
        );
        let (nonce, ciphertext) = seal(&self.vault_key, AAD_PAYLOAD, &plaintext);
        let env = Envelope {
            version: FORMAT_VERSION,
            kdf: KdfHeader {
                algo: KDF_ALGO.into(),
                m_kib: self.kdf.m_kib,
                t: self.kdf.t,
                p: self.kdf.p,
                salt: B64.encode(self.salt),
            },
            key_wrap: self.key_wrap.clone(),
            cipher: CipherHeader {
                algo: CIPHER_ALGO.into(),
                nonce: B64.encode(nonce),
            },
            payload: B64.encode(ciphertext),
            created_at: self.created_at,
            updated_at: now(),
            biometric: if include_biometric { self.biometric.clone() } else { None },
        };
        serde_json::to_vec_pretty(&env).map_err(|e| VaultError::Corrupt(e.to_string()))
    }
}

// ---- entries (BRIEF §6.1, §7, §8) ----

/// Metadata the webview may see: everything except the seed.
#[derive(Serialize)]
pub struct EntryMeta {
    pub id: String,
    pub issuer: String,
    pub account: String,
    pub digits: u32,
    pub period: u32,
    pub algorithm: Algo,
    pub kind: Kind,
    pub tags: Vec<String>,
}

impl Entry {
    pub fn meta(&self) -> EntryMeta {
        EntryMeta {
            id: self.id.clone(),
            issuer: self.issuer.clone(),
            account: self.account.clone(),
            digits: self.digits,
            period: self.period,
            algorithm: self.algorithm,
            kind: self.kind,
            tags: self.tags.clone(),
        }
    }

    /// TOTP code at `now`. HOTP codes come from `Vault::next_hotp`.
    pub fn totp_code(&self, now: u64) -> Result<String, String> {
        otp::code(&self.seed_b32, self.algorithm, self.digits, Kind::Totp, self.period, now)
    }
}

/// Entries from a backup file, decrypted with the password it was made with.
pub fn read_backup(raw: &[u8], password: &str) -> Result<Vec<Entry>, VaultError> {
    if raw.len() > MAX_BACKUP_BYTES {
        return Err(VaultError::Corrupt("file is too large to be a lockbox backup".into()));
    }
    Ok(std::mem::take(&mut Vault::open_raw(raw, password)?.entries))
}

#[derive(Debug, Default, PartialEq, Eq, Serialize)]
pub struct ImportSummary {
    pub added: usize,
    pub skipped: usize,
}

impl Entry {
    fn same_account(&self, other: &Entry) -> bool {
        self.issuer.eq_ignore_ascii_case(&other.issuer)
            && self.account.eq_ignore_ascii_case(&other.account)
            && self.seed_b32 == other.seed_b32
    }
}

fn new_id() -> String {
    let b = <[u8; 16]>::generate();
    let hex: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!("{}-{}-{}-{}-{}", &hex[..8], &hex[8..12], &hex[12..16], &hex[16..20], &hex[20..])
}

impl Vault {
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    #[cfg(test)]
    pub fn entry(&self, id: &str) -> Option<&Entry> {
        self.entries.iter().find(|e| e.id == id)
    }

    /// An existing entry with the same issuer, account and seed (BRIEF §7.5).
    pub fn find_duplicate(&self, new: &NewEntry) -> Option<&Entry> {
        self.entries.iter().find(|e| {
            e.issuer.eq_ignore_ascii_case(&new.issuer)
                && e.account.eq_ignore_ascii_case(&new.account)
                && e.seed_b32 == *new.seed_b32
        })
    }

    /// Adds `new`, optionally replacing the entry `replace` in place. Saves.
    pub fn add(&mut self, new: &NewEntry, replace: Option<&str>) -> Result<String, VaultError> {
        let entry = Entry {
            id: new_id(),
            issuer: new.issuer.clone(),
            account: new.account.clone(),
            seed_b32: new.seed_b32.to_string(),
            digits: new.digits,
            period: new.period,
            algorithm: new.algorithm,
            kind: new.kind,
            counter: new.counter,
            added_at: now(),
            tags: Vec::new(),
        };
        let id = entry.id.clone();
        self.mutate(|entries| {
            match replace.and_then(|r| entries.iter().position(|e| e.id == r)) {
                Some(i) => entries[i] = entry,
                None => entries.push(entry),
            }
            Ok(())
        })?;
        Ok(id)
    }

    /// Metadata only; changing the seed is delete + add (BRIEF §8).
    pub fn edit(
        &mut self,
        id: &str,
        issuer: &str,
        account: &str,
        tags: Vec<String>,
    ) -> Result<(), VaultError> {
        let (issuer, account) = (issuer.trim(), account.trim());
        if issuer.is_empty() && account.is_empty() {
            return Err(VaultError::Invalid("give at least an issuer or an account name".into()));
        }
        self.mutate(|entries| {
            let e = entries.iter_mut().find(|e| e.id == id).ok_or(VaultError::NoSuchEntry)?;
            e.issuer = issuer.into();
            e.account = account.into();
            e.tags = tags;
            Ok(())
        })
    }

    pub fn delete(&mut self, id: &str) -> Result<(), VaultError> {
        self.mutate(|entries| {
            let i = entries.iter().position(|e| e.id == id).ok_or(VaultError::NoSuchEntry)?;
            entries.remove(i);
            Ok(())
        })
    }

    /// HOTP: returns the code for the stored counter, then advances and saves
    /// the counter so the next press yields the next code (RFC 4226).
    pub fn next_hotp(&mut self, id: &str) -> Result<String, VaultError> {
        let mut out = String::new();
        self.mutate(|entries| {
            let e = entries.iter_mut().find(|e| e.id == id).ok_or(VaultError::NoSuchEntry)?;
            if e.kind != Kind::Hotp {
                return Err(VaultError::Invalid("not a counter-based (HOTP) account".into()));
            }
            let counter = e.counter.unwrap_or(0);
            out = otp::code(&e.seed_b32, e.algorithm, e.digits, Kind::Hotp, e.period, counter)
                .map_err(VaultError::Invalid)?;
            e.counter = Some(counter + 1);
            Ok(())
        })?;
        Ok(out)
    }

    /// Adds every backup entry not already in the vault (same issuer, account
    /// and seed), with fresh ids. Never removes or overwrites anything.
    pub fn import(&mut self, incoming: Vec<Entry>) -> Result<ImportSummary, VaultError> {
        let mut summary = ImportSummary::default();
        self.mutate(|entries| {
            for mut e in incoming {
                if entries.iter().any(|x| x.same_account(&e)) {
                    summary.skipped += 1;
                    continue;
                }
                e.id = new_id();
                entries.push(e);
                summary.added += 1;
            }
            Ok(())
        })?;
        Ok(summary)
    }

    /// Applies `f` and saves; if either fails, the in-memory entries are put
    /// back so memory always matches what's on disk.
    fn mutate(
        &mut self,
        f: impl FnOnce(&mut Vec<Entry>) -> Result<(), VaultError>,
    ) -> Result<(), VaultError> {
        let before = self.entries.clone();
        let result = f(&mut self.entries).and_then(|()| self.save());
        if result.is_err() {
            self.entries = before;
        }
        result
    }
}

fn check_password(password: &str) -> Result<(), VaultError> {
    if password.chars().count() < MIN_PASSWORD_CHARS {
        Err(VaultError::WeakPassword)
    } else {
        Ok(())
    }
}

fn derive_kek(password: &str, salt: &[u8], kdf: &KdfParams) -> Result<Key, VaultError> {
    let params = Params::new(kdf.m_kib, kdf.t, kdf.p, Some(KEY_LEN))
        .map_err(|e| VaultError::Corrupt(format!("KDF parameters: {e}")))?;
    let mut kek: Key = Zeroizing::new([0u8; KEY_LEN]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password.as_bytes(), salt, kek.as_mut())
        .map_err(|e| VaultError::Corrupt(format!("KDF: {e}")))?;
    Ok(kek)
}

fn wrap_key(
    vault_key: &Key,
    password: &str,
    salt: &[u8],
    kdf: &KdfParams,
) -> Result<SealedHeader, VaultError> {
    let kek = derive_kek(password, salt, kdf)?;
    let (nonce, ciphertext) = seal(&kek, AAD_KEY_WRAP, vault_key.as_ref());
    Ok(SealedHeader {
        algo: CIPHER_ALGO.into(),
        nonce: B64.encode(nonce),
        ciphertext: B64.encode(ciphertext),
    })
}

/// A wrong password and a tampered key wrap are indistinguishable under GCM;
/// both report `WrongPassword`.
fn unwrap_key(
    wrap: &SealedHeader,
    password: &str,
    salt: &[u8],
    kdf: &KdfParams,
) -> Result<Key, VaultError> {
    let nonce: [u8; NONCE_LEN] = decode_fixed(&wrap.nonce, "key-wrap nonce")?;
    let ciphertext = decode(&wrap.ciphertext, "key wrap")?;
    let kek = derive_kek(password, salt, kdf)?;
    let raw = open(&kek, &nonce, AAD_KEY_WRAP, &ciphertext).ok_or(VaultError::WrongPassword)?;
    let mut vault_key: Key = Zeroizing::new([0u8; KEY_LEN]);
    if raw.len() != KEY_LEN {
        return Err(VaultError::Corrupt("vault key has wrong length".into()));
    }
    vault_key.copy_from_slice(&raw);
    Ok(vault_key)
}

fn seal(key: &Key, aad: &[u8], plaintext: &[u8]) -> ([u8; NONCE_LEN], Vec<u8>) {
    let cipher = Aes256Gcm::new_from_slice(key.as_ref()).expect("32-byte key");
    let nonce = <[u8; NONCE_LEN]>::generate();
    let ciphertext = cipher
        .encrypt(
            &Nonce::from(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("AES-GCM encryption cannot fail for in-memory buffers");
    (nonce, ciphertext)
}

fn open(
    key: &Key,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Option<Zeroizing<Vec<u8>>> {
    let cipher = Aes256Gcm::new_from_slice(key.as_ref()).expect("32-byte key");
    cipher
        .decrypt(
            &Nonce::from(*nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .ok()
        .map(Zeroizing::new)
}

fn decode(b64: &str, what: &str) -> Result<Vec<u8>, VaultError> {
    B64.decode(b64)
        .map_err(|_| VaultError::Corrupt(format!("{what} is not valid base64")))
}

fn decode_fixed<const N: usize>(b64: &str, what: &str) -> Result<[u8; N], VaultError> {
    decode(b64, what)?
        .try_into()
        .map_err(|_| VaultError::Corrupt(format!("{what} has wrong length")))
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// BRIEF §6.1: serialize → encrypt → write `.tmp` → fsync → rename, keeping
/// the previous file as a single rolling `.bak`. The directory is 0700 and
/// files are 0600.
fn write_atomic_with_backup(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let dir = path.parent().expect("vault path has a parent directory");
    fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;

    let tmp = sibling(path, "tmp");
    write_synced(&tmp, bytes)?;

    if path.exists() {
        let bak = sibling(path, "bak");
        let bak_tmp = sibling(path, "bak.tmp");
        write_synced(&bak_tmp, &fs::read(path)?)?;
        fs::rename(&bak_tmp, &bak)?;
    }

    fs::rename(&tmp, path)?;
    fs::File::open(dir)?.sync_all()
}

fn write_synced(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(bytes)?;
    f.sync_all()
}

/// The rolling backup next to the vault (`vault.enc.bak`).
pub fn backup_path(vault: &Path) -> PathBuf {
    sibling(vault, "bak")
}

/// `vault.enc` → `vault.enc.<suffix>`
fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.file_name().expect("vault path has a file name").to_os_string();
    name.push(".");
    name.push(suffix);
    path.with_file_name(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Tiny params so tests are fast; DEFAULT is exercised in its own test.
    const FAST: KdfParams = KdfParams {
        m_kib: 64,
        t: 1,
        p: 1,
    };
    const PW: &str = "correct horse battery";

    fn setup() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lockbox/vault.enc");
        (dir, path)
    }

    fn sample_entry() -> Entry {
        Entry {
            id: "e1".into(),
            issuer: "Example".into(),
            account: "mads@example.com".into(),
            seed_b32: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".into(),
            digits: 6,
            period: 30,
            algorithm: Algo::SHA1,
            kind: Kind::Totp,
            counter: None,
            added_at: 1,
            tags: vec!["work".into()],
        }
    }

    fn read_env(path: &Path) -> serde_json::Value {
        serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
    }

    fn write_env(path: &Path, env: &serde_json::Value) {
        fs::write(path, serde_json::to_vec(env).unwrap()).unwrap();
    }

    #[test]
    fn create_then_unlock() {
        let (_d, path) = setup();
        assert!(!Vault::exists(&path));
        Vault::create(&path, PW, FAST).unwrap();
        assert!(Vault::exists(&path));
        let v = Vault::unlock(&path, PW).unwrap();
        assert!(v.entries.is_empty());
    }

    #[test]
    fn entries_round_trip_through_encryption() {
        let (_d, path) = setup();
        let mut v = Vault::create(&path, PW, FAST).unwrap();
        v.entries.push(sample_entry());
        v.save().unwrap();
        drop(v);

        let raw = fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("GEZDGNBV"), "seed must not appear in plaintext");
        assert!(!raw.contains("Example"), "metadata is inside the payload too");

        let v = Vault::unlock(&path, PW).unwrap();
        assert_eq!(v.entries.len(), 1);
        assert_eq!(v.entries[0].seed_b32, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
        assert_eq!(v.entries[0].tags, vec!["work".to_string()]);
    }

    #[test]
    fn wrong_password_is_rejected() {
        let (_d, path) = setup();
        Vault::create(&path, PW, FAST).unwrap();
        assert!(matches!(
            Vault::unlock(&path, "correct horse battery!"),
            Err(VaultError::WrongPassword)
        ));
    }

    #[test]
    fn create_refuses_to_overwrite() {
        let (_d, path) = setup();
        Vault::create(&path, PW, FAST).unwrap();
        assert!(matches!(
            Vault::create(&path, PW, FAST),
            Err(VaultError::AlreadyExists)
        ));
    }

    #[test]
    fn short_password_is_rejected() {
        let (_d, path) = setup();
        assert!(matches!(
            Vault::create(&path, "1234567", FAST),
            Err(VaultError::WeakPassword)
        ));
        assert!(!path.exists());
    }

    #[test]
    fn missing_vault_is_not_found() {
        let (_d, path) = setup();
        assert!(matches!(Vault::unlock(&path, PW), Err(VaultError::NotFound)));
    }

    #[test]
    fn payload_tamper_is_detected() {
        let (_d, path) = setup();
        let mut v = Vault::create(&path, PW, FAST).unwrap();
        v.entries.push(sample_entry());
        v.save().unwrap();

        let mut env = read_env(&path);
        let mut ct = B64.decode(env["payload"].as_str().unwrap()).unwrap();
        ct[3] ^= 0x01;
        env["payload"] = B64.encode(ct).into();
        write_env(&path, &env);

        assert!(matches!(Vault::unlock(&path, PW), Err(VaultError::Tampered)));
    }

    #[test]
    fn swapped_payload_nonce_is_detected() {
        let (_d, path) = setup();
        Vault::create(&path, PW, FAST).unwrap();
        let mut env = read_env(&path);
        env["cipher"]["nonce"] = B64.encode([7u8; NONCE_LEN]).into();
        write_env(&path, &env);
        assert!(matches!(Vault::unlock(&path, PW), Err(VaultError::Tampered)));
    }

    #[test]
    fn key_wrap_tamper_fails_like_wrong_password() {
        let (_d, path) = setup();
        Vault::create(&path, PW, FAST).unwrap();
        let mut env = read_env(&path);
        let mut ct = B64.decode(env["key_wrap"]["ciphertext"].as_str().unwrap()).unwrap();
        ct[0] ^= 0x80;
        env["key_wrap"]["ciphertext"] = B64.encode(ct).into();
        write_env(&path, &env);
        assert!(matches!(
            Vault::unlock(&path, PW),
            Err(VaultError::WrongPassword)
        ));
    }

    #[test]
    fn edited_kdf_params_fail_like_wrong_password() {
        let (_d, path) = setup();
        Vault::create(&path, PW, FAST).unwrap();
        let mut env = read_env(&path);
        env["kdf"]["t"] = 2.into();
        write_env(&path, &env);
        assert!(matches!(
            Vault::unlock(&path, PW),
            Err(VaultError::WrongPassword)
        ));
    }

    #[test]
    fn kdf_params_round_trip_through_envelope() {
        let (_d, path) = setup();
        let custom = KdfParams {
            m_kib: 128,
            t: 2,
            p: 2,
        };
        Vault::create(&path, PW, custom).unwrap();
        let env = read_env(&path);
        assert_eq!(env["version"], FORMAT_VERSION);
        assert_eq!(env["kdf"]["algo"], "argon2id");
        assert_eq!(env["kdf"]["m_kib"], 128);
        assert_eq!(env["kdf"]["t"], 2);
        assert_eq!(env["kdf"]["p"], 2);
        assert_eq!(B64.decode(env["kdf"]["salt"].as_str().unwrap()).unwrap().len(), SALT_LEN);
        assert_eq!(env["cipher"]["algo"], "aes-256-gcm");
        assert_eq!(env["key_wrap"]["algo"], "aes-256-gcm");
        assert_eq!(Vault::unlock(&path, PW).unwrap().kdf, custom);
    }

    #[test]
    fn default_kdf_params_work() {
        let (_d, path) = setup();
        Vault::create(&path, PW, KdfParams::DEFAULT).unwrap();
        assert_eq!(Vault::unlock(&path, PW).unwrap().kdf, KdfParams::DEFAULT);
    }

    #[test]
    fn absurd_kdf_params_are_rejected_before_deriving() {
        let (_d, path) = setup();
        Vault::create(&path, PW, FAST).unwrap();
        let mut env = read_env(&path);
        env["kdf"]["m_kib"] = (u32::MAX).into();
        write_env(&path, &env);
        assert!(matches!(Vault::unlock(&path, PW), Err(VaultError::Corrupt(_))));
    }

    #[test]
    fn future_version_is_refused() {
        let (_d, path) = setup();
        Vault::create(&path, PW, FAST).unwrap();
        let mut env = read_env(&path);
        env["version"] = 2.into();
        write_env(&path, &env);
        assert!(matches!(
            Vault::unlock(&path, PW),
            Err(VaultError::UnsupportedVersion(2))
        ));
    }

    #[test]
    fn garbage_file_is_corrupt() {
        let (_d, path) = setup();
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, b"not a vault").unwrap();
        assert!(matches!(Vault::unlock(&path, PW), Err(VaultError::Corrupt(_))));
    }

    #[test]
    fn change_password_rekeys_and_keeps_entries() {
        let (_d, path) = setup();
        let mut v = Vault::create(&path, PW, FAST).unwrap();
        v.entries.push(sample_entry());
        v.save().unwrap();
        let old_env = read_env(&path);

        v.change_password_with(PW, "a brand new passphrase", FAST)
            .unwrap();
        drop(v);

        let new_env = read_env(&path);
        assert_ne!(old_env["kdf"]["salt"], new_env["kdf"]["salt"]);
        assert_ne!(old_env["key_wrap"], new_env["key_wrap"]);
        assert!(matches!(
            Vault::unlock(&path, PW),
            Err(VaultError::WrongPassword)
        ));
        let v = Vault::unlock(&path, "a brand new passphrase").unwrap();
        assert_eq!(v.entries.len(), 1);
        assert_eq!(v.entries[0].id, "e1");
    }

    #[test]
    fn change_password_requires_old_password() {
        let (_d, path) = setup();
        let mut v = Vault::create(&path, PW, FAST).unwrap();
        let before = fs::read(&path).unwrap();
        assert!(matches!(
            v.change_password_with("not the password", "a brand new passphrase", FAST),
            Err(VaultError::WrongPassword)
        ));
        assert!(matches!(
            v.change_password_with(PW, "short", FAST),
            Err(VaultError::WeakPassword)
        ));
        assert_eq!(fs::read(&path).unwrap(), before, "vault untouched");
        // The in-memory vault still works with the original password.
        v.save().unwrap();
        Vault::unlock(&path, PW).unwrap();
    }

    #[test]
    fn verify_password_checks_against_vault() {
        let (_d, path) = setup();
        let v = Vault::create(&path, PW, FAST).unwrap();
        assert!(v.verify_password(PW).is_ok());
        assert!(matches!(
            v.verify_password("not the password"),
            Err(VaultError::WrongPassword)
        ));
    }

    fn new_entry(issuer: &str, seed: &str) -> NewEntry {
        otp::from_manual(otp::ManualForm {
            issuer: issuer.into(),
            account: "me@example.com".into(),
            seed: seed.into(),
            digits: None,
            period: None,
            algorithm: None,
            kind: None,
            counter: None,
        })
        .unwrap()
    }

    #[test]
    fn add_edit_delete_persist() {
        let (_d, path) = setup();
        let mut v = Vault::create(&path, PW, FAST).unwrap();
        let a = v.add(&new_entry("Acme", "JBSWY3DPEHPK3PXP"), None).unwrap();
        let b = v.add(&new_entry("Beta", "GEZDGNBVGY3TQOJQ"), None).unwrap();
        assert_ne!(a, b);
        assert_eq!(a.len(), 36, "uuid-shaped id");
        v.edit(&a, "Acme Corp", "ops@example.com", vec!["work".into()]).unwrap();
        v.delete(&b).unwrap();
        drop(v);

        let v = Vault::unlock(&path, PW).unwrap();
        assert_eq!(v.entries().len(), 1);
        let e = v.entry(&a).unwrap();
        assert_eq!((e.issuer.as_str(), e.account.as_str()), ("Acme Corp", "ops@example.com"));
        assert_eq!(e.tags, vec!["work".to_string()]);
        assert_eq!(e.seed_b32, "JBSWY3DPEHPK3PXP");
    }

    #[test]
    fn duplicates_are_found_and_can_be_replaced() {
        let (_d, path) = setup();
        let mut v = Vault::create(&path, PW, FAST).unwrap();
        let id = v.add(&new_entry("Acme", "JBSWY3DPEHPK3PXP"), None).unwrap();
        let again = new_entry("acme", "jbsw y3dp ehpk 3pxp");
        assert_eq!(v.find_duplicate(&again).map(|e| e.id.as_str()), Some(id.as_str()));
        assert!(v.find_duplicate(&new_entry("Acme", "GEZDGNBVGY3TQOJQ")).is_none());

        let new_id = v.add(&again, Some(&id)).unwrap();
        assert_eq!(v.entries().len(), 1);
        assert_eq!(v.entries()[0].id, new_id);
    }

    #[test]
    fn missing_entries_and_bad_edits_are_errors() {
        let (_d, path) = setup();
        let mut v = Vault::create(&path, PW, FAST).unwrap();
        assert!(matches!(v.delete("nope"), Err(VaultError::NoSuchEntry)));
        assert!(matches!(v.edit("nope", "a", "b", vec![]), Err(VaultError::NoSuchEntry)));
        let id = v.add(&new_entry("Acme", "JBSWY3DPEHPK3PXP"), None).unwrap();
        assert!(matches!(v.edit(&id, " ", "", vec![]), Err(VaultError::Invalid(_))));
        assert!(matches!(v.next_hotp(&id), Err(VaultError::Invalid(_))));
    }

    #[test]
    fn hotp_counter_advances_and_persists() {
        let (_d, path) = setup();
        let mut v = Vault::create(&path, PW, FAST).unwrap();
        let mut e = new_entry("Acme", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
        e.kind = Kind::Hotp;
        e.counter = Some(0);
        let id = v.add(&e, None).unwrap();
        // RFC 4226 vectors for counters 0 and 1.
        assert_eq!(v.next_hotp(&id).unwrap(), "755224");
        assert_eq!(v.next_hotp(&id).unwrap(), "287082");
        drop(v);
        let mut v = Vault::unlock(&path, PW).unwrap();
        assert_eq!(v.entry(&id).unwrap().counter, Some(2));
        assert_eq!(v.next_hotp(&id).unwrap(), "359152");
    }

    #[test]
    fn failed_save_rolls_back_memory() {
        let (_d, path) = setup();
        let mut v = Vault::create(&path, PW, FAST).unwrap();
        // A directory squatting on the temp-file path makes the save fail.
        fs::create_dir(sibling(&path, "tmp")).unwrap();
        let r = v.add(&new_entry("Acme", "JBSWY3DPEHPK3PXP"), None);
        assert!(matches!(r, Err(VaultError::Io(_))));
        assert!(v.entries().is_empty(), "memory matches disk");
        fs::remove_dir(sibling(&path, "tmp")).unwrap();
        assert!(Vault::unlock(&path, PW).unwrap().entries().is_empty());
    }

    #[test]
    fn totp_code_uses_entry_settings() {
        let (_d, path) = setup();
        let mut v = Vault::create(&path, PW, FAST).unwrap();
        let id = v.add(&new_entry("Acme", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"), None).unwrap();
        // RFC 6238 SHA1 t=59 → 94287082; 6-digit form 287082.
        assert_eq!(v.entry(&id).unwrap().totp_code(59).unwrap(), "287082");
    }

    #[test]
    fn export_then_import_into_a_fresh_vault_is_identical() {
        let (_d, path) = setup();
        let mut v = Vault::create(&path, PW, FAST).unwrap();
        v.add(&new_entry("Acme", "JBSWY3DPEHPK3PXP"), None).unwrap();
        let mut h = new_entry("Beta", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
        h.kind = Kind::Hotp;
        h.counter = Some(7);
        v.add(&h, None).unwrap();
        let backup = v.export_bytes().unwrap();
        let raw = String::from_utf8(backup.clone()).unwrap();
        assert!(!raw.contains("JBSWY3DP") && !raw.contains("Acme"), "backup is encrypted");

        // "Lose" the vault: a brand-new one with a different password.
        let (_d2, path2) = setup();
        let mut fresh = Vault::create(&path2, "another password", FAST).unwrap();
        let entries = read_backup(&backup, PW).unwrap();
        let summary = fresh.import(entries).unwrap();
        assert_eq!(summary, ImportSummary { added: 2, skipped: 0 });
        drop(fresh);

        let fresh = Vault::unlock(&path2, "another password").unwrap();
        let key = |e: &Entry| (e.issuer.clone(), e.account.clone(), e.seed_b32.clone(), e.kind == Kind::Hotp, e.counter);
        let mut a: Vec<_> = v.entries().iter().map(key).collect();
        let mut b: Vec<_> = fresh.entries().iter().map(key).collect();
        a.sort();
        b.sort();
        assert_eq!(a, b, "same accounts, settings and HOTP counters");
    }

    #[test]
    fn import_skips_accounts_already_present() {
        let (_d, path) = setup();
        let mut v = Vault::create(&path, PW, FAST).unwrap();
        v.add(&new_entry("Acme", "JBSWY3DPEHPK3PXP"), None).unwrap();
        let backup = v.export_bytes().unwrap();
        v.add(&new_entry("Beta", "GEZDGNBVGY3TQOJQ"), None).unwrap();

        let summary = v.import(read_backup(&backup, PW).unwrap()).unwrap();
        assert_eq!(summary, ImportSummary { added: 0, skipped: 1 });
        assert_eq!(v.entries().len(), 2);
    }

    #[test]
    fn backup_needs_the_password_it_was_made_with() {
        let (_d, path) = setup();
        let mut v = Vault::create(&path, PW, FAST).unwrap();
        let old_backup = v.export_bytes().unwrap();
        v.change_password_with(PW, "a brand new passphrase", FAST).unwrap();
        assert!(matches!(
            read_backup(&old_backup, "a brand new passphrase"),
            Err(VaultError::WrongPassword)
        ));
        assert!(read_backup(&old_backup, PW).is_ok());
    }

    #[test]
    fn bad_backups_are_refused() {
        assert!(matches!(read_backup(b"not a backup", PW), Err(VaultError::Corrupt(_))));
        let huge = vec![b' '; MAX_BACKUP_BYTES + 1];
        assert!(matches!(read_backup(&huge, PW), Err(VaultError::Corrupt(_))));
    }

    /// Stands in for the Secure Enclave: a fixed wrapping key.
    fn fake_wrap(byte: u8) -> Key {
        Zeroizing::new([byte; KEY_LEN])
    }

    fn enable_fake_touch_id(v: &mut Vault, byte: u8) {
        v.set_biometric(b"chip-bound blob", &[4u8; 65], &[4u8; 65], &fake_wrap(byte)).unwrap();
    }

    #[test]
    fn touch_id_unlock_round_trip() {
        let (_d, path) = setup();
        let mut v = Vault::create(&path, PW, FAST).unwrap();
        v.add(&new_entry("Acme", "JBSWY3DPEHPK3PXP"), None).unwrap();
        assert!(!Vault::has_biometric(&path));
        enable_fake_touch_id(&mut v, 7);
        assert!(Vault::has_biometric(&path) && v.biometric_enabled());
        assert_eq!(v.biometric_public().unwrap(), vec![4u8; 65]);
        drop(v);

        let v = Vault::unlock_biometric(&path, |se_key, eph| {
            assert_eq!(se_key, b"chip-bound blob");
            assert_eq!(eph, &[4u8; 65]);
            Ok(fake_wrap(7))
        })
        .unwrap();
        assert_eq!(v.entries().len(), 1);
        // The password path still works and sees the same vault.
        assert_eq!(Vault::unlock(&path, PW).unwrap().entries().len(), 1);
    }

    #[test]
    fn touch_id_failures_are_reported_and_harmless() {
        let (_d, path) = setup();
        let mut v = Vault::create(&path, PW, FAST).unwrap();
        assert!(matches!(
            Vault::unlock_biometric(&path, |_, _| Ok(fake_wrap(1))),
            Err(VaultError::Biometric(_))
        ), "not set up");
        enable_fake_touch_id(&mut v, 7);
        assert!(matches!(
            Vault::unlock_biometric(&path, |_, _| Ok(fake_wrap(8))),
            Err(VaultError::Biometric(_))
        ), "wrong wrapping key");
        assert!(matches!(
            Vault::unlock_biometric(&path, |_, _| Err("cancelled".into())),
            Err(VaultError::Biometric(m)) if m == "cancelled"
        ));
        Vault::unlock(&path, PW).unwrap();
    }

    #[test]
    fn backups_never_carry_touch_id() {
        let (_d, path) = setup();
        let mut v = Vault::create(&path, PW, FAST).unwrap();
        enable_fake_touch_id(&mut v, 7);
        let backup = String::from_utf8(v.export_bytes().unwrap()).unwrap();
        assert!(!backup.contains("biometric") && !backup.contains("se_key"));
        assert!(read_backup(backup.as_bytes(), PW).is_ok());
    }

    #[test]
    fn password_change_drops_the_stale_touch_id_wrap() {
        let (_d, path) = setup();
        let mut v = Vault::create(&path, PW, FAST).unwrap();
        enable_fake_touch_id(&mut v, 7);
        v.change_password_with(PW, "a brand new passphrase", FAST).unwrap();
        assert!(!v.biometric_enabled());
        assert!(!Vault::has_biometric(&path), "cleared in the same save as the re-key");
        // Re-enabling seals the new key and works again.
        enable_fake_touch_id(&mut v, 9);
        drop(v);
        assert!(Vault::unlock_biometric(&path, |_, _| Ok(fake_wrap(9))).is_ok());
    }

    #[test]
    fn clear_biometric_removes_it() {
        let (_d, path) = setup();
        let mut v = Vault::create(&path, PW, FAST).unwrap();
        enable_fake_touch_id(&mut v, 7);
        v.clear_biometric().unwrap();
        assert!(!Vault::has_biometric(&path));
    }

    #[test]
    fn older_files_without_the_field_still_open() {
        let (_d, path) = setup();
        Vault::create(&path, PW, FAST).unwrap();
        let raw = fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("biometric"), "absent unless enabled");
        Vault::unlock(&path, PW).unwrap();
    }

    #[test]
    fn saves_are_atomic_and_keep_one_backup() {
        let (_d, path) = setup();
        let mut v = Vault::create(&path, PW, FAST).unwrap();
        let bak = sibling(&path, "bak");
        assert!(!bak.exists(), "first write has nothing to back up");

        let first = fs::read(&path).unwrap();
        v.entries.push(sample_entry());
        v.save().unwrap();
        assert_eq!(fs::read(&bak).unwrap(), first, "backup is the previous version");

        let second = fs::read(&path).unwrap();
        v.save().unwrap();
        assert_eq!(fs::read(&bak).unwrap(), second, "backup rolls forward");

        assert!(!sibling(&path, "tmp").exists());
        assert!(!sibling(&path, "bak.tmp").exists());

        // The backup is itself a valid vault (corruption recovery).
        let restored = Vault::unlock(&bak, PW).unwrap();
        assert_eq!(restored.entries.len(), 1);
    }

    #[test]
    fn files_and_dir_are_private() {
        let (_d, path) = setup();
        let mut v = Vault::create(&path, PW, FAST).unwrap();
        v.save().unwrap();
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(path.parent().unwrap()), 0o700);
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(&sibling(&path, "bak")), 0o600);
    }

    #[test]
    fn nonces_and_salts_are_fresh() {
        let (_d, path) = setup();
        let mut v = Vault::create(&path, PW, FAST).unwrap();
        let a = read_env(&path);
        v.save().unwrap();
        let b = read_env(&path);
        assert_ne!(a["cipher"]["nonce"], b["cipher"]["nonce"]);

        let (_d2, path2) = setup();
        Vault::create(&path2, PW, FAST).unwrap();
        let c = read_env(&path2);
        assert_ne!(a["kdf"]["salt"], c["kdf"]["salt"]);
    }
}
