//! Login and the encrypted local store (ARCHITECTURE.md §9.8).
//!
//! States: `NeedsSetup` (first run) → `Unlocked` ⇄ `Locked`.
//! - The wallet list and the TOTP secret live in `store.v1.json`, encrypted
//!   with a key derived from the password (see the `auth` crate).
//! - Unlocking needs the password **and** a current 6-digit code.
//! - Wrong attempts are delayed, and 5 failures lock login for 30 minutes.
//! - After 5 minutes without activity the session locks itself.
//!
//! Honest scope: the 6-digit code is a gate against someone using this PC; its
//! secret is stored inside the encrypted file, so it adds no encryption
//! strength. No keys exist on this PC, so none of this protects funds.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::testnet::TestWallet;
use audit_log::{AuditLog, Event};
use auth::lockout::Lockout;
use auth::store::{self, KdfParams, StoreError};
use auth::totp;
use serde::{Deserialize, Serialize};
use wallet_core::address_book::AddressBook;
use wallet_core::Registry;
use zeroize::Zeroizing;

/// Lock after this long without any wallet activity.
pub const IDLE_LOCK: Duration = Duration::from_secs(5 * 60);
/// Errors that mean "show the login screen" start with this text.
pub const LOCKED_PREFIX: &str = "Locked";
const LOCKED_MSG: &str = "Locked: log in again to continue.";
const INTERNAL: &str = "Internal error. Restart the app.";
const WRONG: &str = "Wrong password or code.";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoreContents {
    version: u32,
    registry: Registry,
    totp_secret: String,
    totp_last_step: u64,
    /// Added later; older stores load with an empty book.
    #[serde(default)]
    address_book: AddressBook,
    /// Bitcoin signet test wallets (Phase 2 testing). Added later.
    #[serde(default)]
    test_wallets: Vec<TestWallet>,
    /// User settings. Added later.
    #[serde(default)]
    settings: Settings,
    /// The last signing-log receipt from the tablet, per wallet. Added later.
    #[serde(default)]
    tablet_receipts: BTreeMap<String, TabletReceipt>,
}

/// The tablet's signing-log position after its latest signature for a
/// wallet: its number and the log's head hash (hex).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TabletReceipt {
    pub seq: u64,
    pub head: String,
}

fn yes() -> bool {
    true
}

/// User settings, kept in the encrypted store.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    /// Bitcoin shown and checked. When off ("paused"), nothing is deleted:
    /// wallets keep their Bitcoin key, it is just hidden and not queried.
    #[serde(default = "yes")]
    pub bitcoin_enabled: bool,
    /// Real-network sending (real money). Off until the owner has passed
    /// the release gates and switched it on (Settings, with a typed
    /// confirmation). Older stores load with it off.
    #[serde(default)]
    pub real_sending: bool,
    /// Address-book waiting period in minutes (10 to 1440). Older stores
    /// load with 24 hours.
    #[serde(default = "day_minutes")]
    pub book_wait_minutes: u32,
}

fn day_minutes() -> u32 {
    1440
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            bitcoin_enabled: true,
            real_sending: false,
            book_wait_minutes: 1440,
        }
    }
}

struct Unlocked {
    registry: Registry,
    address_book: AddressBook,
    test_wallets: Vec<TestWallet>,
    settings: Settings,
    tablet_receipts: BTreeMap<String, TabletReceipt>,
    key: Zeroizing<[u8; 32]>,
    kdf: KdfParams,
    totp_secret: Zeroizing<Vec<u8>>,
    totp_last_step: u64,
    last_activity: Instant,
}

enum Session {
    NeedsSetup,
    Locked,
    Unlocked(Box<Unlocked>),
}

pub struct Paths {
    pub store: PathBuf,
    /// The unencrypted wallet list from earlier versions, moved into the
    /// store at setup and then deleted.
    pub legacy_registry: PathBuf,
    pub lockout: PathBuf,
    /// Hash-chained audit log (not encrypted; holds no addresses or labels).
    pub audit: PathBuf,
}

pub struct SessionState {
    inner: Mutex<Session>,
    pending_totp: Mutex<Option<Zeroizing<Vec<u8>>>>,
    paths: Paths,
    audit: AuditLog,
}

#[derive(Serialize)]
pub struct AuthStatus {
    /// "needs_setup", "locked" or "unlocked".
    state: &'static str,
    /// Seconds before another login attempt is accepted.
    wait_secs: u64,
    /// True if an unencrypted wallet list from an earlier version exists and
    /// will be moved into the encrypted store at setup.
    has_legacy_wallets: bool,
}

#[derive(Serialize)]
pub struct SetupInfo {
    /// Base32 secret, to type in by hand or write down as a backup.
    secret: String,
    /// QR code of the `otpauth://` link: `size` × `size` modules, row by row.
    qr_size: usize,
    qr_modules: Vec<bool>,
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl SessionState {
    pub fn load(paths: Paths) -> Self {
        let session = if paths.store.exists() {
            Session::Locked
        } else {
            Session::NeedsSetup
        };
        let audit = AuditLog::open(paths.audit.clone());
        Self {
            inner: Mutex::new(session),
            pending_totp: Mutex::new(None),
            paths,
            audit,
        }
    }

    pub fn audit(&self) -> &AuditLog {
        &self.audit
    }

    fn read_lockout(&self) -> Lockout {
        fs::read(&self.paths.lockout)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    fn write_lockout(&self, l: &Lockout) {
        if let Ok(b) = serde_json::to_vec(l) {
            let _ = store::write_atomic(&self.paths.lockout, &b);
        }
    }

    pub fn status(&self) -> Result<AuthStatus, String> {
        let s = self.inner.lock().map_err(|_| INTERNAL.to_owned())?;
        let state = match &*s {
            Session::NeedsSetup => "needs_setup",
            Session::Locked => "locked",
            Session::Unlocked(u) if u.last_activity.elapsed() > IDLE_LOCK => "locked",
            Session::Unlocked(_) => "unlocked",
        };
        Ok(AuthStatus {
            state,
            wait_secs: self.read_lockout().check(now_unix()).err().unwrap_or(0),
            has_legacy_wallets: matches!(&*s, Session::NeedsSetup)
                && self.paths.legacy_registry.exists(),
        })
    }

    /// First run: create the TOTP secret and return it for the authenticator app.
    pub fn setup_begin(&self) -> Result<SetupInfo, String> {
        if !matches!(
            *self.inner.lock().map_err(|_| INTERNAL.to_owned())?,
            Session::NeedsSetup
        ) {
            return Err("Setup is already done.".into());
        }
        let secret = totp::new_secret().map_err(|_| INTERNAL.to_owned())?;
        let uri = totp::otpauth_uri(&secret, "pc");
        let qr = crate::qr::matrix(&uri)?;
        let info = SetupInfo {
            secret: totp::secret_base32(&secret).to_string(),
            qr_size: qr.size,
            qr_modules: qr.modules,
        };
        *self.pending_totp.lock().map_err(|_| INTERNAL.to_owned())? = Some(secret);
        Ok(info)
    }

    /// First run: set the password, confirm the authenticator code, move any
    /// old unencrypted wallet list into the encrypted store.
    pub fn setup_finish(&self, password: &str, code: &str) -> Result<(), String> {
        let mut s = self.inner.lock().map_err(|_| INTERNAL.to_owned())?;
        if !matches!(*s, Session::NeedsSetup) {
            return Err("Setup is already done.".into());
        }
        store::check_password_rule(password).map_err(str::to_owned)?;
        let secret = self
            .pending_totp
            .lock()
            .map_err(|_| INTERNAL.to_owned())?
            .clone()
            .ok_or_else(|| "Start setup again.".to_owned())?;
        let step = totp::verify(&secret, code, now_unix(), 0).ok_or_else(|| {
            "That code doesn't match. Check that the authenticator app was set up with this QR code and that the PC clock is right.".to_owned()
        })?;
        let registry = Registry::load(&self.paths.legacy_registry).map_err(|e| {
            format!("The old wallet list couldn't be read ({e}). It was not changed.")
        })?;
        let kdf = KdfParams::new_random().map_err(|e| e.to_string())?;
        let key = store::derive_key(password, &kdf).map_err(|e| e.to_string())?;
        let unlocked = Unlocked {
            registry,
            address_book: AddressBook::default(),
            test_wallets: Vec::new(),
            settings: Settings::default(),
            tablet_receipts: BTreeMap::new(),
            key,
            kdf,
            totp_secret: secret,
            totp_last_step: step,
            last_activity: Instant::now(),
        };
        self.persist(&unlocked)?;
        if self.paths.legacy_registry.exists() {
            // The list is now inside the encrypted store.
            let _ = fs::remove_file(&self.paths.legacy_registry);
        }
        *self.pending_totp.lock().map_err(|_| INTERNAL.to_owned())? = None;
        self.audit.record(
            Event::SetupCompleted,
            &format!(
                "password and authenticator set; {} wallet(s) moved into the encrypted store",
                unlocked.registry.wallets.len()
            ),
        );
        *s = Session::Unlocked(Box::new(unlocked));
        Ok(())
    }

    fn persist(&self, u: &Unlocked) -> Result<(), String> {
        let contents = StoreContents {
            version: 1,
            registry: u.registry.clone(),
            totp_secret: totp::secret_base32(&u.totp_secret).to_string(),
            totp_last_step: u.totp_last_step,
            address_book: u.address_book.clone(),
            test_wallets: u.test_wallets.clone(),
            settings: u.settings,
            tablet_receipts: u.tablet_receipts.clone(),
        };
        let bytes = store::seal(&u.key, &u.kdf, &contents).map_err(|e| e.to_string())?;
        store::write_atomic(&self.paths.store, &bytes).map_err(|e| e.to_string())
    }

    pub fn unlock(&self, password: &str, code: &str) -> Result<(), String> {
        let mut lockout = self.read_lockout();
        let now = now_unix();
        if let Err(wait) = lockout.check(now) {
            self.audit.record(
                Event::LoginBlocked,
                &format!("attempt refused: {wait} s left of the wrong-attempt delay"),
            );
            return Err(format!(
                "Too many wrong attempts. Try again in {wait} seconds."
            ));
        }
        let mut s = self.inner.lock().map_err(|_| INTERNAL.to_owned())?;
        if matches!(*s, Session::NeedsSetup) {
            return Err("Set up the app first.".into());
        }
        let bytes = fs::read(&self.paths.store)
            .map_err(|_| "The encrypted store can't be read.".to_owned())?;
        let opened: Result<(StoreContents, _, _), StoreError> = store::open(&bytes, password);
        // The delay counts from when the attempt failed (the password check
        // itself takes a moment), not from when it started.
        let fail = |lockout: &mut Lockout| {
            lockout.record_failure(now_unix());
            self.write_lockout(lockout);
            self.audit.record(
                Event::LoginFailed,
                &format!(
                    "wrong password or code ({} wrong attempt(s) in a row)",
                    lockout.failures
                ),
            );
            WRONG.to_owned()
        };
        let (contents, key, kdf) = match opened {
            Ok(v) => v,
            Err(StoreError::WrongPasswordOrTampered) => return Err(fail(&mut lockout)),
            Err(e) => return Err(format!("The encrypted store can't be opened: {e}.")),
        };
        let secret = totp::secret_from_base32(&contents.totp_secret)
            .ok_or_else(|| "The encrypted store is damaged.".to_owned())?;
        let Some(step) = totp::verify(&secret, code, now, contents.totp_last_step) else {
            return Err(fail(&mut lockout));
        };
        lockout.record_success();
        self.write_lockout(&lockout);
        let unlocked = Unlocked {
            registry: contents.registry,
            address_book: contents.address_book,
            test_wallets: contents.test_wallets,
            settings: contents.settings,
            tablet_receipts: contents.tablet_receipts,
            key,
            kdf,
            totp_secret: secret,
            totp_last_step: step,
            last_activity: Instant::now(),
        };
        // Save the used step so the same code can't be used again.
        self.persist(&unlocked)?;
        self.audit.record(
            Event::LoginSucceeded,
            &format!("{} wallet(s)", unlocked.registry.wallets.len()),
        );
        *s = Session::Unlocked(Box::new(unlocked));
        Ok(())
    }

    /// Lock now. `idle` = the app's idle timer did it (not the Lock button).
    pub fn lock(&self, idle: bool) {
        if let Ok(mut s) = self.inner.lock() {
            if matches!(*s, Session::Unlocked(_)) {
                // Dropping `Unlocked` zeroizes the key and TOTP secret.
                *s = Session::Locked;
                if idle {
                    self.audit.record(
                        Event::IdleLocked,
                        &format!("no activity for {} minutes", IDLE_LOCK.as_secs() / 60),
                    );
                } else {
                    self.audit.record(Event::Locked, "Lock button");
                }
            }
        }
    }

    /// Run `f` on the address book (with the wallet list for reference) if
    /// unlocked. With `save`, the change is encrypted and written first.
    pub fn with_book<T>(
        &self,
        save: bool,
        f: impl FnOnce(&Registry, &mut AddressBook) -> Result<T, String>,
    ) -> Result<T, String> {
        let mut s = self.inner.lock().map_err(|_| INTERNAL.to_owned())?;
        let Session::Unlocked(u) = &mut *s else {
            return Err(LOCKED_MSG.into());
        };
        if u.last_activity.elapsed() > IDLE_LOCK {
            *s = Session::Locked;
            self.audit.record(
                Event::IdleLocked,
                &format!("no activity for {} minutes", IDLE_LOCK.as_secs() / 60),
            );
            return Err(LOCKED_MSG.into());
        }
        u.last_activity = Instant::now();
        if !save {
            let mut book = u.address_book.clone();
            return f(&u.registry, &mut book);
        }
        let mut next = u.address_book.clone();
        let out = f(&u.registry, &mut next)?;
        let previous = std::mem::replace(&mut u.address_book, next);
        if let Err(e) = self.persist(u) {
            u.address_book = previous;
            return Err(e);
        }
        Ok(out)
    }

    /// Current settings (login required).
    pub fn settings(&self) -> Result<Settings, String> {
        let s = self.inner.lock().map_err(|_| INTERNAL.to_owned())?;
        match &*s {
            Session::Unlocked(u) if u.last_activity.elapsed() <= IDLE_LOCK => Ok(u.settings),
            _ => Err(LOCKED_MSG.into()),
        }
    }

    /// Change settings; encrypted and saved before taking effect.
    pub fn update_settings(&self, f: impl FnOnce(&mut Settings)) -> Result<Settings, String> {
        let mut s = self.inner.lock().map_err(|_| INTERNAL.to_owned())?;
        let Session::Unlocked(u) = &mut *s else {
            return Err(LOCKED_MSG.into());
        };
        if u.last_activity.elapsed() > IDLE_LOCK {
            *s = Session::Locked;
            return Err(LOCKED_MSG.into());
        }
        u.last_activity = Instant::now();
        let previous = u.settings;
        f(&mut u.settings);
        if let Err(e) = self.persist(u) {
            u.settings = previous;
            return Err(e);
        }
        Ok(u.settings)
    }

    /// Save the tablet's receipt for a wallet. Returns the previous one.
    pub fn record_tablet_receipt(
        &self,
        wallet_id: &str,
        receipt: TabletReceipt,
    ) -> Result<Option<TabletReceipt>, String> {
        let mut s = self.inner.lock().map_err(|_| INTERNAL.to_owned())?;
        let Session::Unlocked(u) = &mut *s else {
            return Err(LOCKED_MSG.into());
        };
        let previous = u.tablet_receipts.insert(wallet_id.to_owned(), receipt);
        if let Err(e) = self.persist(u) {
            match previous.clone() {
                Some(p) => u.tablet_receipts.insert(wallet_id.to_owned(), p),
                None => u.tablet_receipts.remove(wallet_id),
            };
            return Err(e);
        }
        Ok(previous)
    }

    /// Run `f` on the test wallets if unlocked. With `save`, the change is
    /// encrypted and written first.
    pub fn with_test_wallets<T>(
        &self,
        save: bool,
        f: impl FnOnce(&mut Vec<TestWallet>) -> Result<T, String>,
    ) -> Result<T, String> {
        let mut s = self.inner.lock().map_err(|_| INTERNAL.to_owned())?;
        let Session::Unlocked(u) = &mut *s else {
            return Err(LOCKED_MSG.into());
        };
        if u.last_activity.elapsed() > IDLE_LOCK {
            *s = Session::Locked;
            return Err(LOCKED_MSG.into());
        }
        u.last_activity = Instant::now();
        let mut next = u.test_wallets.clone();
        let out = f(&mut next)?;
        if save {
            let previous = std::mem::replace(&mut u.test_wallets, next);
            if let Err(e) = self.persist(u) {
                u.test_wallets = previous;
                return Err(e);
            }
        }
        Ok(out)
    }

    /// Run `f` on the wallet list if unlocked (and not idle for too long).
    /// With `save`, the change is encrypted and written before it takes effect.
    pub fn with_registry<T>(
        &self,
        touch: bool,
        save: bool,
        f: impl FnOnce(&mut Registry) -> Result<T, String>,
    ) -> Result<T, String> {
        let mut s = self.inner.lock().map_err(|_| INTERNAL.to_owned())?;
        let Session::Unlocked(u) = &mut *s else {
            return Err(LOCKED_MSG.into());
        };
        if u.last_activity.elapsed() > IDLE_LOCK {
            *s = Session::Locked;
            self.audit.record(
                Event::IdleLocked,
                &format!("no activity for {} minutes", IDLE_LOCK.as_secs() / 60),
            );
            return Err(LOCKED_MSG.into());
        }
        if touch {
            u.last_activity = Instant::now();
        }
        if !save {
            return f(&mut u.registry);
        }
        let mut next = u.registry.clone();
        let out = f(&mut next)?;
        let previous = std::mem::replace(&mut u.registry, next);
        if let Err(e) = self.persist(u) {
            u.registry = previous;
            return Err(e);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_paths(name: &str) -> Paths {
        let dir = std::env::temp_dir().join(format!("session-test-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        Paths {
            store: dir.join("store.v1.json"),
            legacy_registry: dir.join("wallets.json"),
            lockout: dir.join("lockout.json"),
            audit: dir.join("audit.jsonl"),
        }
    }

    fn current_code(secret_b32: &str) -> String {
        let s = totp::secret_from_base32(secret_b32).expect("secret");
        format!(
            "{:06}",
            totp::code_at_step(&s, now_unix() / totp::STEP_SECS, 6)
        )
    }

    #[test]
    fn older_stores_load_with_bitcoin_on() {
        let old = r#"{"version":1,"registry":{"version":1,"wallets":[]},"totp_secret":"HP4BBOUSJXXOTVF27JZMFY4KIBXMWG2Z","totp_last_step":0}"#;
        let c: StoreContents = serde_json::from_str(old).expect("old store");
        assert!(c.settings.bitcoin_enabled);
        let mut v: serde_json::Value = serde_json::from_str(old).expect("json");
        v["settings"] = serde_json::json!({"bitcoin_enabled": false});
        let c: StoreContents = serde_json::from_value(v).expect("with settings");
        assert!(!c.settings.bitcoin_enabled);
    }

    #[test]
    fn setup_lock_unlock_and_replay() {
        let paths = temp_paths("flow");
        let store_path = paths.store.clone();
        let s = SessionState::load(paths);
        assert_eq!(s.status().map(|a| a.state).ok(), Some("needs_setup"));
        assert!(s.with_registry(true, false, |_| Ok(())).is_err());

        let info = s.setup_begin().expect("begin");
        assert!(info.qr_size > 20 && info.qr_modules.len() == info.qr_size * info.qr_size);
        assert!(s
            .setup_finish("short", &current_code(&info.secret))
            .is_err());
        let right = current_code(&info.secret);
        let wrong = format!(
            "{:06}",
            (right.parse::<u32>().expect("n") + 500_000) % 1_000_000
        );
        assert!(s.setup_finish("correct horse battery", &wrong).is_err());
        s.setup_finish("correct horse battery", &right)
            .expect("finish");
        assert_eq!(s.status().map(|a| a.state).ok(), Some("unlocked"));

        // The file on disk isn't readable without the password.
        let text = fs::read_to_string(&store_path).expect("store");
        assert!(!text.contains(&info.secret));

        s.lock(false);
        assert!(s
            .with_registry(true, false, |_| Ok(()))
            .err()
            .is_some_and(|e| e.starts_with(LOCKED_PREFIX)));
        // The code used at setup can't be reused (same 30-second step).
        assert_eq!(s.unlock("correct horse battery", &right), Err(WRONG.into()));
        // Wrong password, recorded as a failure.
        let _ = fs::remove_file(&s.paths.lockout);
        assert_eq!(s.unlock("wrong password!!", "123456"), Err(WRONG.into()));
        assert_eq!(s.read_lockout().failures, 1);
        // While a delay is in force, attempts are refused without checking.
        s.write_lockout(&Lockout {
            failures: 4,
            not_before: now_unix() + 100,
        });
        assert!(s
            .unlock("correct horse battery", "123456")
            .err()
            .is_some_and(|e| e.contains("Try again")));

        // Each step was written to the audit log, oldest first.
        let events: Vec<Event> = s
            .audit()
            .recent(20)
            .expect("audit")
            .into_iter()
            .rev()
            .map(|e| e.event)
            .collect();
        assert_eq!(
            events,
            vec![
                Event::SetupCompleted,
                Event::Locked,
                Event::LoginFailed,
                Event::LoginFailed,
                Event::LoginBlocked,
            ]
        );
        assert!(s.audit().status().intact);
    }
}
