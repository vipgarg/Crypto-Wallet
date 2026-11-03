//! Append-only, hash-chained audit log (ARCHITECTURE.md §9.5, §9.7).
//!
//! One JSON entry per line. Each entry holds the SHA-256 of the previous line
//! (`prev`), so the whole file is checked at every start:
//! - **Detected:** accidental corruption, a changed, removed or reordered
//!   entry, a cut-off file (unless cut exactly at the end, see below).
//! - **Not detected:** someone with access to this PC rewriting the whole
//!   chain, or deleting the newest entries. Writing the head hash on paper
//!   from time to time (shown on the Log page) lets you catch a rewrite of
//!   everything before that point. Not tamper-proof.
//!
//! Privacy: the log is **not encrypted**, because failed logins must be
//! recorded before anyone has logged in. It therefore never contains
//! addresses, labels, amounts or keys: only event names, wallet ids and
//! counts.
//!
//! If the chain is broken at start, the old file is kept beside it (renamed,
//! never deleted) and a new chain starts with an entry saying so.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// `prev` of the first entry.
pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";
/// Longest detail text stored (longer text is cut).
pub const MAX_DETAIL: usize = 200;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Event {
    AppStarted,
    /// The previous log failed verification; it was kept and a new chain began.
    ChainBroken,
    SetupCompleted,
    LoginSucceeded,
    LoginFailed,
    /// A login attempt was refused because of the wrong-attempt delay.
    LoginBlocked,
    Locked,
    IdleLocked,
    WalletAdded,
    WalletRemoved,
    /// Address book entry added / removed / renamed (id and network only).
    AddressAdded,
    AddressRemoved,
    AddressRenamed,
    /// PC safety checks reported a failure or warning.
    ChecksProblem,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub seq: u64,
    /// PC clock time (Unix seconds). The PC clock isn't trusted for security
    /// decisions; it's here to help you read the log.
    pub at: u64,
    pub event: Event,
    pub detail: String,
    /// SHA-256 (hex) of the previous line, or `GENESIS`.
    pub prev: String,
}

fn hash_line(line: &str) -> String {
    hex::encode(Sha256::digest(line.as_bytes()))
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Result of checking a log file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verified {
    /// Every entry chains to the one before. `head` is the hash of the last
    /// line (or `GENESIS` for an empty log).
    Intact { count: u64, head: String },
    /// The chain is broken at entry number `at` (1-based line number).
    Broken { at: u64, reason: String },
}

/// Check a log's text from start to end.
pub fn verify(text: &str) -> Verified {
    let mut prev = GENESIS.to_owned();
    let mut count = 0u64;
    if text.is_empty() {
        return Verified::Intact { count, head: prev };
    }
    if !text.ends_with('\n') {
        let at = text.lines().count() as u64;
        return Verified::Broken {
            at,
            reason: "the last entry is cut off".into(),
        };
    }
    for (i, line) in text.lines().enumerate() {
        let at = i as u64 + 1;
        let Ok(e) = serde_json::from_str::<Entry>(line) else {
            return Verified::Broken {
                at,
                reason: "the entry is unreadable".into(),
            };
        };
        if e.seq != at {
            return Verified::Broken {
                at,
                reason: format!("expected entry #{at}, found #{}", e.seq),
            };
        }
        if e.prev != prev {
            return Verified::Broken {
                at,
                reason: "it doesn't match the entry before it (changed, removed or reordered)"
                    .into(),
            };
        }
        // The hash covers the raw line, so any edit (even extra spaces that
        // keep the JSON valid) is caught by the next entry.
        prev = hash_line(line);
        count = at;
    }
    Verified::Intact { count, head: prev }
}

struct State {
    next_seq: u64,
    head: String,
    /// Set when the log couldn't be written; shown on the Checks page.
    write_error: Option<String>,
    /// Set when the chain was broken at start (kept for the status).
    broken_at_start: Option<String>,
}

pub struct AuditLog {
    path: PathBuf,
    state: Mutex<State>,
}

/// What the Checks and Log pages show.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Status {
    pub intact: bool,
    pub count: u64,
    /// First 12 hex characters of the head hash, for the paper log.
    pub head_short: String,
    pub problem: Option<String>,
}

impl AuditLog {
    /// Open (or create) the log and check it. A broken chain is moved aside
    /// to `<name>.broken-<unix time>` and a new chain is started.
    pub fn open(path: PathBuf) -> Self {
        let text = fs::read_to_string(&path).unwrap_or_default();
        let (state, broken) = match verify(&text) {
            Verified::Intact { count, head } => (
                State {
                    next_seq: count + 1,
                    head,
                    write_error: None,
                    broken_at_start: None,
                },
                None,
            ),
            Verified::Broken { at, reason } => {
                let kept = path.with_extension(format!("broken-{}", now_unix()));
                let moved = fs::rename(&path, &kept).is_ok();
                let msg = format!(
                    "The audit log failed its check at entry #{at}: {reason}. {}",
                    if moved {
                        format!(
                            "The old log was kept as {} and a new log was started.",
                            kept.file_name()
                                .map(|n| n.to_string_lossy().into_owned())
                                .unwrap_or_default()
                        )
                    } else {
                        "The old log couldn't be moved aside.".to_owned()
                    }
                );
                (
                    State {
                        next_seq: 1,
                        head: GENESIS.to_owned(),
                        write_error: None,
                        broken_at_start: Some(msg.clone()),
                    },
                    Some(msg),
                )
            }
        };
        let log = Self {
            path,
            state: Mutex::new(state),
        };
        if let Some(msg) = broken {
            log.record(Event::ChainBroken, &msg);
        }
        log
    }

    /// Append an entry. Never panics; a write failure is kept and reported in
    /// [`AuditLog::status`].
    pub fn record(&self, event: Event, detail: &str) {
        let Ok(mut s) = self.state.lock() else {
            return;
        };
        let detail: String = detail
            .chars()
            .filter(|c| !c.is_control())
            .take(MAX_DETAIL)
            .collect();
        let entry = Entry {
            seq: s.next_seq,
            at: now_unix(),
            event,
            detail,
            prev: s.head.clone(),
        };
        let Ok(line) = serde_json::to_string(&entry) else {
            return;
        };
        match append_line(&self.path, &line) {
            Ok(()) => {
                s.head = hash_line(&line);
                s.next_seq += 1;
            }
            Err(e) => s.write_error = Some(format!("The audit log couldn't be written: {e}.")),
        }
    }

    pub fn status(&self) -> Status {
        let Ok(s) = self.state.lock() else {
            return Status {
                intact: false,
                count: 0,
                head_short: String::new(),
                problem: Some("Internal error.".into()),
            };
        };
        let problem = s.write_error.clone().or_else(|| s.broken_at_start.clone());
        Status {
            intact: problem.is_none(),
            count: s.next_seq - 1,
            head_short: s.head.chars().take(12).collect(),
            problem,
        }
    }

    /// The newest `n` entries, newest first. The file is checked again; if it
    /// was changed while the app was running, that's reported as an error.
    pub fn recent(&self, n: usize) -> Result<Vec<Entry>, String> {
        let _guard = self
            .state
            .lock()
            .map_err(|_| "Internal error.".to_owned())?;
        let text = fs::read_to_string(&self.path).unwrap_or_default();
        if let Verified::Broken { at, reason } = verify(&text) {
            return Err(format!(
                "The audit log failed its check at entry #{at}: {reason}. It was changed while the app was running."
            ));
        }
        Ok(text
            .lines()
            .rev()
            .take(n)
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect())
    }
}

fn append_line(path: &Path, line: &str) -> Result<(), String> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).map_err(|e| e.kind().to_string())?;
    }
    let mut f: File = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| e.kind().to_string())?;
    let mut buf = String::with_capacity(line.len() + 1);
    buf.push_str(line);
    buf.push('\n');
    f.write_all(buf.as_bytes())
        .map_err(|e| e.kind().to_string())?;
    f.sync_all().map_err(|e| e.kind().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("audit-log-test-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("dir");
        dir.join("audit.jsonl")
    }

    #[test]
    fn appends_and_survives_a_restart() {
        let p = temp("restart");
        let log = AuditLog::open(p.clone());
        log.record(Event::AppStarted, "v0.1.0");
        log.record(Event::LoginFailed, "wrong password or code");
        log.record(Event::WalletAdded, "test-01 from signer 73c5da0a");
        let st = log.status();
        assert!(st.intact);
        assert_eq!(st.count, 3);
        drop(log);

        let log = AuditLog::open(p.clone());
        log.record(Event::Locked, "");
        assert_eq!(log.status().count, 4);
        let recent = log.recent(10).expect("recent");
        assert_eq!(recent[0].event, Event::Locked, "newest first");
        assert_eq!(recent[3].seq, 1);
        assert!(matches!(
            verify(&fs::read_to_string(&p).expect("read")),
            Verified::Intact { count: 4, .. }
        ));
    }

    #[test]
    fn detects_changes_removals_and_cut_off_entries() {
        let p = temp("tamper");
        let log = AuditLog::open(p.clone());
        for i in 0..5 {
            log.record(Event::LoginSucceeded, &format!("#{i}"));
        }
        let good = fs::read_to_string(&p).expect("read");
        let lines: Vec<&str> = good.lines().collect();

        // Changed detail in entry #2 → caught at entry #3.
        let edited = good.replacen("\"#1\"", "\"#9\"", 1);
        assert!(matches!(verify(&edited), Verified::Broken { at: 3, .. }));
        // Entry #3 removed.
        let removed: String = lines
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != 2)
            .map(|(_, l)| format!("{l}\n"))
            .collect();
        assert!(matches!(verify(&removed), Verified::Broken { at: 3, .. }));
        // Two entries swapped.
        let mut swapped = lines.clone();
        swapped.swap(1, 2);
        let swapped: String = swapped.iter().map(|l| format!("{l}\n")).collect();
        assert!(matches!(verify(&swapped), Verified::Broken { at: 2, .. }));
        // Cut off in the middle of the last entry.
        assert!(matches!(
            verify(&good[..good.len() - 5]),
            Verified::Broken { at: 5, .. }
        ));
        // Garbage line.
        assert!(matches!(
            verify(&format!("{good}not json\n")),
            Verified::Broken { at: 6, .. }
        ));
        // Known limit: removing the newest entries is not detected by the
        // chain alone (the paper head hash is for that).
        let truncated: String = lines[..3].iter().map(|l| format!("{l}\n")).collect();
        assert!(matches!(
            verify(&truncated),
            Verified::Intact { count: 3, .. }
        ));
    }

    #[test]
    fn broken_log_is_kept_and_a_new_chain_starts() {
        let p = temp("broken");
        let log = AuditLog::open(p.clone());
        log.record(Event::AppStarted, "a");
        log.record(Event::AppStarted, "b");
        drop(log);
        let text = fs::read_to_string(&p)
            .expect("read")
            .replacen("\"a\"", "\"x\"", 1);
        fs::write(&p, text).expect("write");

        let log = AuditLog::open(p.clone());
        let st = log.status();
        assert!(!st.intact);
        assert!(st
            .problem
            .as_deref()
            .unwrap_or_default()
            .contains("entry #2"));
        let recent = log.recent(5).expect("recent");
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].event, Event::ChainBroken);
        // The old file still exists beside the new one.
        let kept = fs::read_dir(p.parent().expect("dir"))
            .expect("ls")
            .filter_map(Result::ok)
            .any(|e| e.file_name().to_string_lossy().contains("broken-"));
        assert!(kept);
    }

    #[test]
    fn change_while_running_is_reported() {
        let p = temp("running");
        let log = AuditLog::open(p.clone());
        log.record(Event::AppStarted, "a");
        log.record(Event::AppStarted, "b");
        let text = fs::read_to_string(&p)
            .expect("read")
            .replacen("\"a\"", "\"x\"", 1);
        fs::write(&p, text).expect("write");
        assert!(log.recent(5).is_err());
    }

    #[test]
    fn details_are_cleaned_and_capped() {
        let p = temp("detail");
        let log = AuditLog::open(p.clone());
        log.record(
            Event::AppStarted,
            &format!("line1\nline2{}", "x".repeat(500)),
        );
        let e = &log.recent(1).expect("recent")[0];
        assert!(!e.detail.contains('\n'));
        assert_eq!(e.detail.chars().count(), MAX_DETAIL);
    }
}
