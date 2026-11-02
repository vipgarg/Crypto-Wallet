//! Start-up checks of the online Windows PC (ARCHITECTURE.md §9.8,
//! ARCHITECTURE-MOBILE.md §5.3).
//!
//! **Honest limit:** these checks catch misconfiguration and unsophisticated
//! malware. Malware with administrator rights can fake every one of them.
//! They are not the security boundary; the signer's screen and your approval
//! are.
//!
//! The Windows-specific parts only run built-in tools (`powershell`,
//! `whoami`, `tasklist`, `reg`) and parse their output. The parsing is kept in
//! pure functions so it is tested on every platform.

use std::time::Duration;

use serde::Serialize;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Pass,
    Warn,
    Fail,
    /// The check couldn't run (e.g. a tool didn't answer).
    Unknown,
    /// Not relevant on this operating system.
    NotApplicable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Check {
    pub id: &'static str,
    pub title: &'static str,
    pub status: Status,
    pub detail: String,
    /// Under the plan, a failure here blocks sending (there is no sending in
    /// the watch-only app yet, so this is shown as information).
    pub blocks_sends: bool,
}

fn check(
    id: &'static str,
    title: &'static str,
    status: Status,
    detail: impl Into<String>,
    blocks_sends: bool,
) -> Check {
    Check {
        id,
        title,
        status,
        detail: detail.into(),
        blocks_sends,
    }
}

// ---------------------------------------------------------------------------
// Pure evaluators (tested everywhere)
// ---------------------------------------------------------------------------

/// `Get-MpComputerStatus` fields as JSON.
pub fn evaluate_defender(json: Option<&str>) -> Check {
    const ID: &str = "defender";
    const TITLE: &str = "Windows Defender";
    let Some(v) = json.and_then(|j| serde_json::from_str::<serde_json::Value>(j).ok()) else {
        return check(
            ID,
            TITLE,
            Status::Unknown,
            "Couldn't read Defender status. If you use another antivirus, check that it is on and up to date.",
            true,
        );
    };
    let b = |k: &str| v.get(k).and_then(serde_json::Value::as_bool);
    let n = |k: &str| v.get(k).and_then(serde_json::Value::as_u64);
    if b("AMServiceEnabled") == Some(false) || b("RealTimeProtectionEnabled") == Some(false) {
        return check(
            ID,
            TITLE,
            Status::Fail,
            "Real-time protection is OFF.",
            true,
        );
    }
    let sig_age = n("AntivirusSignatureAge");
    let scan_age = n("QuickScanAge");
    let mut problems = Vec::new();
    if sig_age.is_none_or(|d| d > 7) {
        problems.push(format!(
            "virus definitions are {} days old (should be 7 or less)",
            sig_age.map_or("an unknown number of".into(), |d| d.to_string())
        ));
    }
    if scan_age.is_none_or(|d| d > 7) {
        problems.push("no quick scan in the last 7 days".to_owned());
    }
    if problems.is_empty() {
        check(
            ID,
            TITLE,
            Status::Pass,
            format!(
                "Real-time protection on; definitions {} day(s) old; last quick scan {} day(s) ago.",
                sig_age.unwrap_or(0),
                scan_age.unwrap_or(0)
            ),
            true,
        )
    } else {
        check(
            ID,
            TITLE,
            Status::Warn,
            format!("Real-time protection on, but {}.", problems.join(" and ")),
            true,
        )
    }
}

/// `{"hotfixAgeDays": n, "rebootRequired": bool}` from PowerShell.
pub fn evaluate_updates(json: Option<&str>) -> Check {
    const ID: &str = "windows_update";
    const TITLE: &str = "Windows updates";
    let Some(v) = json.and_then(|j| serde_json::from_str::<serde_json::Value>(j).ok()) else {
        return check(
            ID,
            TITLE,
            Status::Unknown,
            "Couldn't read the update history.",
            false,
        );
    };
    let age = v.get("hotfixAgeDays").and_then(serde_json::Value::as_u64);
    let reboot = v
        .get("rebootRequired")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let mut problems = Vec::new();
    if age.is_none_or(|d| d > 45) {
        problems.push(format!(
            "the latest update was installed {} days ago (should be 45 or less)",
            age.map_or("an unknown number of".into(), |d| d.to_string())
        ));
    }
    if reboot {
        problems.push("a restart is pending to finish installing updates".to_owned());
    }
    if problems.is_empty() {
        check(
            ID,
            TITLE,
            Status::Pass,
            format!("Latest update installed {} day(s) ago.", age.unwrap_or(0)),
            false,
        )
    } else {
        check(
            ID,
            TITLE,
            Status::Warn,
            format!("{}.", capitalize(&problems.join("; "))),
            false,
        )
    }
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
        None => String::new(),
    }
}

/// `whoami /groups /fo csv /nh` output.
pub fn evaluate_account(groups_csv: Option<&str>) -> Check {
    const ID: &str = "account";
    const TITLE: &str = "Windows account";
    let Some(text) = groups_csv else {
        return check(
            ID,
            TITLE,
            Status::Unknown,
            "Couldn't read the account's groups.",
            true,
        );
    };
    let elevated = text.contains("S-1-16-12288") || text.contains("S-1-16-16384");
    let admin_member = text.lines().any(|l| l.contains("S-1-5-32-544"));
    if elevated {
        check(ID, TITLE, Status::Fail, "The app is running with administrator rights (\"Run as administrator\"). Run it normally from a standard account.", true)
    } else if admin_member {
        check(ID, TITLE, Status::Warn, "This is an administrator account. The plan expects a separate standard (non-admin) \"wallet\" account.", true)
    } else {
        check(
            ID,
            TITLE,
            Status::Pass,
            "Standard (non-admin) account, not elevated.",
            true,
        )
    }
}

/// Process names of remote-access tools (lower case). Several are commonly
/// used in "support" scams.
pub const REMOTE_TOOLS: &[(&str, &str)] = &[
    ("anydesk.exe", "AnyDesk"),
    ("teamviewer.exe", "TeamViewer"),
    ("teamviewer_service.exe", "TeamViewer"),
    ("rustdesk.exe", "RustDesk"),
    ("ultraviewer_desktop.exe", "UltraViewer"),
    ("ultraviewer_service.exe", "UltraViewer"),
    ("remoting_host.exe", "Chrome Remote Desktop"),
    ("screenconnect.clientservice.exe", "ScreenConnect"),
    ("screenconnect.windowsclient.exe", "ScreenConnect"),
    ("awesun.exe", "AweSun"),
    ("todesk.exe", "ToDesk"),
    ("splashtopstreamer.exe", "Splashtop"),
    ("srservice.exe", "Splashtop"),
    ("parsecd.exe", "Parsec"),
    ("rutserv.exe", "Remote Utilities"),
    ("rfusclient.exe", "Remote Utilities"),
    ("supremo.exe", "Supremo"),
    ("supremoservice.exe", "Supremo"),
    ("quickassist.exe", "Windows Quick Assist"),
    ("msra.exe", "Windows Remote Assistance"),
    ("aa_v3.exe", "Ammyy Admin"),
    ("winvnc.exe", "VNC"),
    ("tvnserver.exe", "TightVNC"),
    ("vncserver.exe", "VNC"),
];

/// `tasklist /fo csv /nh` output plus the `SESSIONNAME` variable.
pub fn evaluate_remote_access(tasklist_csv: Option<&str>, session_name: Option<&str>) -> Check {
    const ID: &str = "remote_access";
    const TITLE: &str = "Remote-access tools";
    if session_name.is_some_and(|s| s.to_ascii_uppercase().starts_with("RDP-")) {
        return check(
            ID,
            TITLE,
            Status::Fail,
            "This is a Remote Desktop session. Use the wallet only while sitting at the PC.",
            true,
        );
    }
    let Some(text) = tasklist_csv else {
        return check(
            ID,
            TITLE,
            Status::Unknown,
            "Couldn't list running programs.",
            true,
        );
    };
    let mut found: Vec<&str> = Vec::new();
    for line in text.lines() {
        let name = line
            .trim()
            .trim_start_matches('"')
            .split('"')
            .next()
            .unwrap_or("")
            .to_ascii_lowercase();
        if let Some((_, label)) = REMOTE_TOOLS.iter().find(|(exe, _)| *exe == name) {
            if !found.contains(label) {
                found.push(label);
            }
        }
    }
    if found.is_empty() {
        check(
            ID,
            TITLE,
            Status::Pass,
            "No remote-access tool is running.",
            true,
        )
    } else {
        check(
            ID,
            TITLE,
            Status::Fail,
            format!(
                "Running: {}. Close it and uninstall it from the wallet account. Nobody legitimate needs remote access to your wallet PC.",
                found.join(", ")
            ),
            true,
        )
    }
}

/// Proxy from environment variables and the Windows "Internet Settings".
pub fn evaluate_proxy(env_proxy: Option<&str>, reg_query: Option<&str>) -> Check {
    const ID: &str = "proxy";
    const TITLE: &str = "Network proxy";
    let reg_on = reg_query.is_some_and(|t| {
        t.lines()
            .any(|l| l.contains("ProxyEnable") && l.trim_end().ends_with("0x1"))
    });
    match (env_proxy.filter(|s| !s.trim().is_empty()), reg_on) {
        (None, false) => check(ID, TITLE, Status::Pass, "No proxy is set.", true),
        (env, reg) => {
            let mut parts = Vec::new();
            if let Some(e) = env {
                parts.push(format!(
                    "environment variable set ({})",
                    e.chars().take(60).collect::<String>()
                ));
            }
            if reg {
                parts.push("Windows proxy setting is ON".to_owned());
            }
            check(
                ID,
                TITLE,
                Status::Warn,
                format!(
                    "{}. A proxy you didn't set up can read or change your network traffic.",
                    capitalize(&parts.join("; "))
                ),
                true,
            )
        }
    }
}

/// Compare the PC clock with recent block times from providers.
/// `observed` = (provider, block timestamp in Unix seconds).
pub fn evaluate_clock(now_unix: u64, observed: &[(String, u64)]) -> Check {
    const ID: &str = "clock";
    const TITLE: &str = "PC clock";
    const MAX_DIFF: i64 = 120;
    if observed.is_empty() {
        return check(
            ID,
            TITLE,
            Status::Unknown,
            "Couldn't get the current block time from any provider.",
            true,
        );
    }
    let diffs: Vec<i64> = observed
        .iter()
        .map(|(_, ts)| {
            i64::try_from(now_unix).unwrap_or(i64::MAX) - i64::try_from(*ts).unwrap_or(0)
        })
        .collect();
    let best = diffs
        .iter()
        .copied()
        .min_by_key(|d| d.abs())
        .unwrap_or(i64::MAX);
    if best.abs() <= MAX_DIFF {
        check(
            ID,
            TITLE,
            Status::Pass,
            format!("Within {} seconds of the blockchain's time.", best.abs()),
            true,
        )
    } else {
        check(
            ID,
            TITLE,
            Status::Fail,
            format!(
                "The PC clock is {} seconds {} the blockchain's time. Turn on \"Set time automatically\" in Windows settings.",
                best.abs(),
                if best > 0 { "ahead of" } else { "behind" }
            ),
            true,
        )
    }
}

/// SHA-256 of the running app file, to compare with the reviewed release.
pub fn exe_fingerprint() -> Check {
    const ID: &str = "app_file";
    const TITLE: &str = "App file fingerprint";
    let result = std::env::current_exe().and_then(std::fs::read);
    match result {
        Ok(bytes) => {
            let hash = hex::encode(Sha256::digest(&bytes));
            check(
                ID,
                TITLE,
                Status::Pass,
                format!(
                    "SHA-256 {hash}. Compare with the hash recorded for the reviewed release (development builds change on every build)."
                ),
                false,
            )
        }
        Err(_) => check(
            ID,
            TITLE,
            Status::Unknown,
            "Couldn't read the app file.",
            false,
        ),
    }
}

// ---------------------------------------------------------------------------
// Running the Windows tools
// ---------------------------------------------------------------------------

/// Longest time a single tool may take before the check is reported unknown.
pub const TOOL_TIMEOUT: Duration = Duration::from_secs(20);

#[cfg(windows)]
fn run_tool(program: &str, args: &[&str]) -> Option<String> {
    use std::os::windows::process::CommandExt;
    use std::process::Command;
    use std::sync::mpsc;
    // CREATE_NO_WINDOW: don't flash a console window.
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let mut cmd = Command::new(program);
    cmd.args(args).creation_flags(CREATE_NO_WINDOW);
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(cmd.output());
    });
    let out = rx.recv_timeout(TOOL_TIMEOUT).ok()?.ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    (!text.is_empty()).then_some(text)
}

#[cfg(windows)]
fn powershell(script: &str) -> Option<String> {
    run_tool(
        "powershell.exe",
        &[
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ],
    )
}

/// Run every local check. Slow-ish (a few seconds): call it off the UI thread.
pub fn run_local_checks() -> Vec<Check> {
    let env_proxy = std::env::var("HTTPS_PROXY")
        .or_else(|_| std::env::var("HTTP_PROXY"))
        .or_else(|_| std::env::var("ALL_PROXY"))
        .ok();
    let mut checks = vec![exe_fingerprint()];

    #[cfg(windows)]
    {
        let defender = powershell(
            "Get-MpComputerStatus | Select-Object AMServiceEnabled,RealTimeProtectionEnabled,AntivirusSignatureAge,QuickScanAge | ConvertTo-Json -Compress",
        );
        let updates = powershell(
            "$h = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1; \
             $age = if ($h -and $h.InstalledOn) { ((Get-Date) - $h.InstalledOn).Days } else { $null }; \
             $r = Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired'; \
             @{ hotfixAgeDays = $age; rebootRequired = $r } | ConvertTo-Json -Compress",
        );
        let groups = run_tool("whoami.exe", &["/groups", "/fo", "csv", "/nh"]);
        let tasks = run_tool("tasklist.exe", &["/fo", "csv", "/nh"]);
        let reg = run_tool(
            "reg.exe",
            &[
                "query",
                "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
                "/v",
                "ProxyEnable",
            ],
        );
        let session = std::env::var("SESSIONNAME").ok();
        checks.push(evaluate_account(groups.as_deref()));
        checks.push(evaluate_defender(defender.as_deref()));
        checks.push(evaluate_updates(updates.as_deref()));
        checks.push(evaluate_remote_access(tasks.as_deref(), session.as_deref()));
        checks.push(evaluate_proxy(env_proxy.as_deref(), reg.as_deref()));
    }

    #[cfg(not(windows))]
    {
        for (id, title) in [
            ("account", "Windows account"),
            ("defender", "Windows Defender"),
            ("windows_update", "Windows updates"),
            ("remote_access", "Remote-access tools"),
        ] {
            checks.push(check(
                id,
                title,
                Status::NotApplicable,
                "Only checked on Windows.",
                false,
            ));
        }
        checks.push(evaluate_proxy(env_proxy.as_deref(), None));
    }
    checks
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defender() {
        let ok = r#"{"AMServiceEnabled":true,"RealTimeProtectionEnabled":true,"AntivirusSignatureAge":1,"QuickScanAge":2}"#;
        assert_eq!(evaluate_defender(Some(ok)).status, Status::Pass);
        let off = r#"{"AMServiceEnabled":true,"RealTimeProtectionEnabled":false,"AntivirusSignatureAge":1,"QuickScanAge":2}"#;
        assert_eq!(evaluate_defender(Some(off)).status, Status::Fail);
        // "Never scanned" is reported by Windows as a huge number of days.
        let stale = r#"{"AMServiceEnabled":true,"RealTimeProtectionEnabled":true,"AntivirusSignatureAge":12,"QuickScanAge":4294967295}"#;
        let c = evaluate_defender(Some(stale));
        assert_eq!(c.status, Status::Warn);
        assert!(c.detail.contains("12 days") && c.detail.contains("quick scan"));
        assert_eq!(evaluate_defender(None).status, Status::Unknown);
        assert_eq!(evaluate_defender(Some("not json")).status, Status::Unknown);
    }

    #[test]
    fn updates() {
        assert_eq!(
            evaluate_updates(Some(r#"{"hotfixAgeDays":10,"rebootRequired":false}"#)).status,
            Status::Pass
        );
        assert_eq!(
            evaluate_updates(Some(r#"{"hotfixAgeDays":60,"rebootRequired":false}"#)).status,
            Status::Warn
        );
        let c = evaluate_updates(Some(r#"{"hotfixAgeDays":3,"rebootRequired":true}"#));
        assert_eq!(c.status, Status::Warn);
        assert!(c.detail.contains("restart"));
        assert_eq!(
            evaluate_updates(Some(r#"{"hotfixAgeDays":null,"rebootRequired":false}"#)).status,
            Status::Warn
        );
    }

    #[test]
    fn account() {
        let standard = "\"Everyone\",\"Well-known group\",\"S-1-1-0\",\"Mandatory group, Enabled by default, Enabled group\"\n\"Mandatory Label\\Medium Mandatory Level\",\"Label\",\"S-1-16-8192\",\"\"";
        assert_eq!(evaluate_account(Some(standard)).status, Status::Pass);
        let admin_filtered = format!("{standard}\n\"BUILTIN\\Administrators\",\"Alias\",\"S-1-5-32-544\",\"Group used for deny only\"");
        assert_eq!(evaluate_account(Some(&admin_filtered)).status, Status::Warn);
        let elevated = "\"BUILTIN\\Administrators\",\"Alias\",\"S-1-5-32-544\",\"Enabled group\"\n\"Mandatory Label\\High Mandatory Level\",\"Label\",\"S-1-16-12288\",\"\"";
        assert_eq!(evaluate_account(Some(elevated)).status, Status::Fail);
        assert_eq!(evaluate_account(None).status, Status::Unknown);
    }

    #[test]
    fn remote_access() {
        let clean = "\"explorer.exe\",\"1\",\"Console\",\"1\",\"10 K\"\n\"msedge.exe\",\"2\",\"Console\",\"1\",\"10 K\"";
        assert_eq!(
            evaluate_remote_access(Some(clean), Some("Console")).status,
            Status::Pass
        );
        let bad = format!("{clean}\n\"AnyDesk.exe\",\"3\",\"Console\",\"1\",\"10 K\"\n\"QuickAssist.exe\",\"4\",\"Console\",\"1\",\"1 K\"");
        let c = evaluate_remote_access(Some(&bad), Some("Console"));
        assert_eq!(c.status, Status::Fail);
        assert!(c.detail.contains("AnyDesk") && c.detail.contains("Quick Assist"));
        assert_eq!(
            evaluate_remote_access(Some(clean), Some("RDP-Tcp#3")).status,
            Status::Fail
        );
        assert_eq!(
            evaluate_remote_access(None, Some("Console")).status,
            Status::Unknown
        );
    }

    #[test]
    fn proxy() {
        assert_eq!(evaluate_proxy(None, None).status, Status::Pass);
        let off = "\n    ProxyEnable    REG_DWORD    0x0\n";
        assert_eq!(evaluate_proxy(None, Some(off)).status, Status::Pass);
        let on = "\n    ProxyEnable    REG_DWORD    0x1\n";
        assert_eq!(evaluate_proxy(None, Some(on)).status, Status::Warn);
        assert_eq!(
            evaluate_proxy(Some("http://10.0.0.1:8080"), None).status,
            Status::Warn
        );
        assert_eq!(evaluate_proxy(Some("  "), None).status, Status::Pass);
    }

    #[test]
    fn clock() {
        let now = 1_800_000_000;
        assert_eq!(evaluate_clock(now, &[]).status, Status::Unknown);
        assert_eq!(
            evaluate_clock(now, &[("a".into(), now - 14)]).status,
            Status::Pass
        );
        let c = evaluate_clock(now, &[("a".into(), now - 600), ("b".into(), now - 590)]);
        assert_eq!(c.status, Status::Fail);
        assert!(c.detail.contains("590 seconds ahead"));
        assert!(evaluate_clock(now, &[("a".into(), now + 300)])
            .detail
            .contains("behind"));
    }

    #[test]
    fn fingerprint_runs() {
        let c = exe_fingerprint();
        assert_eq!(c.status, Status::Pass);
        assert!(c.detail.starts_with("SHA-256 "));
    }
}
