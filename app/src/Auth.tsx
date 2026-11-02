import { useEffect, useState } from "react";
import { api, errorText, type CheckStatus, type SetupInfo, type SystemCheck } from "./api";

const STATUS_ICON: Record<CheckStatus, string> = {
  pass: "✓",
  warn: "!",
  fail: "✗",
  unknown: "?",
  not_applicable: "–",
};

/** Start-up checks (§9.8). Shown on the login screen and the Checks page. */
export function ChecksPanel({ compact = false }: { compact?: boolean }) {
  const [checks, setChecks] = useState<SystemCheck[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [running, setRunning] = useState(false);

  const run = async () => {
    setRunning(true);
    setError(null);
    try {
      setChecks(await api.startupChecks());
    } catch (e) {
      setError(errorText(e));
    } finally {
      setRunning(false);
    }
  };

  useEffect(() => {
    void run();
  }, []);

  const problems = checks?.filter((c) => c.status === "fail" || c.status === "warn") ?? [];
  const shown = compact ? problems : (checks ?? []);

  return (
    <div className="card checks">
      <div className="section-head">
        <h3>PC safety checks</h3>
        <button className="secondary" onClick={() => void run()} disabled={running}>
          {running ? "Checking…" : "Run again"}
        </button>
      </div>
      {error && <p className="error">{error}</p>}
      {!checks && !error && <p className="muted">Checking this PC…</p>}
      {checks && compact && problems.length === 0 && (
        <p className="ok-text">✓ No problems found ({checks.length} checks).</p>
      )}
      {shown.length > 0 && (
        <ul className="check-list">
          {shown.map((c) => (
            <li key={c.id} className={`check check-${c.status}`}>
              <span className="check-icon">{STATUS_ICON[c.status]}</span>
              <div>
                <div className="check-title">{c.title}</div>
                <div className="check-detail">{c.detail}</div>
              </div>
            </li>
          ))}
        </ul>
      )}
      <p className="hint">
        These checks catch common problems and simple malware. Malware with administrator rights can fake them, so they
        are not the security boundary: your signer's screen and your approval are.
      </p>
    </div>
  );
}

function QrCode({ size, modules }: { size: number; modules: boolean[] }) {
  const quiet = 4;
  const total = size + quiet * 2;
  const rects = [];
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      if (modules[y * size + x]) rects.push(<rect key={`${x}-${y}`} x={x + quiet} y={y + quiet} width={1} height={1} />);
    }
  }
  return (
    <svg className="qr" viewBox={`0 0 ${total} ${total}`} width={220} height={220} shapeRendering="crispEdges">
      <rect width={total} height={total} fill="#fff" />
      <g fill="#000">{rects}</g>
    </svg>
  );
}

export function SetupScreen({ hasLegacy, onDone }: { hasLegacy: boolean; onDone: () => void }) {
  const [step, setStep] = useState<1 | 2>(1);
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [info, setInfo] = useState<SetupInfo | null>(null);
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const next = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    if ([...password].length < 12) return setError("Use at least 12 characters.");
    if (password !== confirm) return setError("The two passwords don't match.");
    try {
      setInfo(await api.setupBegin());
      setStep(2);
    } catch (err) {
      setError(errorText(err));
    }
  };

  const finish = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.setupFinish(password, code);
      setPassword("");
      setConfirm("");
      onDone();
    } catch (err) {
      setError(errorText(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="auth">
      <h1>Set up Watch-Only Wallet</h1>
      <p className="hint">
        This app holds no keys, so this login protects your wallet list and privacy, not your funds. It encrypts the
        wallet list on this PC and asks for a code from your phone.
      </p>
      {hasLegacy && (
        <p className="warning">Your existing wallet list will be moved into the encrypted file during setup.</p>
      )}
      {error && <p className="error">{error}</p>}
      {step === 1 && (
        <form className="card form" onSubmit={(e) => void next(e)}>
          <h3>Step 1 of 2: choose a password</h3>
          <label>
            Password <span className="muted">(at least 12 characters; a few random words work well)</span>
            <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" autoFocus />
          </label>
          <label>
            Type it again
            <input type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)} autoComplete="new-password" />
          </label>
          <button type="submit">Next</button>
        </form>
      )}
      {step === 2 && info && (
        <form className="card form" onSubmit={(e) => void finish(e)}>
          <h3>Step 2 of 2: link your authenticator app</h3>
          <ol>
            <li>Open an authenticator app on your phone (Google Authenticator, Microsoft Authenticator, Aegis…).</li>
            <li>Add an account by scanning this QR code.</li>
            <li>
              Write the text code below on paper and keep it with your recovery runbook. If you lose your phone, it's
              how you set the app up again.
            </li>
            <li>Type the 6-digit code the app shows.</li>
          </ol>
          <div className="qr-wrap">
            <QrCode size={info.qr_size} modules={info.qr_modules} />
            <div className="mono secret">{info.secret.match(/.{1,4}/g)?.join(" ")}</div>
          </div>
          <label>
            6-digit code
            <input
              value={code}
              onChange={(e) => setCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
              inputMode="numeric"
              autoComplete="one-time-code"
              className="mono code"
            />
          </label>
          <button type="submit" disabled={busy || code.length !== 6}>
            {busy ? "Encrypting…" : "Finish setup"}
          </button>
        </form>
      )}
      <ChecksPanel compact />
    </div>
  );
}

export function LoginScreen({ waitSecs, onDone }: { waitSecs: number; onDone: () => void }) {
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(waitSecs > 0 ? `Too many wrong attempts. Try again in ${waitSecs} seconds.` : null);
  const [busy, setBusy] = useState(false);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.unlock(password, code);
      setPassword("");
      onDone();
    } catch (err) {
      setError(errorText(err));
      setCode("");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="auth">
      <h1>Watch-Only Wallet</h1>
      <form className="card form" onSubmit={(e) => void submit(e)}>
        <h3>Log in</h3>
        {error && <p className="error">{error}</p>}
        <label>
          Password
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" autoFocus />
        </label>
        <label>
          6-digit code from your authenticator app
          <input
            value={code}
            onChange={(e) => setCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
            inputMode="numeric"
            autoComplete="one-time-code"
            className="mono code"
          />
        </label>
        <button type="submit" disabled={busy || password.length === 0 || code.length !== 6}>
          {busy ? "Checking…" : "Log in"}
        </button>
        <p className="hint">
          Forgot the password or lost the authenticator? Your funds are not affected (no keys are on this PC). Delete
          the file store.v1.json in the app's data folder and set the app up again; then re-add your wallets' public
          addresses.
        </p>
      </form>
      <ChecksPanel compact />
    </div>
  );
}
