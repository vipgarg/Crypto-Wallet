import { useCallback, useEffect, useRef, useState } from "react";
import { ChecksPanel, LoginScreen, SetupScreen } from "./Auth";
import { ReceivePage } from "./Receive";
import {
  LOCKED_EVENT,
  type AuthStatus,
  api,
  errorText,
  type AppInfo,
  type AssetBalance,
  type BalanceStatus,
  type Portfolio,
  type Progress,
  type ActivityEntry,
  type Flag,
  type WalletActivity,
  type TxEntry,
  type Tier,
  type WalletView,
} from "./api";
import { AddFromSigner } from "./ScanSigner";
import { AuditLogPage } from "./AuditLog";

type Page = "portfolio" | "receive" | "activity" | "wallets" | "checks" | "log" | "about";

const STATUS_TEXT: Record<BalanceStatus, string> = {
  verified: "Verified (2+ sources agree)",
  unverified: "Unverified (1 source)",
  disagreement: "Sources disagree",
  unavailable: "Unavailable",
};

function StatusBadge({ status }: { status: BalanceStatus }) {
  return <span className={`badge badge-${status}`}>{STATUS_TEXT[status]}</span>;
}

function BalanceCell({ b }: { b: AssetBalance }) {
  return (
    <div className="balance">
      <div className="balance-main">
        <span className="amount">{b.display ?? "—"}</span>
        <span className="asset-label">{b.label}</span>
      </div>
      <StatusBadge status={b.status} />
      {b.problems.length > 0 && (
        <ul className="problems">
          {b.problems.map((p, i) => (
            <li key={i}>{p}</li>
          ))}
        </ul>
      )}
    </div>
  );
}

function seconds(ms: number): string {
  return `${Math.floor(ms / 1000)}.${Math.floor((ms % 1000) / 100)} s`;
}

function ProgressLog({ progress, live }: { progress: Progress; live: boolean }) {
  const end = useRef<HTMLDivElement>(null);
  const lines = live ? progress.lines.slice(-14) : progress.lines;
  useEffect(() => {
    if (live) end.current?.scrollIntoView({ block: "nearest" });
  }, [live, progress.lines.length]);
  return (
    <div className="log">
      {lines.map((l, i) => (
        <div key={i} className={`log-line log-${l.level}`}>
          <span className="log-time">{seconds(l.at_ms)}</span> {l.text}
        </div>
      ))}
      <div ref={end} />
    </div>
  );
}

/** Portfolio state lives at the app level, so a refresh keeps running and its
 * result is kept while you switch tabs. */
function usePortfolio() {
  const [data, setData] = useState<Portfolio | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [progress, setProgress] = useState<Progress | null>(null);
  const [stale, setStale] = useState(false);
  const running = useRef(false);

  // While a refresh runs, ask Rust for the progress log twice a second.
  useEffect(() => {
    if (!loading) return;
    let stopped = false;
    const poll = async () => {
      try {
        const p = await api.getProgress();
        if (!stopped) setProgress(p);
      } catch {
        /* progress is best-effort */
      }
    };
    void poll();
    const timer = window.setInterval(() => void poll(), 500);
    return () => {
      stopped = true;
      window.clearInterval(timer);
    };
  }, [loading]);

  const refresh = useCallback(async () => {
    // Guard: never start a second refresh from the UI (React's development
    // mode runs effects twice, and buttons can be double-clicked).
    if (running.current) return;
    running.current = true;
    setLoading(true);
    setError(null);
    setStale(false);
    try {
      setData(await api.getPortfolio());
    } catch (e) {
      setError(errorText(e));
    } finally {
      running.current = false;
      setLoading(false);
      api.getProgress().then(setProgress, () => undefined);
    }
  }, []);

  // One automatic refresh when the app opens.
  const started = useRef(false);
  useEffect(() => {
    if (started.current) return;
    started.current = true;
    void refresh();
  }, [refresh]);

  return { data, error, loading, progress, stale, refresh, markStale: () => setStale(true) };
}

type PortfolioState = ReturnType<typeof usePortfolio>;

function PortfolioPage({ state }: { state: PortfolioState }) {
  const { data, error, loading, progress, stale, refresh } = state;

  return (
    <section>
      <div className="section-head">
        <h2>Portfolio</h2>
        <button onClick={() => void refresh()} disabled={loading}>
          {loading ? "Checking providers…" : "Refresh"}
        </button>
      </div>
      <p className="hint">
        Every balance is asked of at least two independent providers. Only identical answers count as
        verified; nothing is decided by majority.
      </p>
      {loading && (
        <div className="card progress">
          <div className="progress-head">
            <strong>Checking providers…</strong>
            <span className="muted">
              {progress ? `${seconds(progress.elapsed_ms)} · ${progress.checks} checks done` : "starting"}
            </span>
          </div>
          {progress && <ProgressLog progress={progress} live />}
        </div>
      )}
      {error && <p className="error">{error}</p>}
      {stale && !loading && (
        <p className="warning">The wallet list changed since the last refresh. Click Refresh to update.</p>
      )}
      {data?.warnings.map((w, i) => (
        <p key={i} className="warning">
          {w}
        </p>
      ))}
      {data && data.wallets.length === 0 && <p>No wallets yet. Add one on the Wallets page.</p>}
      {data && data.totals.length > 0 && (
        <div className="totals">
          {data.totals.map((t) => (
            <div key={t.asset} className="total">
              <div className="amount">{t.display ?? "—"}</div>
              <div className="asset-label">{t.label}</div>
              {t.display === null ? (
                <div className="incomplete">Not verified: no total shown</div>
              ) : (
                !t.complete && <div className="incomplete">Incomplete: some balances not verified</div>
              )}
            </div>
          ))}
        </div>
      )}
      {!loading && progress && progress.lines.length > 0 && (
        <details className="card">
          <summary>
            Last refresh log: {seconds(progress.elapsed_ms)}, {progress.checks} checks
          </summary>
          <ProgressLog progress={progress} live={false} />
        </details>
      )}
      {data?.wallets.map((w) => (
        <div key={w.id} className="card">
          <h3>
            {w.label} <span className="muted">· {w.id} · {w.tier_name}</span>
          </h3>
          <div className="balances">
            {w.balances.map((b) => (
              <BalanceCell key={b.asset} b={b} />
            ))}
          </div>
        </div>
      ))}
    </section>
  );
}

const TIERS: { value: Tier; label: string }[] = [
  { value: "savings", label: "T-1 Savings" },
  { value: "spending", label: "T-2 Spending" },
  { value: "vault", label: "T-0 Vault" },
  { value: "watch_only", label: "T-W Watch-only" },
];

function WalletsPage({ onChanged }: { onChanged: () => void }) {
  const [wallets, setWallets] = useState<WalletView[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [form, setForm] = useState({ id: "", label: "", tier: "savings" as Tier, btc: "", eth: "", tron: "" });
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api.listWallets().then(setWallets, (e) => setError(errorText(e)));
  }, []);

  const set = (k: keyof typeof form) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) =>
    setForm({ ...form, [k]: e.target.value });

  const add = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const orNull = (s: string) => (s.trim() === "" ? null : s.trim());
      setWallets(
        await api.addWallet({
          id: form.id,
          label: form.label,
          tier: form.tier,
          btc: orNull(form.btc),
          eth: orNull(form.eth),
          tron: orNull(form.tron),
        }),
      );
      onChanged();
      setForm({ id: "", label: "", tier: "savings", btc: "", eth: "", tron: "" });
    } catch (err) {
      setError(errorText(err));
    } finally {
      setBusy(false);
    }
  };

  const remove = async (id: string) => {
    if (!window.confirm(`Stop watching "${id}"? This only removes it from this app; funds are not affected.`)) return;
    try {
      setWallets(await api.removeWallet(id));
      onChanged();
    } catch (err) {
      setError(errorText(err));
    }
  };

  return (
    <section>
      <h2>Wallets</h2>
      <p className="hint">
        Watch-only: enter <strong>public</strong> data only (a BIP-84 zpub/xpub or address, an Ethereum address, a
        TRON address). Never type a seed phrase or private key into this computer.
      </p>
      {error && <p className="error">{error}</p>}
      {wallets.map((w) => (
        <div key={w.id} className="card">
          <h3>
            {w.label} <span className="muted">· {w.id} · {w.tier_name}</span>
          </h3>
          {w.signer_fingerprint && (
            <p className="hint">From the signer tablet · fingerprint {w.signer_fingerprint}</p>
          )}
          <dl>
            {w.btc && (
              <>
                <dt>Bitcoin</dt>
                <dd className="mono">
                  {w.btc.kind === "account_xpub" ? `Account key, fingerprint ${w.btc.fingerprint}` : w.btc.address}
                </dd>
              </>
            )}
            {w.eth && (
              <>
                <dt>Ethereum</dt>
                <dd className="mono">{w.eth}</dd>
              </>
            )}
            {w.tron && (
              <>
                <dt>TRON</dt>
                <dd className="mono">{w.tron}</dd>
              </>
            )}
          </dl>
          <button className="danger" onClick={() => void remove(w.id)}>
            Stop watching
          </button>
        </div>
      ))}

      <AddFromSigner
        onAdded={(w) => {
          setWallets(w);
          onChanged();
        }}
      />

      <form className="card form" onSubmit={(e) => void add(e)}>
        <h3>Or add a wallet by hand</h3>
        <p className="hint">
          For wallets not made on the tablet (e.g. an exchange deposit address). Prefer the tablet export above: it
          avoids typing mistakes.
        </p>
        <label>
          ID <span className="muted">(e.g. savings-01)</span>
          <input value={form.id} onChange={set("id")} required maxLength={32} autoComplete="off" spellCheck={false} />
        </label>
        <label>
          Label
          <input value={form.label} onChange={set("label")} required maxLength={40} autoComplete="off" />
        </label>
        <label>
          Tier
          <select value={form.tier} onChange={set("tier")}>
            {TIERS.map((t) => (
              <option key={t.value} value={t.value}>
                {t.label}
              </option>
            ))}
          </select>
        </label>
        <label>
          Bitcoin <span className="muted">(zpub/xpub at m/84'/0'/0', or one address)</span>
          <input value={form.btc} onChange={set("btc")} className="mono" autoComplete="off" spellCheck={false} />
        </label>
        <label>
          Ethereum address <span className="muted">(checksummed 0x…)</span>
          <input value={form.eth} onChange={set("eth")} className="mono" autoComplete="off" spellCheck={false} />
        </label>
        <label>
          TRON address <span className="muted">(T…)</span>
          <input value={form.tron} onChange={set("tron")} className="mono" autoComplete="off" spellCheck={false} />
        </label>
        <button type="submit" disabled={busy}>
          Add wallet
        </button>
      </form>
    </section>
  );
}

function AboutPage() {
  const [info, setInfo] = useState<AppInfo | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    api.appInfo().then(setInfo, (e) => setError(errorText(e)));
  }, []);
  if (error) return <p className="error">{error}</p>;
  if (!info) return null;
  return (
    <section>
      <h2>About this build</h2>
      <dl>
        <dt>Version</dt>
        <dd>{info.version}</dd>
        <dt>Network config SHA-256</dt>
        <dd className="mono">{info.config_sha256}</dd>
        <dt>Pinned USDT (Ethereum)</dt>
        <dd className="mono">{info.usdt_erc20}</dd>
        <dt>Pinned USDT (TRON)</dt>
        <dd className="mono">{info.usdt_trc20}</dd>
      </dl>
      <p className="hint">Compare the config hash with the value recorded for the reviewed release.</p>
      {info.independence_warnings.map((w, i) => (
        <p key={i} className="warning">
          {w}
        </p>
      ))}
      <h3>Data providers</h3>
      <table>
        <thead>
          <tr>
            <th>Network</th>
            <th>Provider</th>
            <th>Operator</th>
            <th>URL</th>
          </tr>
        </thead>
        <tbody>
          {info.providers.map((p) => (
            <tr key={p.id}>
              <td>{p.network}</td>
              <td>{p.id}</td>
              <td>{p.operator}</td>
              <td className="mono">{p.base_url}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}

const DIRECTION_TEXT: Record<ActivityEntry["direction"], string> = {
  in: "↓ Received",
  out: "↑ Sent",
  self_transfer: "↺ To itself",
  not_involved: "· Not involved",
};

function flagText(f: Flag): string {
  switch (f.kind) {
    case "zero_value":
      return "0-value transfer (poisoning trick)";
    case "dust":
      return "Dust (under 1 USDT)";
    case "look_alike":
      return `Looks like ${f.similar_to_label}: ${f.similar_to}`;
    case "fake_token":
      return "Fake token pretending to be USD";
    case "unknown_token":
      return "Not the official USDT contract";
    case "approval":
      return "Token approval: another address may spend your tokens";
    case "spent_by_other":
      return "Someone else moved tokens out of this wallet (using an approval)";
    case "permission_change":
      return "Account permissions changed: check who controls this account";
    case "other_contract":
      return `Called a contract that isn't USDT: ${f.contract}`;
    case "trc10":
      return "TRC-10 token (spam)";
    case "failed":
      return "Transaction failed";
  }
}

/** Shows the first and last 6 characters in bold, which is what you compare. */
function Addr({ a }: { a: string }) {
  if (a.length <= 14) return <span className="mono">{a}</span>;
  return (
    <span className="mono addr">
      <strong>{a.slice(0, 6)}</strong>
      {a.slice(6, -6)}
      <strong>{a.slice(-6)}</strong>
    </span>
  );
}

function EntryRow({ e }: { e: ActivityEntry }) {
  const severe = e.flags.some((f) => f.kind === "approval" || f.kind === "look_alike");
  return (
    <tr className={severe ? "row-warn" : ""}>
      <td>{new Date(e.time_ms).toLocaleString()}</td>
      <td>{e.is_approval ? "⚠ Approval" : DIRECTION_TEXT[e.direction]}</td>
      <td>
        <div className="amount-small">{e.amount ?? "unlimited / unknown"}</div>
        <div className="asset-label">{e.token_label}</div>
      </td>
      <td>
        <Addr a={e.counterparty} />
      </td>
      <td>
        {e.flags.map((f, i) => (
          <div key={i} className={`flag flag-${f.kind}`}>
            {flagText(f)}
          </div>
        ))}
      </td>
    </tr>
  );
}

function EntryTable({ entries }: { entries: ActivityEntry[] }) {
  return (
    <table className="activity">
      <thead>
        <tr>
          <th>Date</th>
          <th>Type</th>
          <th>Amount</th>
          <th>Counterparty</th>
          <th>Warnings</th>
        </tr>
      </thead>
      <tbody>
        {entries.map((e, i) => (
          <EntryRow key={`${e.txid}-${i}`} e={e} />
        ))}
      </tbody>
    </table>
  );
}

const SEVERE: Flag["kind"][] = ["approval", "spent_by_other", "permission_change", "look_alike"];

function TxRow({ e }: { e: TxEntry }) {
  const severe = e.flags.some((f) => SEVERE.includes(f.kind));
  return (
    <tr className={severe ? "row-warn" : ""}>
      <td>{new Date(e.time_ms).toLocaleString()}</td>
      <td>
        <div>{e.action}</div>
        <div className="asset-label">{DIRECTION_TEXT[e.direction]}</div>
      </td>
      <td>
        <div className="amount-small">{e.amount ?? "—"}</div>
        {e.asset_label && <div className="asset-label">{e.asset_label}</div>}
      </td>
      <td>{e.counterparty ? <Addr a={e.counterparty} /> : <span className="muted">—</span>}</td>
      <td>
        {e.flags.map((f, i) => (
          <div key={i} className={`flag flag-${f.kind}`}>
            {flagText(f)}
          </div>
        ))}
      </td>
    </tr>
  );
}

function TxTable({ entries }: { entries: TxEntry[] }) {
  return (
    <table className="activity">
      <thead>
        <tr>
          <th>Date</th>
          <th>What</th>
          <th>Amount</th>
          <th>Counterparty</th>
          <th>Warnings</th>
        </tr>
      </thead>
      <tbody>
        {entries.map((e, i) => (
          <TxRow key={`${e.txid}-${i}`} e={e} />
        ))}
      </tbody>
    </table>
  );
}

function ActivityPage() {
  const [tab, setTab] = useState<"transfers" | "transactions">("transfers");
  const [wallets, setWallets] = useState<WalletView[]>([]);
  const [selected, setSelected] = useState("");
  const [data, setData] = useState<WalletActivity | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    api.listWallets().then(
      (ws) => {
        const tron = ws.filter((w) => w.tron);
        setWallets(tron);
        if (tron.length > 0) setSelected(tron[0].id);
      },
      (e) => setError(errorText(e)),
    );
  }, []);

  const load = async () => {
    if (!selected) return;
    setLoading(true);
    setError(null);
    setData(null);
    try {
      setData(await api.getActivity(selected));
    } catch (e) {
      setError(errorText(e));
    } finally {
      setLoading(false);
    }
  };

  const visible = data?.entries.filter((e) => !e.hidden) ?? [];
  const hidden = data?.entries.filter((e) => e.hidden) ?? [];
  const txVisible = data?.transactions?.entries.filter((e) => !e.hidden) ?? [];
  const txHidden = data?.transactions?.entries.filter((e) => e.hidden) ?? [];

  return (
    <section>
      <h2>Activity</h2>
      <p className="warning">
        Never copy a recipient address from transaction history. Scammers send tiny or 0-value transfers from
        addresses that look like ones you use. Always take addresses from your verified address book.
      </p>
      <p className="hint">
        Latest 50 USDT transfers and latest 50 transactions per TRON wallet, like Tronscan's two tabs. Ethereum and
        Bitcoin history come next.
      </p>
      {wallets.length === 0 && !error && <p>No wallet with a TRON address yet.</p>}
      {wallets.length > 0 && (
        <div className="toolbar">
          <select value={selected} onChange={(e) => setSelected(e.target.value)}>
            {wallets.map((w) => (
              <option key={w.id} value={w.id}>
                {w.label} ({w.id})
              </option>
            ))}
          </select>
          <button onClick={() => void load()} disabled={loading || !selected}>
            {loading ? "Loading…" : "Load activity"}
          </button>
        </div>
      )}
      {error && <p className="error">{error}</p>}
      {data && (
        <>
          {data.permission_changes > 0 && (
            <p className="error">
              ⚠ {data.permission_changes} account permission change(s) found. On TRON this is how attackers take over
              an account. If you didn't do this, treat the wallet as compromised and follow the incident runbook.
            </p>
          )}
          {data.approval_count > 0 && (
            <p className="error">
              ⚠ {data.approval_count} token approval(s) or approved spend(s) found: another address may be able to move
              this wallet's tokens. If you didn't do this, follow the incident runbook (revoke from a clean device).
            </p>
          )}
          {data.lookalike_count > 0 && (
            <p className="warning">
              {data.lookalike_count} transfer(s) involve an address that looks like one you use but is different. These
              are typical of address poisoning.
            </p>
          )}
          {data.notes.map((n, i) => (
            <p key={i} className="hint">
              {n}
            </p>
          ))}
          <div className="tabs">
            <button className={tab === "transfers" ? "active" : ""} onClick={() => setTab("transfers")}>
              Transfers (USDT) · {visible.length}
            </button>
            <button className={tab === "transactions" ? "active" : ""} onClick={() => setTab("transactions")}>
              Transactions (all) · {txVisible.length}
            </button>
          </div>
          {tab === "transfers" && (
            <>
              <div className="card">
                <p className="hint">Token movements of genuine USDT (TRC-20) to or from this wallet.</p>
                {visible.length === 0 ? (
                  <p className="muted">No regular USDT transfers in the latest entries.</p>
                ) : (
                  <EntryTable entries={visible} />
                )}
              </div>
              {hidden.length > 0 && (
                <details className="card">
                  <summary>Hidden: {hidden.length} suspicious, dust or unknown-token transfers</summary>
                  <p className="error">These are hidden on purpose. Do not copy any address from this list.</p>
                  <EntryTable entries={hidden} />
                </details>
              )}
            </>
          )}
          {tab === "transactions" && (
            <>
              {data.transactions_error && <p className="error">{data.transactions_error}</p>}
              {data.transactions && (
                <>
                  <div className="card">
                    <p className="hint">
                      Everything this account did on-chain: TRX transfers, contract calls (USDT transfers and approvals),
                      permission changes, staking and voting. Source: {data.transactions.source}.
                    </p>
                    {txVisible.length === 0 ? (
                      <p className="muted">No transactions in the latest entries.</p>
                    ) : (
                      <TxTable entries={txVisible} />
                    )}
                  </div>
                  {txHidden.length > 0 && (
                    <details className="card">
                      <summary>Hidden: {txHidden.length} dust, spam or unrelated transactions</summary>
                      <p className="error">These are hidden on purpose. Do not copy any address from this list.</p>
                      <TxTable entries={txHidden} />
                    </details>
                  )}
                </>
              )}
            </>
          )}
        </>
      )}
    </section>
  );
}

/** Lock after this long without keyboard or mouse use (Rust enforces it too). */
const IDLE_LOCK_MS = 5 * 60 * 1000;

function MainApp({ onLock }: { onLock: () => void }) {
  const [page, setPage] = useState<Page>("portfolio");
  const portfolio = usePortfolio();

  // Idle lock: any key, click or mouse move counts as activity.
  useEffect(() => {
    let last = Date.now();
    const touch = () => {
      last = Date.now();
    };
    const events = ["mousemove", "mousedown", "keydown", "wheel", "touchstart"];
    events.forEach((e) => window.addEventListener(e, touch, { passive: true }));
    const timer = window.setInterval(() => {
      if (Date.now() - last > IDLE_LOCK_MS) {
        void api.lock(true).finally(onLock);
      }
    }, 15_000);
    return () => {
      events.forEach((e) => window.removeEventListener(e, touch));
      window.clearInterval(timer);
    };
  }, [onLock]);

  return (
    <div className="app">
      <header>
        <div className="brand">
          Watch-Only Wallet <span className="tag">no keys on this computer</span>
        </div>
        <nav>
          {(["portfolio", "receive", "activity", "wallets", "checks", "log", "about"] as Page[]).map((p) => (
            <button key={p} className={page === p ? "active" : ""} onClick={() => setPage(p)}>
              {p[0].toUpperCase() + p.slice(1)}
            </button>
          ))}
          <button className="lock-btn" onClick={() => void api.lock(false).finally(onLock)} title="Lock the app now">
            🔒 Lock
          </button>
        </nav>
      </header>
      <main>
        {page === "portfolio" && <PortfolioPage state={portfolio} />}
        {page === "receive" && <ReceivePage />}
        {page === "activity" && <ActivityPage />}
        {page === "wallets" && <WalletsPage onChanged={portfolio.markStale} />}
        {page === "checks" && (
          <section>
            <h2>PC safety checks</h2>
            <ChecksPanel />
          </section>
        )}
        {page === "log" && <AuditLogPage />}
        {page === "about" && <AboutPage />}
      </main>
    </div>
  );
}

/** Decides between first-run setup, login and the app itself. */
export default function App() {
  const [status, setStatus] = useState<AuthStatus | null>(null);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(() => {
    api.authStatus().then(setStatus, (e) => setError(errorText(e)));
  }, []);

  useEffect(() => {
    refresh();
    const onLocked = () => refresh();
    window.addEventListener(LOCKED_EVENT, onLocked);
    return () => window.removeEventListener(LOCKED_EVENT, onLocked);
  }, [refresh]);

  if (error) return <p className="error">{error}</p>;
  if (!status) return null;
  if (status.state === "needs_setup") return <SetupScreen hasLegacy={status.has_legacy_wallets} onDone={refresh} />;
  if (status.state === "locked") return <LoginScreen waitSecs={status.wait_secs} onDone={refresh} />;
  return <MainApp onLock={refresh} />;
}
