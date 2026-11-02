import { useCallback, useEffect, useRef, useState } from "react";
import {
  api,
  errorText,
  type AppInfo,
  type AssetBalance,
  type BalanceStatus,
  type Portfolio,
  type Progress,
  type Tier,
  type WalletView,
} from "./api";

type Page = "portfolio" | "wallets" | "about";

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

function PortfolioPage() {
  const [data, setData] = useState<Portfolio | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [progress, setProgress] = useState<Progress | null>(null);

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
    setLoading(true);
    setError(null);
    try {
      setData(await api.getPortfolio());
    } catch (e) {
      setError(errorText(e));
    } finally {
      setLoading(false);
      api.getProgress().then(setProgress, () => undefined);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

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

function WalletsPage() {
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

      <form className="card form" onSubmit={(e) => void add(e)}>
        <h3>Add a wallet to watch</h3>
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

export default function App() {
  const [page, setPage] = useState<Page>("portfolio");
  return (
    <div className="app">
      <header>
        <div className="brand">
          Watch-Only Wallet <span className="tag">no keys on this computer</span>
        </div>
        <nav>
          {(["portfolio", "wallets", "about"] as Page[]).map((p) => (
            <button key={p} className={page === p ? "active" : ""} onClick={() => setPage(p)}>
              {p[0].toUpperCase() + p.slice(1)}
            </button>
          ))}
        </nav>
      </header>
      <main>
        {page === "portfolio" && <PortfolioPage />}
        {page === "wallets" && <WalletsPage />}
        {page === "about" && <AboutPage />}
      </main>
    </div>
  );
}
