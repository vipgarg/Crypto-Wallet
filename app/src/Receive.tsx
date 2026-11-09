import { useEffect, useRef, useState } from "react";
import { QrCode } from "./Auth";
import { useBitcoin } from "./settings";
import { api, errorText, type ReceiveNetwork, type ReceiveView, type WalletView } from "./api";

const NETWORKS: { id: ReceiveNetwork; label: string; has: (w: WalletView) => boolean }[] = [
  { id: "tron", label: "TRON (TRC-20)", has: (w) => !!w.tron },
  { id: "ethereum", label: "Ethereum (ERC-20)", has: (w) => !!w.eth },
  { id: "bitcoin", label: "Bitcoin", has: (w) => !!w.btc },
];

/** Clipboard is cleared this long after copying (§9.1). */
const CLIPBOARD_CLEAR_MS = 60_000;

/** Address in even groups of 4, with the first and last 6 characters in bold. */
export function ChunkedAddress({ a }: { a: string }) {
  const chars = [...a];
  const parts: { text: string; bold: boolean }[] = [];
  chars.forEach((c, i) => {
    const bold = i < 6 || i >= chars.length - 6;
    const text = (i > 0 && i % 4 === 0 ? " " : "") + c;
    const last = parts[parts.length - 1];
    if (last && last.bold === bold) last.text += text;
    else parts.push({ text, bold });
  });
  return (
    <div className="mono big-address">
      {parts.map((p, i) => (p.bold ? <strong key={i}>{p.text}</strong> : <span key={i}>{p.text}</span>))}
    </div>
  );
}

export function ReceivePage() {
  const btc = useBitcoin();
  const [wallets, setWallets] = useState<WalletView[]>([]);
  const [walletId, setWalletId] = useState("");
  const [network, setNetwork] = useState<ReceiveNetwork | null>(null);
  const [skip, setSkip] = useState(0);
  const [view, setView] = useState<ReceiveView | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [copied, setCopied] = useState(false);
  const clearTimer = useRef<number | null>(null);

  useEffect(() => {
    api.listWallets().then(
      (ws) => {
        setWallets(ws);
        if (ws.length > 0) setWalletId(ws[0].id);
      },
      (e) => setError(errorText(e)),
    );
    return () => {
      if (clearTimer.current) window.clearTimeout(clearTimer.current);
    };
  }, []);

  const wallet = wallets.find((w) => w.id === walletId);
  const available = wallet ? NETWORKS.filter((n) => n.has(wallet) && (btc || n.id !== "bitcoin")) : [];

  useEffect(() => {
    setNetwork(available[0]?.id ?? null);
    setSkip(0);
    setView(null);
  }, [walletId]);

  useEffect(() => {
    if (!walletId || !network) return;
    let stale = false;
    setLoading(true);
    setError(null);
    setView(null);
    setCopied(false);
    api
      .getReceive(walletId, network, skip)
      .then(
        (v) => !stale && setView(v),
        (e) => !stale && setError(errorText(e)),
      )
      .finally(() => !stale && setLoading(false));
    return () => {
      stale = true;
    };
  }, [walletId, network, skip]);

  const copy = async () => {
    if (!view) return;
    try {
      await navigator.clipboard.writeText(view.address);
      setCopied(true);
      if (clearTimer.current) window.clearTimeout(clearTimer.current);
      clearTimer.current = window.setTimeout(() => {
        void navigator.clipboard.writeText("").catch(() => undefined);
        setCopied(false);
      }, CLIPBOARD_CLEAR_MS);
    } catch {
      setError("Couldn't copy. Select the address and copy it by hand.");
    }
  };

  return (
    <section>
      <h2>Receive</h2>
      {wallets.length === 0 && !error && <p>No wallets yet. Add one on the Wallets page.</p>}
      {wallets.length > 0 && (
        <div className="toolbar">
          <select value={walletId} onChange={(e) => setWalletId(e.target.value)}>
            {wallets.map((w) => (
              <option key={w.id} value={w.id}>
                {w.label} ({w.id}) · {w.tier_name}
              </option>
            ))}
          </select>
          {available.map((n) => (
            <button
              key={n.id}
              className={network === n.id ? "" : "secondary"}
              onClick={() => {
                setNetwork(n.id);
                setSkip(0);
              }}
            >
              {n.label}
            </button>
          ))}
        </div>
      )}
      {error && <p className="error">{error}</p>}
      {loading && <p className="muted">{network === "bitcoin" ? "Finding an unused address…" : "Loading…"}</p>}
      {view && (
        <div className="card receive">
          <div className="network-banner">
            Only send <strong>{view.assets.join(" or ")}</strong> to this address.
            <div className="muted">Sending on any other network can lose the funds.</div>
          </div>
          {view.warnings.map((w, i) => (
            <p key={i} className="warning">
              {w}
            </p>
          ))}
          <div className="receive-body">
            <QrCode size={view.qr.size} modules={view.qr.modules} />
            <div className="receive-text">
              <div className="asset-label">
                {view.network} address{view.btc_index !== null ? ` · receive #${view.btc_index} (never used)` : ""}
              </div>
              <ChunkedAddress a={view.address} />
              <div className="receive-actions">
                <button onClick={() => void copy()}>{copied ? "Copied (clears in 60 s)" : "Copy address"}</button>
                {view.btc_index !== null && (
                  <button className="secondary" onClick={() => setSkip((s) => Math.min(s + 1, 19))} disabled={skip >= 19}>
                    New address
                  </button>
                )}
              </div>
            </div>
          </div>
          <div className="verify-box">
            <h3>Before you share it: verify on the signer</h3>
            <p>
              Malware on this PC could show a different address here. {view.signer_hint} Every character must match,
              especially the <strong>bold</strong> start and end.
            </p>
            <p className="muted">
              Then send it over one channel and confirm the first and last 6 characters with the payer over another
              (for example email + phone call). For a new payer, ask for a small test payment first.
            </p>
          </div>
        </div>
      )}
    </section>
  );
}
