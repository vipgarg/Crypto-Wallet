// USDT on Ethereum SEPOLIA (test network, no value). The PC builds the
// transaction and shows it as a QR → the tablet checks it, you type the
// recipient's last 6 characters there, it signs and shows a QR → this PC
// checks the signature against what it built and sends it.
import { useEffect, useState } from "react";
import { api, errorText, type EthSent, type PreparedEth, type SepoliaBalances, type WalletView } from "./api";
import { QrCode } from "./Auth";
import { QrScanner } from "./QrScanner";
import { ChunkedAddress } from "./Receive";

type EthStep =
  | { kind: "form" }
  | { kind: "show"; p: PreparedEth }
  | { kind: "scan"; p: PreparedEth }
  | { kind: "sent"; sent: EthSent };

export function EthTestSend() {
  const [wallets, setWallets] = useState<WalletView[]>([]);
  const [selected, setSelected] = useState("");
  const [bal, setBal] = useState<SepoliaBalances | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [form, setForm] = useState({ recipient: "", amount: "" });
  const [step, setStep] = useState<EthStep>({ kind: "form" });

  useEffect(() => {
    api.listWallets().then(
      (ws) => {
        const e = ws.filter((w) => w.eth);
        setWallets(e);
        if (e.length > 0) setSelected(e[0].id);
      },
      (e) => setError(errorText(e)),
    );
  }, []);

  useEffect(() => {
    setBal(null);
    setStep({ kind: "form" });
  }, [selected]);

  const wallet = wallets.find((w) => w.id === selected);

  const run = async <T,>(what: string, f: () => Promise<T>): Promise<T | undefined> => {
    setBusy(what);
    setError(null);
    try {
      return await f();
    } catch (e) {
      setError(errorText(e));
      return undefined;
    } finally {
      setBusy(null);
    }
  };

  const check = async () => {
    const b = await run("Checking Sepolia balance…", () => api.getSepoliaBalances(selected));
    if (b) setBal(b);
  };

  const prepare = async (e: React.FormEvent) => {
    e.preventDefault();
    const p = await run("Building the transaction…", () =>
      api.prepareEthTestSend(selected, form.recipient.trim(), form.amount.trim()),
    );
    if (p) setStep({ kind: "show", p });
  };

  const finish = async (text: string, p: PreparedEth) => {
    const sent = await run("Checking the signature and sending…", () => api.finishEthTestSend(text));
    setStep(sent ? { kind: "sent", sent } : { kind: "show", p });
  };

  return (
    <>
      {error && <p className="error">{error}</p>}
      {busy && <p className="hint">{busy}</p>}
      <div className="card">
        <h3>Wallet</h3>
        {wallets.length === 0 ? (
          <p className="muted">No wallet with an Ethereum address yet. Add one from the tablet on the Wallets page.</p>
        ) : (
          <div className="toolbar">
            <select value={selected} onChange={(e) => setSelected(e.target.value)}>
              {wallets.map((w) => (
                <option key={w.id} value={w.id}>
                  {w.label} ({w.id})
                </option>
              ))}
            </select>
            <button onClick={() => void check()} disabled={!!busy || !selected}>
              Check Sepolia balance
            </button>
          </div>
        )}
        {wallet?.eth && (
          <>
            <p className="hint">
              The same Ethereum address works on Sepolia. You need test ETH for network fees (any Sepolia faucet) and
              Aave's Sepolia test USDT (Aave faucet, Sepolia market → USDT), sent to:
            </p>
            <ChunkedAddress a={wallet.eth} />
          </>
        )}
        {bal && (
          <p>
            Sepolia balance: <strong>{bal.usdt} test USDT</strong> · {bal.eth} test ETH{" "}
            <span className="muted">
              (source: {bal.source}; see {bal.explorer_url})
            </span>
          </p>
        )}
      </div>

      {wallet && step.kind === "form" && (
        <form className="card form" onSubmit={(e) => void prepare(e)}>
          <h3>Prepare a test USDT payment</h3>
          <label>
            Recipient (Ethereum address, 0x…)
            <input
              className="mono"
              value={form.recipient}
              onChange={(e) => setForm({ ...form, recipient: e.target.value })}
              autoComplete="off"
              spellCheck={false}
              required
            />
          </label>
          <p className="hint">
            Write the recipient on paper: you'll type its last 6 characters on the tablet. It must also be on the
            tablet's own allowlist for this wallet (typed there with its capitals exactly as shown).
          </p>
          <label>
            Amount (test USDT, e.g. 5 or 2.5)
            <input value={form.amount} onChange={(e) => setForm({ ...form, amount: e.target.value })} required />
          </label>
          <button type="submit" disabled={!!busy}>
            Build payment
          </button>
        </form>
      )}

      {(step.kind === "show" || step.kind === "scan") && (
        <div className="card">
          <h3>Payment waiting for the tablet</h3>
          <dl>
            <dt>Recipient</dt>
            <dd>
              <ChunkedAddress a={step.p.recipient} />
            </dd>
            <dt>Amount</dt>
            <dd>{step.p.amount} test USDT</dd>
            <dt>Network fee</dt>
            <dd>
              likely about {step.p.likely_fee_eth} test ETH, at most {step.p.max_fee_eth}
            </dd>
            <dt>Nonce</dt>
            <dd>{step.p.nonce}</dd>
            <dt>Request ID starts with</dt>
            <dd className="mono big-address">
              <strong>{step.p.request_id.slice(0, 8)}</strong>
            </dd>
          </dl>
          {step.kind === "show" && (
            <>
              <p className="hint">
                On the tablet: wallet → <strong>Test network</strong> → <strong>Sign an Ethereum test payment</strong> →
                scan this QR. Check the recipient, amount and request ID start, then type the recipient's last 6
                characters from your paper. An Ethereum transaction doesn't expire: if you cancel after signing, build
                and send a new one (it replaces the old one, same nonce).
              </p>
              <div className="qr-wrap">
                <QrCode size={step.p.qr_size} modules={step.p.qr_modules} px={460} />
              </div>
              <div className="button-row">
                <button onClick={() => setStep({ kind: "scan", p: step.p })}>Scan the signed QR from the tablet</button>
                <button className="secondary" onClick={() => setStep({ kind: "form" })}>
                  Cancel payment
                </button>
              </div>
            </>
          )}
          {step.kind === "scan" && (
            <QrScanner
              prefix="WES1:"
              maxLength={2000}
              wrongHint="That isn't an Ethereum signature from the tablet (it should start with WES1)."
              onResult={(t) => void finish(t, step.p)}
              onCancel={() => setStep({ kind: "show", p: step.p })}
            />
          )}
        </div>
      )}

      {step.kind === "sent" && (
        <div className="card">
          <h3>✓ Test payment sent</h3>
          <p>
            Transaction: <span className="mono">{step.sent.txid}</span>
          </p>
          <p className="hint">
            Accepted by: {step.sent.accepted_by.join(", ")}. See it in your browser:{" "}
            <span className="mono">{step.sent.explorer_url}</span>
          </p>
          {step.sent.errors.length > 0 && <p className="hint">Other nodes: {step.sent.errors.join("; ")}</p>}
          {step.sent.log_note && <p className="warning">{step.sent.log_note}</p>}
          <button
            onClick={() => {
              setStep({ kind: "form" });
              void check();
            }}
          >
            Done
          </button>
        </div>
      )}
    </>
  );
}
