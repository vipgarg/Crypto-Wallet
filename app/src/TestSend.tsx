// Test send page (Phase 2): Bitcoin SIGNET only. Coins on signet have no
// value. The flow: the PC builds the payment and shows it as a QR → the
// tablet checks it, you type the recipient's last 6 characters there, it
// signs and shows a QR → this PC verifies the signatures against what it
// built and broadcasts.
import { useEffect, useState } from "react";
import {
  api,
  errorText,
  type PreparedSend,
  type SentView,
  type TestWalletSummary,
  type TestWalletView,
} from "./api";
import { QrCode } from "./Auth";
import { QrScanner } from "./QrScanner";
import { ChunkedAddress } from "./Receive";

const MAX_QR_TEXT = 6000;

function btc(sats: number): string {
  return `${(sats / 1e8).toFixed(8).replace(/\.?0+$/, "")} sBTC (${sats.toLocaleString()} sats)`;
}

type Step =
  | { kind: "form" }
  | { kind: "show"; prepared: PreparedSend }
  | { kind: "scan"; prepared: PreparedSend }
  | { kind: "sending"; prepared: PreparedSend }
  | { kind: "sent"; sent: SentView };

export function TestSendPage() {
  const [wallets, setWallets] = useState<TestWalletSummary[]>([]);
  const [selected, setSelected] = useState("");
  const [view, setView] = useState<TestWalletView | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [adding, setAdding] = useState<"no" | "scan" | "paste">("no");
  const [pasted, setPasted] = useState("");
  const [form, setForm] = useState({ recipient: "", amount: "", fee: "2" });
  const [step, setStep] = useState<Step>({ kind: "form" });

  useEffect(() => {
    api.listTestWallets().then(
      (ws) => {
        setWallets(ws);
        if (ws.length > 0) setSelected(ws[0].id);
      },
      (e) => setError(errorText(e)),
    );
  }, []);

  useEffect(() => {
    setView(null);
    setStep({ kind: "form" });
  }, [selected]);

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

  const addWallet = async (text: string) => {
    setAdding("no");
    const ws = await run("Adding…", () => api.addTestWallet(text));
    if (ws) {
      setWallets(ws);
      setSelected(ws[ws.length - 1].id);
      setPasted("");
    }
  };

  const remove = async () => {
    if (!window.confirm("Remove this test wallet from the PC? (It stays on the tablet.)")) return;
    const ws = await run("Removing…", () => api.removeTestWallet(selected));
    if (ws) {
      setWallets(ws);
      setSelected(ws[0]?.id ?? "");
    }
  };

  const scan = async () => {
    const v = await run("Checking balance on both signet sources (about 20–40 seconds, requests are spaced out)…", () => api.scanTestWallet(selected));
    if (v) setView(v);
  };

  const prepare = async (e: React.FormEvent) => {
    e.preventDefault();
    const amount = Number(form.amount);
    const fee = Number(form.fee);
    if (!Number.isInteger(amount) || amount <= 0) return setError("Amount must be a whole number of sats.");
    if (!Number.isInteger(fee) || fee < 1) return setError("Fee rate must be a whole number of sat/vB.");
    const p = await run("Building the payment…", () =>
      api.prepareTestSend(selected, form.recipient.trim(), amount, fee),
    );
    if (p) setStep({ kind: "show", prepared: p });
  };

  const finish = async (text: string, prepared: PreparedSend) => {
    setStep({ kind: "sending", prepared });
    const sent = await run("Verifying signatures and broadcasting…", () => api.finishTestSend(text));
    setStep(sent ? { kind: "sent", sent } : { kind: "show", prepared });
  };

  return (
    <section>
      <h2>Test send (Bitcoin signet)</h2>
      <p className="warning">
        Test network only: signet coins have <strong>no value</strong>. This page is for practising the full signing
        flow with the tablet before any real sending exists.
      </p>
      {error && <p className="error">{error}</p>}
      {busy && <p className="hint">{busy}</p>}

      <div className="card">
        <h3>Test wallets</h3>
        {wallets.length > 0 && (
          <div className="toolbar">
            <select value={selected} onChange={(e) => setSelected(e.target.value)}>
              {wallets.map((w) => (
                <option key={w.id} value={w.id}>
                  {w.label} ({w.id}) · fingerprint {w.fingerprint}
                </option>
              ))}
            </select>
            <button onClick={() => void scan()} disabled={!!busy}>
              Check balance
            </button>
            <button className="danger" onClick={() => void remove()} disabled={!!busy}>
              Remove
            </button>
          </div>
        )}
        {(() => {
          const w = wallets.find((x) => x.id === selected);
          if (!w || view) return null;
          return (
            <div>
              <p className="hint">
                Test receive address #0 for the faucet (signet addresses start with <strong>tb1</strong>; the Receive
                page shows <em>real</em> Bitcoin addresses starting with bc1, which a test faucet refuses):
              </p>
              <ChunkedAddress a={w.first_receive_address} />
            </div>
          );
        })()}
        {adding === "no" && (
          <div className="button-row">
            <button className="secondary" onClick={() => setAdding("scan")}>
              Add test wallet (scan the tablet)
            </button>
            <button className="secondary" onClick={() => setAdding("paste")}>
              Paste export text
            </button>
          </div>
        )}
        {adding !== "no" && (
          <p className="hint">
            On the tablet: open the wallet → <strong>Test network (signet)</strong> → unlock → its export QR (starts
            with WWT1).
          </p>
        )}
        {adding === "scan" && (
          <QrScanner
            prefix="WWT1:"
            maxLength={2000}
            wrongHint="That QR isn't a test-network export (WWT1). Show the tablet's test export QR."
            onResult={(t) => void addWallet(t)}
            onCancel={() => setAdding("no")}
          />
        )}
        {adding === "paste" && (
          <div className="form">
            <textarea rows={3} value={pasted} onChange={(e) => setPasted(e.target.value.slice(0, 2000))} />
            <div className="button-row">
              <button disabled={!pasted.trim()} onClick={() => void addWallet(pasted)}>
                Add
              </button>
              <button className="secondary" onClick={() => setAdding("no")}>
                Cancel
              </button>
            </div>
          </div>
        )}
      </div>

      {view && (
        <div className="card">
          <h3>
            {view.label} <span className="muted">· signet</span>
          </h3>
          <p>
            Balance: <strong>{btc(view.confirmed_sats)}</strong>{" "}
            <span className={view.status === "verified" ? "badge badge-verified" : "badge badge-unverified"}>
              {view.status === "verified" ? "Both sources agree" : "Only one source answered"}
            </span>
          </p>
          {view.problems.map((p, i) => (
            <p key={i} className="hint">
              {p}
            </p>
          ))}
          <p className="hint">Receive test coins at (receive address #{view.receive_index}):</p>
          <ChunkedAddress a={view.receive_address} />
          <p className="hint">
            Free test coins: open a signet faucet in your browser (for example signetfaucet.com or
            bitcoinsignetfaucet.com), paste this <strong>tb1…</strong> address, then press "Check balance" after about
            10 minutes (1 confirmation). Don't use the Receive page for this: it shows real Bitcoin addresses (bc1…).
          </p>
        </div>
      )}

      {view && step.kind === "form" && (
        <form className="card form" onSubmit={(e) => void prepare(e)}>
          <h3>Prepare a test payment</h3>
          <label>
            Recipient (signet address, starts with tb1)
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
            For practice, send to another test wallet of yours, or back to the faucet's return address. Write the
            address on paper: you'll type its last 6 characters on the tablet.
          </p>
          <label>
            Amount (sats)
            <input value={form.amount} onChange={(e) => setForm({ ...form, amount: e.target.value })} required />
          </label>
          <label>
            Fee rate (sat/vB)
            <input value={form.fee} onChange={(e) => setForm({ ...form, fee: e.target.value })} required />
          </label>
          <button type="submit" disabled={!!busy}>
            Build payment
          </button>
        </form>
      )}

      {(step.kind === "show" || step.kind === "scan" || step.kind === "sending") && (
        <div className="card">
          <h3>Payment waiting for the tablet</h3>
          <dl>
            <dt>Recipient</dt>
            <dd>
              <ChunkedAddress a={step.prepared.plan.recipient} />
            </dd>
            <dt>Amount</dt>
            <dd>{btc(step.prepared.plan.amount_sats)}</dd>
            <dt>Fee</dt>
            <dd>
              {btc(step.prepared.plan.fee_sats)} · about {step.prepared.plan.fee_rate} sat/vB
            </dd>
            <dt>Change back to you</dt>
            <dd>
              {step.prepared.plan.change_sats > 0
                ? `${btc(step.prepared.plan.change_sats)} (change address #${step.prepared.plan.change_index})`
                : "none"}
            </dd>
            <dt>Transaction ID starts with</dt>
            <dd className="mono big-address">
              <strong>{step.prepared.plan.txid.slice(0, 8)}</strong>
            </dd>
          </dl>
          {step.kind === "show" && (
            <>
              <p className="hint">
                On the tablet: open the wallet → <strong>Sign a test payment</strong> → scan this QR. Check that the
                tablet shows the same recipient, amount, fee and transaction ID start. Then type the recipient's last 6
                characters <strong>from your paper</strong>.
              </p>
              <div className="qr-wrap">
                <QrCode size={step.prepared.qr_size} modules={step.prepared.qr_modules} px={520} />
              </div>
              <div className="button-row">
                <button onClick={() => setStep({ kind: "scan", prepared: step.prepared })}>
                  Scan the signed QR from the tablet
                </button>
                <button className="secondary" onClick={() => setStep({ kind: "form" })}>
                  Cancel payment
                </button>
              </div>
            </>
          )}
          {step.kind === "scan" && (
            <QrScanner
              prefix="WPS1:"
              maxLength={MAX_QR_TEXT}
              wrongHint="That QR isn't a signed payment (WPS1). Show the tablet's signed QR."
              onResult={(t) => void finish(t, step.prepared)}
              onCancel={() => setStep({ kind: "show", prepared: step.prepared })}
            />
          )}
        </div>
      )}

      {step.kind === "sent" && (
        <div className="card">
          <h3>✓ Test payment sent</h3>
          <p>
            Transaction ID: <span className="mono">{step.sent.txid}</span>
          </p>
          <p className="hint">Accepted by: {step.sent.accepted_by.join(", ")}</p>
          {step.sent.errors.map((e, i) => (
            <p key={i} className="hint">
              {e}
            </p>
          ))}
          <p className="hint">
            See it in your browser: <span className="mono">{step.sent.explorer_url}</span>
          </p>
          <button
            onClick={() => {
              setStep({ kind: "form" });
              void scan();
            }}
          >
            Done
          </button>
        </div>
      )}
    </section>
  );
}
