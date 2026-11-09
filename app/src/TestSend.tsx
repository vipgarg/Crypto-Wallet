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
import { useBitcoin } from "./settings";
import { EthTestSend } from "./EthTestSend";
import type { NileBalances, PreparedTron, TronSent, WalletView } from "./api";

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

function BitcoinTestSend() {
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
    <>
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
    </>
  );
}

type TronStep =
  | { kind: "form" }
  | { kind: "show"; p: PreparedTron }
  | { kind: "scan"; p: PreparedTron }
  | { kind: "sent"; sent: TronSent };

function TronTestSend({ real = false }: { real?: boolean }) {
  const [wallets, setWallets] = useState<WalletView[]>([]);
  const [selected, setSelected] = useState("");
  const [bal, setBal] = useState<NileBalances | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [form, setForm] = useState({ recipient: "", amount: "" });
  const [kind, setKind] = useState<"usdt" | "trx">("usdt");
  const [step, setStep] = useState<TronStep>({ kind: "form" });

  useEffect(() => {
    api.listWallets().then(
      (ws) => {
        const t = ws.filter((w) => w.tron);
        setWallets(t);
        if (t.length > 0) setSelected(t[0].id);
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
    const b = await run("Checking Nile balance…", () => api.getNileBalances(selected));
    if (b) setBal(b);
  };

  const prepare = async (e: React.FormEvent) => {
    e.preventDefault();
    const p = await run("Building the transaction…", () =>
      api.prepareTronTestSend(selected, form.recipient.trim(), form.amount.trim(), kind, real),
    );
    if (p) setStep({ kind: "show", p });
  };

  const finish = async (text: string, p: PreparedTron) => {
    const sent = await run("Checking the signature and broadcasting…", () => api.finishTronTestSend(text));
    setStep(sent ? { kind: "sent", sent } : { kind: "show", p });
  };

  return (
    <>
      {error && <p className="error">{error}</p>}
      {busy && <p className="hint">{busy}</p>}
      <div className="card">
        <h3>Wallet</h3>
        {wallets.length === 0 ? (
          <p className="muted">No wallet with a TRON address yet. Add one from the tablet on the Wallets page.</p>
        ) : (
          <div className="toolbar">
            <select value={selected} onChange={(e) => setSelected(e.target.value)}>
              {wallets.map((w) => (
                <option key={w.id} value={w.id}>
                  {w.label} ({w.id})
                </option>
              ))}
            </select>
            {!real && (
              <button onClick={() => void check()} disabled={!!busy || !selected}>
                Check Nile balance
              </button>
            )}
          </div>
        )}
        {real && (
          <p className="error">
            REAL MONEY on TRON mainnet. Signed only by a real-money wallet on the real-network tablet build, to an
            address on its allowlist, within its daily limit.
          </p>
        )}
        {wallet?.tron && !real && (
          <>
            <p className="hint">
              The same TRON address works on the Nile test network. Get free test TRX and test USDT from the Nile
              faucet (nileex.io → Get test coins), pasting this address:
            </p>
            <ChunkedAddress a={wallet.tron} />
            <p className="hint">
              You need some test TRX too: TRON uses it to pay for sending USDT (energy), up to 30 TRX per transfer.
            </p>
          </>
        )}
        {bal && (
          <p>
            Nile balance: <strong>{bal.usdt} test USDT</strong> · {bal.trx} test TRX{" "}
            <span className="muted">
              (source: {bal.source}, one node; see {bal.explorer_url})
            </span>
          </p>
        )}
      </div>

      {wallet && step.kind === "form" && (
        <form className="card form" onSubmit={(e) => void prepare(e)}>
          <h3>Prepare a test payment</h3>
          <div className="toolbar">
            <label>
              <input type="radio" checked={kind === "usdt"} onChange={() => setKind("usdt")} /> Test USDT
            </label>
            <label>
              <input
                type="radio"
                checked={kind === "trx"}
                onChange={() => {
                  setKind("trx");
                  setForm({ ...form, recipient: "" });
                }}
              />{" "}
              TRX top-up to my own wallet
            </label>
          </div>
          {kind === "usdt" ? (
            <>
              <label>
                Recipient (TRON address, starts with T)
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
                Write the recipient on paper: you'll type its last 6 characters on the tablet. TRON addresses are
                case-sensitive. It must also be on the tablet's own allowlist for this wallet.
              </p>
            </>
          ) : (
            <>
              <label>
                To which of your wallets
                <select
                  value={form.recipient}
                  onChange={(e) => setForm({ ...form, recipient: e.target.value })}
                  required
                >
                  <option value="">Choose…</option>
                  {wallets
                    .filter((w) => w.id !== selected && w.tron)
                    .map((w) => (
                      <option key={w.id} value={w.tron ?? ""}>
                        {w.label} ({w.id})
                      </option>
                    ))}
                </select>
              </label>
              <p className="hint">
                Plain TRX can only go to your own wallets (to pay their network fees), at most 200 TRX each. The
                tablet checks this too, and the wallet must be on its allowlist.
              </p>
            </>
          )}
          <label>
            Amount ({kind === "usdt" ? "test USDT" : "test TRX"}, e.g. 5 or 2.5)
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
            <dd>
              {step.p.amount} test {step.p.unit}
              {step.p.kind === "trx" && " (top-up to your own wallet)"}
            </dd>
            {step.p.kind === "usdt" && (
              <>
                <dt>Fee limit</dt>
                <dd>up to {step.p.fee_limit_trx} test TRX</dd>
              </>
            )}
            <dt>Estimated network cost</dt>
            <dd>{step.p.fee_estimate}</dd>
            <dt>Transaction ID starts with</dt>
            <dd className="mono big-address">
              <strong>{step.p.txid.slice(0, 8)}</strong>
            </dd>
          </dl>
          {step.kind === "show" && (
            <>
              <p className="hint">
                On the tablet: wallet → <strong>Test network</strong> → <strong>Sign a TRON test payment</strong> → scan
                this QR. Check the recipient, amount and transaction ID start, then type the recipient's last 6
                characters from your paper. It must be signed within about 9 minutes, or build it again.
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
              prefix="WTS1:"
              maxLength={2000}
              wrongHint="That isn't a TRON signature from the tablet (it should start with WTS1)."
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
            Transaction ID: <span className="mono">{step.sent.txid}</span>
          </p>
          <p className="hint">
            See it in your browser: <span className="mono">{step.sent.explorer_url}</span>
          </p>
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

export function TestSendPage() {
  const btc = useBitcoin();
  const [tab, setTab] = useState<"tron" | "eth" | "btc" | "real-tron" | "real-eth">("tron");
  const [realOn, setRealOn] = useState(false);
  const [confirm, setConfirm] = useState("");
  const [realError, setRealError] = useState<string | null>(null);
  useEffect(() => {
    api.getSettings().then((s) => setRealOn(s.real_sending), () => undefined);
  }, []);
  const switchReal = async (enabled: boolean) => {
    setRealError(null);
    try {
      const s = await api.setRealSending(enabled, confirm);
      setRealOn(s.real_sending);
      setConfirm("");
      if (!s.real_sending && tab.startsWith("real")) setTab("tron");
    } catch (e) {
      setRealError(errorText(e));
    }
  };
  const active = (btc || tab !== "btc") && (realOn || !tab.startsWith("real")) ? tab : "tron";
  return (
    <section>
      <h2>Test send</h2>
      <p className="warning">
        Test networks only: these coins have <strong>no value</strong>. Practise the full signing flow with the tablet
        before any real sending exists.
      </p>
      <div className="tabs">
        <button className={active === "tron" ? "active" : ""} onClick={() => setTab("tron")}>
          USDT on TRON Nile
        </button>
        <button className={active === "eth" ? "active" : ""} onClick={() => setTab("eth")}>
          USDT on Ethereum Sepolia
        </button>
        {realOn && (
          <>
            <button className={active === "real-tron" ? "active" : ""} onClick={() => setTab("real-tron")}>
              TRON (REAL)
            </button>
            <button className={active === "real-eth" ? "active" : ""} onClick={() => setTab("real-eth")}>
              Ethereum (REAL)
            </button>
          </>
        )}
        {btc && (
          <button className={active === "btc" ? "active" : ""} onClick={() => setTab("btc")}>
            Bitcoin signet
          </button>
        )}
      </div>
      {active === "tron" ? (
        <TronTestSend />
      ) : active === "eth" ? (
        <EthTestSend />
      ) : active === "real-tron" ? (
        <TronTestSend real />
      ) : active === "real-eth" ? (
        <EthTestSend real />
      ) : (
        <BitcoinTestSend />
      )}
      <div className="card">
        <h3>Real-network sending: {realOn ? "ON" : "off"}</h3>
        {realOn ? (
          <button className="secondary" onClick={() => void switchReal(false)}>
            Switch real sending off
          </button>
        ) : (
          <>
            <p className="hint">
              Only after the release gates (docs/release-gate.md): recovery test on a factory-reset tablet, fresh real
              wallets on the real-network tablet build, then a small trial. To switch on, type{" "}
              <span className="mono">I HAVE PASSED THE RELEASE GATES</span>
            </p>
            <div className="toolbar">
              <input value={confirm} onChange={(e) => setConfirm(e.target.value)} autoComplete="off" />
              <button onClick={() => void switchReal(true)}>Switch on</button>
            </div>
          </>
        )}
        {realError && <p className="error">{realError}</p>}
      </div>
    </section>
  );
}
