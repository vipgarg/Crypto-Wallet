// Address book page (ARCHITECTURE.md §7.1). This online copy is a convenience
// and is not trusted: your paper address book is the source of truth, and
// later the signer tablet keeps its own allowlist.
import { useEffect, useState } from "react";
import {
  api,
  errorText,
  type AddressBookView,
  type BookEntryView,
  type HistoryNetwork,
  type Tier,
  type VerifiedBy,
} from "./api";
import { ChunkedAddress } from "./Receive";
import { useBitcoin } from "./settings";

const NETWORKS: { id: HistoryNetwork; label: string; hint: string }[] = [
  { id: "tron", label: "TRON (TRC-20 USDT, TRX)", hint: "T…" },
  { id: "ethereum", label: "Ethereum (ERC-20 USDT, ETH)", hint: "0x… with mixed upper/lower case (checksummed)" },
  { id: "bitcoin", label: "Bitcoin", hint: "bc1q…, bc1p…, 1… or 3…" },
];

const VERIFIED: { id: VerifiedBy; label: string }[] = [
  { id: "phone_call", label: "Phone call: I read the address back to the recipient" },
  { id: "second_channel", label: "Confirmed through a second, independent channel" },
  { id: "test_transaction", label: "Small test transaction, and the recipient confirmed it arrived" },
  { id: "own_account_elsewhere", label: "My own account elsewhere (checked in its official app)" },
];

function waitLabel(m: number): string {
  if (m >= 60 && m % 60 === 0) return `${m / 60} hour${m === 60 ? "" : "s"}`;
  return `${m} minute${m === 1 ? "" : "s"}`;
}

function when(secs: number): string {
  return new Date(secs * 1000).toLocaleString();
}

function Status({ e, wait }: { e: BookEntryView; wait: string }) {
  switch (e.usable.kind) {
    case "yes":
      return <span className="badge badge-verified">Usable</span>;
    case "waiting":
      return (
        <span className="badge badge-unverified">
          Waiting period ({wait}): usable from {when(e.usable.from)}
        </span>
      );
    case "unknown":
      return (
        <span className="badge badge-unavailable">
          Network time unavailable: treated as still waiting (until at least {when(e.usable.from)})
        </span>
      );
  }
}

const EMPTY = {
  label: "",
  network: "tron" as HistoryNetwork,
  address: "",
  verified_by: "phone_call" as VerifiedBy,
  note: "",
  spending: true,
  savings: false,
  paper: false,
};

export function AddressBookPage() {
  const btc = useBitcoin();
  const networks = NETWORKS.filter((n) => btc || n.id !== "bitcoin");
  const [view, setView] = useState<AddressBookView | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const [form, setForm] = useState(EMPTY);
  const [busy, setBusy] = useState(false);
  const [renaming, setRenaming] = useState<{ id: string; label: string } | null>(null);

  const changeWait = async (m: number) => {
    setFormError(null);
    try {
      await api.setBookWait(m);
      load();
    } catch (e) {
      setFormError(errorText(e));
    }
  };

  const load = () => {
    setError(null);
    api.getAddressBook().then(setView, (e) => setError(errorText(e)));
  };
  useEffect(load, []);

  const add = async (ev: React.FormEvent) => {
    ev.preventDefault();
    setBusy(true);
    setFormError(null);
    try {
      const tiers: Tier[] = [];
      if (form.spending) tiers.push("spending");
      if (form.savings) tiers.push("savings");
      setView(
        await api.addAddressBookEntry({
          label: form.label,
          network: form.network,
          address: form.address,
          verified_by: form.verified_by,
          note: form.note,
          tiers,
          written_on_paper: form.paper,
        }),
      );
      setForm(EMPTY);
    } catch (e) {
      setFormError(errorText(e));
    } finally {
      setBusy(false);
    }
  };

  const remove = async (e: BookEntryView) => {
    if (
      !window.confirm(
        `Remove "${e.label}" from the address book? To use this address again later it must be added again, with a new waiting period. Also cross it out in your paper address book.`,
      )
    )
      return;
    try {
      setView(await api.removeAddressBookEntry(e.id));
    } catch (err) {
      setError(errorText(err));
    }
  };

  const saveRename = async () => {
    if (!renaming) return;
    try {
      setView(await api.renameAddressBookEntry(renaming.id, renaming.label));
      setRenaming(null);
    } catch (err) {
      setError(errorText(err));
    }
  };

  const net = networks.find((n) => n.id === form.network) ?? networks[0];

  return (
    <section>
      <h2>Address book</h2>
      <p className="hint">
        People and accounts you pay. Your <strong>paper address book</strong> is the source of truth: before approving
        any payment you will compare the address on the signer tablet with your paper, never with this screen. This
        list helps you pick recipients and blocks look-alike addresses. Never copy an address from transaction history.
      </p>
      {error && <p className="error">{error}</p>}
      {view && view.network_time === null && (
        <p className="warning">
          The current time couldn't be confirmed from two network sources, so every waiting period is treated as not
          over yet. Changing the PC clock has no effect on waiting periods.
        </p>
      )}

      {view && (
        <>
          {view.entries.length === 0 && <p className="muted">No entries yet.</p>}
          {view.entries.map((e) => (
            <div key={e.id} className="card">
              <h3>
                {renaming?.id === e.id ? (
                  <span className="button-row">
                    <input
                      value={renaming.label}
                      maxLength={40}
                      onChange={(ev) => setRenaming({ id: e.id, label: ev.target.value })}
                    />
                    <button onClick={() => void saveRename()}>Save</button>
                    <button className="secondary" onClick={() => setRenaming(null)}>
                      Cancel
                    </button>
                  </span>
                ) : (
                  <>
                    {e.label} <span className="muted">· {e.network_name} · {e.id}</span>
                  </>
                )}
              </h3>
              <ChunkedAddress a={e.address} />
              <p>
                <Status e={e} wait={view.waiting_text} />
              </p>
              <dl>
                <dt>May be paid from</dt>
                <dd>{e.tiers.join(", ")}</dd>
                <dt>How it was verified</dt>
                <dd>
                  {e.verified_by}
                  {e.note && <span className="muted"> · {e.note}</span>}
                </dd>
                <dt>Added</dt>
                <dd>{when(e.added_at)} (network time)</dd>
              </dl>
              {e.previously_removed_at !== null && (
                <p className="warning">
                  This address was removed from the book on {when(e.previously_removed_at)} and added again later.
                </p>
              )}
              <div className="button-row">
                <button className="secondary" onClick={() => setRenaming({ id: e.id, label: e.label })}>
                  Rename
                </button>
                <button className="danger" onClick={() => void remove(e)}>
                  Remove
                </button>
              </div>
              <p className="hint">
                To change the address, network or who may pay it: remove this entry and add a new one (new waiting
                period).
              </p>
            </div>
          ))}

          <form className="card form" onSubmit={(e) => void add(e)}>
            <h3>Add an address</h3>
            <p className="hint">
              Get the address from the recipient directly and verify it outside this computer (read it back on a phone
              call, or send a small test amount first). A new address can be used only after a waiting period
              ({view.waiting_text}), which gives you time to notice a mistake or a scam.
            </p>
            <div className="toolbar">
              <span className="muted">Waiting period:</span>
              {[10, 60, 360, 1440].map((m) => (
                <button
                  type="button"
                  key={m}
                  className={view.waiting_text === waitLabel(m) ? "" : "secondary"}
                  disabled={busy}
                  onClick={() => void changeWait(m)}
                >
                  {waitLabel(m)}
                </button>
              ))}
            </div>
            <p className="hint">
              Applies at once and is recorded in the audit log. Use 24 hours once real amounts are involved; the
              tablet's own allowlist has its own waiting period, which a compromised PC can't change.
            </p>
            {formError && <p className="error">{formError}</p>}
            <label>
              Label <span className="muted">(e.g. "Supplier, Mumbai")</span>
              <input
                value={form.label}
                onChange={(e) => setForm({ ...form, label: e.target.value })}
                required
                maxLength={40}
                autoComplete="off"
              />
            </label>
            <label>
              Network
              <select
                value={form.network}
                onChange={(e) => setForm({ ...form, network: e.target.value as HistoryNetwork })}
              >
                {networks.map((n) => (
                  <option key={n.id} value={n.id}>
                    {n.label}
                  </option>
                ))}
              </select>
            </label>
            <label>
              Address <span className="muted">({net.hint})</span>
              <input
                value={form.address}
                onChange={(e) => setForm({ ...form, address: e.target.value })}
                required
                className="mono"
                autoComplete="off"
                spellCheck={false}
              />
            </label>
            <label>
              How did you verify it?
              <select
                value={form.verified_by}
                onChange={(e) => setForm({ ...form, verified_by: e.target.value as VerifiedBy })}
              >
                {VERIFIED.map((v) => (
                  <option key={v.id} value={v.id}>
                    {v.label}
                  </option>
                ))}
              </select>
            </label>
            <label>
              Note <span className="muted">(optional, e.g. "called Ravi on 98xxxxxx12, 3 Nov")</span>
              <input
                value={form.note}
                onChange={(e) => setForm({ ...form, note: e.target.value })}
                maxLength={120}
                autoComplete="off"
              />
            </label>
            <fieldset className="plain">
              <legend>May be paid from</legend>
              <label className="confirm">
                <input
                  type="checkbox"
                  checked={form.spending}
                  onChange={(e) => setForm({ ...form, spending: e.target.checked })}
                />
                T-2 Spending
              </label>
              <label className="confirm">
                <input
                  type="checkbox"
                  checked={form.savings}
                  onChange={(e) => setForm({ ...form, savings: e.target.checked })}
                />
                T-1 Savings
              </label>
              <p className="hint">The Vault never pays outside addresses: it only moves funds to your own Savings.</p>
            </fieldset>
            <label className="confirm">
              <input
                type="checkbox"
                checked={form.paper}
                onChange={(e) => setForm({ ...form, paper: e.target.checked })}
              />
              I wrote the label and the full address in my paper address book, and checked it character by character.
            </label>
            <button type="submit" disabled={busy || !form.paper}>
              {busy ? "Adding…" : "Add to address book"}
            </button>
          </form>

          <div className="card">
            <h3>Your own wallets</h3>
            <p className="hint">
              Filled in automatically from the Wallets page; nothing to type. Addresses that look like these are refused
              above.
            </p>
            {view.own.length === 0 ? (
              <p className="muted">No wallets yet.</p>
            ) : (
              <table className="activity">
                <tbody>
                  {view.own.map((o, i) => (
                    <tr key={i}>
                      <td>{o.label}</td>
                      <td>{o.network_name}</td>
                      <td className="mono addr">{o.address}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>

          {view.revoked.length > 0 && (
            <details className="card">
              <summary>Removed addresses ({view.revoked.length})</summary>
              <p className="hint">Kept so a removed address can't come back unnoticed.</p>
              <table className="activity">
                <tbody>
                  {view.revoked.map((r, i) => (
                    <tr key={i}>
                      <td>{r.label}</td>
                      <td>{r.network}</td>
                      <td className="mono addr">{r.address}</td>
                      <td>removed {when(r.removed_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </details>
          )}
        </>
      )}
    </section>
  );
}
