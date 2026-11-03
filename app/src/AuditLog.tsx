// Log page: the hash-chained audit log (ARCHITECTURE.md §9.5). Read-only.
import { useEffect, useState } from "react";
import { api, errorText, type AuditEntry, type AuditEvent, type AuditView } from "./api";

const EVENT_TEXT: Record<AuditEvent, string> = {
  app_started: "App started",
  chain_broken: "Audit log check failed",
  setup_completed: "First-time setup completed",
  login_succeeded: "Logged in",
  login_failed: "Login failed",
  login_blocked: "Login attempt refused (waiting time)",
  locked: "Locked",
  idle_locked: "Locked (idle)",
  wallet_added: "Wallet added",
  wallet_removed: "Wallet removed",
  checks_problem: "PC safety check problem",
};

/** Events worth a second look. */
const ALERT: ReadonlySet<AuditEvent> = new Set<AuditEvent>([
  "chain_broken",
  "login_failed",
  "login_blocked",
  "wallet_added",
  "wallet_removed",
  "checks_problem",
]);

function when(at: number): string {
  return new Date(at * 1000).toLocaleString();
}

function Row({ e }: { e: AuditEntry }) {
  return (
    <tr className={ALERT.has(e.event) ? "row-warn" : ""}>
      <td className="muted">#{e.seq}</td>
      <td>{when(e.at)}</td>
      <td>{EVENT_TEXT[e.event] ?? e.event}</td>
      <td className="muted">{e.detail}</td>
    </tr>
  );
}

export function AuditLogPage() {
  const [view, setView] = useState<AuditView | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = () => {
    setError(null);
    api.getAuditLog().then(setView, (e) => setError(errorText(e)));
  };
  useEffect(load, []);

  return (
    <section>
      <h2>Audit log</h2>
      <p className="hint">
        Every login, lock, wallet change and PC check problem, newest first. Each entry is linked to the one before
        it (hash chain) and the whole log is checked at every start. This catches accidental damage and edits to old
        entries. It can't stop someone with full control of this PC from rewriting the whole log: for that, write the{" "}
        <strong>head</strong> below on paper now and then, and compare later.
      </p>
      <p className="hint">
        Review it weekly. Anything you don't recognise (a login you didn't make, a wallet you didn't add) means stop
        and investigate. Times are from the PC clock.
      </p>
      {error && <p className="error">{error}</p>}
      {view && (
        <>
          {view.problem ? (
            <p className="error">{view.problem}</p>
          ) : (
            <p className="ok-text">
              ✓ Intact: {view.count} entries. Head <span className="mono">{view.head_short}</span>
            </p>
          )}
          <button className="secondary" onClick={load}>
            Reload
          </button>
          <table className="activity">
            <thead>
              <tr>
                <th>#</th>
                <th>When</th>
                <th>Event</th>
                <th>Detail</th>
              </tr>
            </thead>
            <tbody>
              {view.entries.map((e) => (
                <Row key={e.seq} e={e} />
              ))}
            </tbody>
          </table>
          {view.count > view.entries.length && (
            <p className="hint">Showing the newest {view.entries.length} of {view.count} entries.</p>
          )}
        </>
      )}
    </section>
  );
}
