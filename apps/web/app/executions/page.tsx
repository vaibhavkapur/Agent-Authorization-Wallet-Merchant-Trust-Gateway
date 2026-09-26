"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { Claim, call, money, ts } from "@/lib/api";
import { Badge, decisionKind, statusKind } from "@/components/JsonView";

export default function ExecutionsPage() {
  const [claims, setClaims] = useState<Claim[]>([]);
  const [metrics, setMetrics] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);

  const load = () => {
    call<Claim[]>("/v1/executions", { as: "user" }).then(setClaims).catch((e) => setError(String(e)));
    call("/v1/metrics").then(setMetrics).catch(() => undefined);
  };
  useEffect(load, []);

  const runWorker = async () => {
    await call("/v1/demo/worker/run-once", { method: "POST" });
    load();
  };

  return (
    <div className="grid">
      <div className="panel">
        <div className="row" style={{ justifyContent: "space-between" }}>
          <h1 style={{ margin: 0 }}>Executions</h1>
          <button onClick={runWorker}>Run reconciliation worker once</button>
        </div>
        {error && <p className="notice">{error}</p>}
        <table style={{ marginTop: 12 }}>
          <thead>
            <tr>
              <th>Execution</th>
              <th>Grant</th>
              <th>Profile</th>
              <th>Amount</th>
              <th>Payee</th>
              <th>Decision</th>
              <th>State</th>
              <th>Payment</th>
              <th>Claimed</th>
            </tr>
          </thead>
          <tbody>
            {claims.map((c) => (
              <tr key={c.id}>
                <td>
                  <Link href={`/executions/${c.id}`}>
                    <code>{c.id}</code>
                  </Link>
                </td>
                <td>
                  <code>{c.grant_id}</code>
                </td>
                <td>{(c as any).profile}</td>
                <td>{money(c.amount_minor, c.currency)}</td>
                <td>{c.payee_id}</td>
                <td>
                  <Badge kind={decisionKind(c.decision)}>{c.decision}</Badge>
                </td>
                <td>
                  <Badge kind={statusKind(c.state)}>{c.state}</Badge>
                </td>
                <td>
                  {c.payment_attempt?.state} {c.payment_attempt?.fault && <span className="muted">(fault: {c.payment_attempt.fault})</span>}
                </td>
                <td>{ts(c.claimed_at)}</td>
              </tr>
            ))}
            {!claims.length && (
              <tr>
                <td colSpan={9} className="muted">No executions yet.</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      {metrics && (
        <div className="grid three">
          <div className="panel">
            <h3>Verification</h3>
            {Object.entries(metrics.verification ?? {}).map(([role, v]: any) => (
              <div key={role} style={{ fontSize: 13, marginBottom: 6 }}>
                <strong>{role}</strong>: {v.count} checks, avg {v.latency_ms_avg} ms ·{" "}
                {Object.entries(v.decisions ?? {}).map(([d, n]) => `${d} ${n}`).join(", ")}
              </div>
            ))}
          </div>
          <div className="panel">
            <h3>Rejection reasons</h3>
            {Object.entries(metrics.rejection_reasons ?? {}).map(([r, n]: any) => (
              <div key={r} style={{ fontSize: 13 }}>
                <code>{r}</code> × {n}
              </div>
            ))}
            {!Object.keys(metrics.rejection_reasons ?? {}).length && <span className="muted">none</span>}
          </div>
          <div className="panel">
            <h3>Replay · expiry · unresolved</h3>
            <div style={{ fontSize: 13 }}>Replay attempts rejected: {metrics.replay?.attempts_rejected} (nonces recorded {metrics.replay?.nonces_recorded})</div>
            <div style={{ fontSize: 13 }}>Grants expiring within 1h: {metrics.authorizations?.expiring_within_1h} · expired: {metrics.authorizations?.expired}</div>
            <div style={{ fontSize: 13 }}>Unresolved executions: {metrics.executions?.unresolved}</div>
            <div style={{ fontSize: 13 }}>
              By state: {Object.entries(metrics.executions?.by_state ?? {}).map(([s, n]) => `${s} ${n}`).join(", ") || "—"}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
