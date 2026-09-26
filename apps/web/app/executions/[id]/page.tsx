"use client";

import { useEffect, useState } from "react";
import { Claim, Diagnostic, Grant, call, money, ts } from "@/lib/api";
import { DiagnosticCard } from "@/components/DiagnosticCard";
import { EvidenceViewer } from "@/components/EvidenceViewer";
import { Badge, JsonView, statusKind } from "@/components/JsonView";

type Detail = {
  diagnostic: Diagnostic;
  claim: Claim;
  receipts: Record<string, string>;
  grant: Grant;
  verification_attempts: { id: string; role: string; decision: string; reason_codes: string[]; latency_ms: number; verified_at: number; ruleset_version: string }[];
};

export default function ExecutionDetail({ params }: { params: { id: string } }) {
  const [d, setD] = useState<Detail | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const load = () =>
    call<Detail>(`/v1/executions/${params.id}`, { as: "user" })
      .then(setD)
      .catch((e) => setErr(String(e)));
  useEffect(() => {
    load();
  }, [params.id]);

  if (err) return <p className="notice">{err}</p>;
  if (!d) return <p className="muted">Loading…</p>;

  return (
    <div className="grid">
      <div className="panel">
        <div className="row" style={{ justifyContent: "space-between" }}>
          <h1 style={{ margin: 0 }}>
            Execution <code>{d.claim.id}</code>
          </h1>
          <Badge kind={statusKind(d.claim.state)}>{d.claim.state}</Badge>
        </div>
        <dl className="kv" style={{ marginTop: 12 }}>
          <dt>Grant</dt>
          <dd>
            <code>{d.grant.id}</code> · {d.grant.profile} · {d.grant.mode} · <Badge kind={statusKind(d.grant.status)}>{d.grant.status}</Badge>
          </dd>
          <dt>Amount / payee</dt>
          <dd>
            {money(d.claim.amount_minor, d.claim.currency)} → {d.claim.payee_id}
          </dd>
          <dt>Checkout digest</dt>
          <dd>
            <code>{d.claim.checkout_digest}</code>
          </dd>
          <dt>Idempotency key</dt>
          <dd>
            <code>{(d.claim as any).idempotency_key}</code>
          </dd>
          <dt>Payment attempt</dt>
          <dd>
            {d.claim.payment_attempt?.state}
            {d.claim.payment_attempt?.psp_confirmation_id && <span className="muted"> · PSP {d.claim.payment_attempt.psp_confirmation_id}</span>}
            {d.claim.payment_attempt?.fault && <span className="muted"> · injected fault {d.claim.payment_attempt.fault}</span>}
          </dd>
          <dt>Claimed / resolved</dt>
          <dd>
            {ts(d.claim.claimed_at)} / {ts(d.claim.resolved_at)}
          </dd>
          <dt>Receipts</dt>
          <dd>{Object.keys(d.receipts).length ? Object.keys(d.receipts).join(", ") : <span className="muted">none yet</span>}</dd>
        </dl>
        {d.claim.state === "execution_unknown" && (
          <p className="notice">
            The processor response was lost. The grant is frozen; the worker reconciles from the processor ledger. <button onClick={async () => { await call("/v1/demo/worker/run-once", { method: "POST" }); load(); }}>Run worker now</button>
          </p>
        )}
      </div>
      <DiagnosticCard diagnostic={d.diagnostic} />
      <div className="panel">
        <h2>Verification attempts on this trace</h2>
        <table>
          <thead>
            <tr>
              <th>Verifier role</th>
              <th>Decision</th>
              <th>Reasons</th>
              <th>Latency</th>
              <th>Ruleset</th>
              <th>At</th>
            </tr>
          </thead>
          <tbody>
            {d.verification_attempts.map((v) => (
              <tr key={v.id}>
                <td>{v.role}</td>
                <td>{v.decision}</td>
                <td>{v.reason_codes.join(", ") || "—"}</td>
                <td>{v.latency_ms} ms</td>
                <td className="muted">{v.ruleset_version}</td>
                <td>{ts(v.verified_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <EvidenceViewer claimId={d.claim.id} />
      <details className="panel">
        <summary className="muted">Raw receipts (JWT compact)</summary>
        <JsonView value={d.receipts} />
      </details>
    </div>
  );
}
