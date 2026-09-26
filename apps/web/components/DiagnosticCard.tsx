"use client";

import { Diagnostic, money } from "@/lib/api";
import { Badge, JsonView, decisionKind, statusKind } from "./JsonView";

const CHECKS: { key: keyof Diagnostic; label: string }[] = [
  { key: "request_authentication", label: "Request authentication (TAP)" },
  { key: "delegation_verification", label: "Delegation verification" },
  { key: "constraint_verification", label: "Purchase constraints" },
  { key: "binding_verification", label: "Checkout ↔ payment binding" },
  { key: "execution_state", label: "Execution state" },
];

export function DiagnosticCard({ diagnostic, title }: { diagnostic?: Diagnostic | null; title?: string }) {
  if (!diagnostic) return null;
  return (
    <div className="panel">
      <div className="row" style={{ justifyContent: "space-between", marginBottom: 12 }}>
        <h2 style={{ margin: 0 }}>{title ?? "Verification diagnostic"}</h2>
        <Badge kind={decisionKind(diagnostic.decision)}>{diagnostic.decision}</Badge>
      </div>
      <div className="checks">
        {CHECKS.map((c) => (
          <div className="check" key={c.key}>
            <div className="name">{c.label}</div>
            <Badge kind={statusKind(String(diagnostic[c.key]))}>{String(diagnostic[c.key])}</Badge>
          </div>
        ))}
      </div>
      <dl className="kv" style={{ marginTop: 12 }}>
        <dt>Reason codes</dt>
        <dd>{diagnostic.reason_codes?.length ? diagnostic.reason_codes.map((r) => <code key={r} style={{ marginRight: 6 }}>{r}</code>) : <span className="muted">none</span>}</dd>
        {diagnostic.evaluated_total_minor && (
          <>
            <dt>Evaluated total</dt>
            <dd>{money(diagnostic.evaluated_total_minor, diagnostic.currency ?? "USD")}</dd>
          </>
        )}
        {diagnostic.authorized_max_minor && (
          <>
            <dt>Authorized maximum</dt>
            <dd>{money(diagnostic.authorized_max_minor, diagnostic.currency ?? "USD")}</dd>
          </>
        )}
        {diagnostic.execution_outcome && (
          <>
            <dt>Execution outcome</dt>
            <dd>{diagnostic.execution_outcome}</dd>
          </>
        )}
        <dt>Profile / ruleset</dt>
        <dd>
          {diagnostic.profile ?? "—"} <span className="muted">{diagnostic.profile_version}</span> · {diagnostic.ruleset_version}
        </dd>
        <dt>Trace</dt>
        <dd>
          <code>{diagnostic.trace_id}</code>
        </dd>
      </dl>
      <details style={{ marginTop: 8 }}>
        <summary className="muted">Raw diagnostic</summary>
        <JsonView value={diagnostic} />
      </details>
    </div>
  );
}
