"use client";

import { useEffect, useState } from "react";
import { call } from "@/lib/api";
import { Badge, JsonView } from "./JsonView";

type Role = "merchant" | "payment" | "user" | "auditor";

type Evidence = {
  role: Role;
  profile: string;
  profile_version: string;
  artifacts: Record<string, any>;
  receipts: Record<string, { jwt: string; status: string; reference: string; issuer: string; decoded: { header: any; payload: any } }>;
  diagnostic: any;
  explanation: string;
  audit_events?: { actor: string; action: string; target: string; at: number; details: any }[];
  grant?: any;
};

function PresentationView({ view }: { view: any }) {
  if (view?.links) {
    return (
      <div>
        {view.links.map((l: any) => (
          <div key={l.link} className="panel" style={{ marginBottom: 8 }}>
            <div className="row">
              <Badge kind="neutral">link {l.link}</Badge>
              <code>typ {l.header?.typ}</code>
              <code>alg {l.header?.alg}</code>
              {l.header?.kid && <code>kid {l.header.kid}</code>}
            </div>
            <details open>
              <summary className="muted">Signed payload</summary>
              <JsonView value={l.payload} maxHeight={220} />
            </details>
            <details open>
              <summary className="muted">Disclosures presented to this role ({l.disclosures.length})</summary>
              <JsonView value={l.disclosures} maxHeight={260} />
            </details>
          </div>
        ))}
      </div>
    );
  }
  if (view?.layers) {
    return (
      <div>
        {Object.entries(view.layers).map(([name, layer]: any) => (
          <div key={name} className="panel" style={{ marginBottom: 8 }}>
            <div className="row">
              <Badge kind="neutral">{name.toUpperCase()}</Badge>
              <code>typ {layer.header?.typ}</code>
              <code>alg {layer.header?.alg}</code>
              {layer.header?.kid && <code>kid {layer.header.kid}</code>}
            </div>
            <details open>
              <summary className="muted">Signed payload</summary>
              <JsonView value={layer.payload} maxHeight={220} />
            </details>
            <details open>
              <summary className="muted">Disclosures presented to this role ({layer.disclosures?.length ?? 0})</summary>
              <JsonView value={layer.disclosures} maxHeight={260} />
            </details>
          </div>
        ))}
      </div>
    );
  }
  return <JsonView value={view} />;
}

export function EvidenceViewer({ claimId }: { claimId: string }) {
  const [role, setRole] = useState<Role>("merchant");
  const [ev, setEv] = useState<Evidence | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    setEv(null);
    call<Evidence>(`/v1/executions/${claimId}/evidence?role=${role}`, { as: "user" })
      .then(setEv)
      .catch((e) => setErr(String(e)));
  }, [claimId, role]);

  return (
    <div className="panel">
      <h2>Role-specific evidence</h2>
      <div className="tabs">
        {(["merchant", "payment", "user", "auditor"] as Role[]).map((r) => (
          <button key={r} className={r === role ? "active" : ""} onClick={() => setRole(r)}>
            {r} view
          </button>
        ))}
      </div>
      {err && <p className="notice">{err}</p>}
      {ev && (
        <div className="grid">
          <p className="muted">{ev.explanation}</p>
          {Object.entries(ev.artifacts).map(([type, value]) => (
            <div key={type}>
              <h3>{type.replace(/_/g, " ")}</h3>
              {type.endsWith("_presentation") ? <PresentationView view={value} /> : <JsonView value={value} maxHeight={260} />}
            </div>
          ))}
          {Object.keys(ev.receipts).length > 0 && (
            <div>
              <h3>Receipts</h3>
              {Object.entries(ev.receipts).map(([kind, r]) => (
                <div key={kind} className="panel" style={{ marginBottom: 8 }}>
                  <div className="row">
                    <Badge kind={r.status === "Success" ? "ok" : "bad"}>{kind} receipt · {r.status}</Badge>
                    <span className="muted">issuer {r.issuer}</span>
                    <span className="muted">reference {r.reference.slice(0, 16)}…</span>
                  </div>
                  <JsonView value={r.decoded} maxHeight={200} />
                </div>
              ))}
            </div>
          )}
          {ev.audit_events && (
            <div>
              <h3>Audit trail</h3>
              <table>
                <thead>
                  <tr>
                    <th>At</th>
                    <th>Actor</th>
                    <th>Action</th>
                    <th>Target</th>
                  </tr>
                </thead>
                <tbody>
                  {ev.audit_events.map((e, i) => (
                    <tr key={i}>
                      <td>{new Date(e.at * 1000).toLocaleTimeString()}</td>
                      <td>{e.actor}</td>
                      <td>
                        <code>{e.action}</code>
                      </td>
                      <td className="muted">{e.target}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
