"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { ApiError, Grant, call, money, ts } from "@/lib/api";
import { Badge, statusKind } from "@/components/JsonView";

export default function AuthorizationsPage() {
  const [grants, setGrants] = useState<Grant[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);

  const load = () =>
    call<Grant[]>("/v1/authorizations", { as: "user" })
      .then(setGrants)
      .catch((e) => setError(String(e)));

  useEffect(() => {
    load();
  }, []);

  const cancel = async (id: string) => {
    try {
      const r = await call<{ outcome: string; note?: string }>(`/v1/authorizations/${id}/cancel`, { method: "POST", as: "user" });
      setNote(`${id}: ${r.outcome}${r.note ? ` — ${r.note}` : ""}`);
      await load();
    } catch (e: any) {
      setError(e instanceof ApiError ? `${e.status}: ${JSON.stringify(e.body)}` : String(e));
    }
  };

  return (
    <div className="grid">
      <div className="panel">
        <h1>Authorizations</h1>
        <p className="muted">
          Lifecycle: proposed → awaiting_consent → active → claimed → consumed; active → cancelled | expired; claimed → execution_unknown → consumed | resolved_not_executed.
          Cancellation is serialised with claiming on the grant row; once submission has begun it can only be pending.
        </p>
        {error && <p className="notice">{error}</p>}
        {note && <p className="notice">{note}</p>}
        <table>
          <thead>
            <tr>
              <th>Grant</th>
              <th>Profile</th>
              <th>Mode</th>
              <th>Status</th>
              <th>Cap</th>
              <th>Merchants</th>
              <th>Expires</th>
              <th>Version</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {grants.map((g) => (
              <tr key={g.id}>
                <td>
                  <code>{g.id}</code>
                </td>
                <td>{g.profile}</td>
                <td>{g.mode}</td>
                <td>
                  <Badge kind={statusKind(g.status)}>{g.status}</Badge>
                </td>
                <td>{money(g.constraints.max_total_minor, g.constraints.currency)}</td>
                <td>{g.constraints.merchants.map((m) => m.name).join(", ")}</td>
                <td>{ts(g.expires_at)}</td>
                <td>{g.version}</td>
                <td>
                  <button className="danger" onClick={() => cancel(g.id)} disabled={g.status !== "active"}>
                    Cancel
                  </button>
                </td>
              </tr>
            ))}
            {!grants.length && (
              <tr>
                <td colSpan={9} className="muted">
                  No authorizations yet. <Link href="/">Delegate one.</Link>
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
