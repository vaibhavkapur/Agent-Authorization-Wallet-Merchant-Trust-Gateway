"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { ApiError, Grant, Participants, Proposal, PurchaseResult, call, money, participants } from "@/lib/api";
import { DiagnosticCard } from "@/components/DiagnosticCard";
import { Badge, JsonView, decisionKind } from "@/components/JsonView";
import { ReviewScreen } from "@/components/ReviewScreen";

type Challenge = { challenge_id: string; nonce: string; snapshot_digest: string; expires_at: number; review: Record<string, any> };

function localIsoPlusHours(hours: number): string {
  const d = new Date(Date.now() + hours * 3600 * 1000);
  const off = -d.getTimezoneOffset();
  const sign = off >= 0 ? "+" : "-";
  const pad = (n: number) => String(Math.abs(n)).padStart(2, "0");
  const local = new Date(d.getTime() + off * 60000).toISOString().slice(0, 19);
  return `${local}${sign}${pad(Math.floor(Math.abs(off) / 60))}:${pad(Math.abs(off) % 60)}`;
}

export default function DelegatePage() {
  const [parts, setParts] = useState<Participants | null>(null);
  const [profile, setProfile] = useState<"ap2" | "vi">("ap2");
  const [mode, setMode] = useState<"autonomous" | "direct">("autonomous");
  const [maxTotal, setMaxTotal] = useState("150.00");
  const [merchants, setMerchants] = useState<string[]>(["merchant_a", "merchant_b"]);
  const [expires, setExpires] = useState(localIsoPlusHours(26));
  const [directMerchant, setDirectMerchant] = useState("merchant_a");
  const [directSku, setDirectSku] = useState("SKU-HEADPHONES");
  const [catalog, setCatalog] = useState<Record<string, any[]>>({});
  const [proposal, setProposal] = useState<Proposal | null>(null);
  const [challenge, setChallenge] = useState<Challenge | null>(null);
  const [grant, setGrant] = useState<Grant | null>(null);
  const [purchase, setPurchase] = useState<PurchaseResult | null>(null);
  const [buyMerchant, setBuyMerchant] = useState("merchant_a");
  const [buySku, setBuySku] = useState("SKU-HEADPHONES");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [checkoutRef, setCheckoutRef] = useState<string | null>(null);

  useEffect(() => {
    participants().then(setParts).catch((e) => setError(String(e)));
    for (const m of ["merchant_a", "merchant_b"]) {
      call(`/v1/merchants/${m}/catalog`).then((c) => setCatalog((prev) => ({ ...prev, [m]: c }))).catch(() => undefined);
    }
  }, []);

  const run = async (fn: () => Promise<void>) => {
    setBusy(true);
    setError(null);
    try {
      await fn();
    } catch (e: any) {
      if (e instanceof ApiError) setError(`${e.status}: ${JSON.stringify(e.body?.detail ?? e.body)}`);
      else setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  const propose = () =>
    run(async () => {
      setProposal(null);
      setChallenge(null);
      setGrant(null);
      setPurchase(null);
      let body: Record<string, any>;
      if (mode === "autonomous") {
        body = {
          user_id: parts?.users[0]?.id,
          agent_id: parts?.agents[0]?.id,
          profile,
          mode,
          purchase_count: 1,
          currency: "USD",
          max_total_minor: String(Math.round(parseFloat(maxTotal) * 100)),
          merchant_ids: merchants,
          expires_at: expires,
          display_time_zone: expires.slice(-6),
        };
      } else {
        const co = await call(`/v1/merchants/${directMerchant}/checkouts`, {
          method: "POST",
          body: JSON.stringify({ line_items: [{ id: directSku, quantity: 1 }] }),
        });
        setCheckoutRef(co.checkout_id);
        body = {
          user_id: parts?.users[0]?.id,
          agent_id: parts?.agents[0]?.id,
          profile,
          mode,
          checkout_reference: co.checkout_id,
          merchant_id: directMerchant,
          display_time_zone: expires.slice(-6),
        };
      }
      const p = await call<Proposal>("/v1/authorization-proposals", { method: "POST", body: JSON.stringify(body), as: "agent" });
      setProposal(p);
    });

  const review = () =>
    run(async () => {
      if (!proposal) return;
      const ch = await call<Challenge>(`/v1/authorization-proposals/${proposal.id}/consent-challenge`, { method: "POST", as: "user" });
      setChallenge(ch);
    });

  const approve = () =>
    run(async () => {
      if (!proposal || !challenge) return;
      const g = await call<Grant>(`/v1/authorization-proposals/${proposal.id}/approve`, {
        method: "POST",
        as: "user",
        body: JSON.stringify({ challenge_id: challenge.challenge_id, nonce: challenge.nonce, snapshot_digest: challenge.snapshot_digest }),
      });
      setGrant(g);
    });

  const changeTerms = () =>
    run(async () => {
      if (!proposal) return;
      const p = await call<Proposal>(`/v1/authorization-proposals/${proposal.id}`, {
        method: "PATCH",
        as: "agent",
        body: JSON.stringify({ max_total_minor: String(Math.round(parseFloat(maxTotal) * 100) + 5000) }),
      });
      setProposal(p);
    });

  const buy = () =>
    run(async () => {
      if (!grant) return;
      const body: Record<string, any> =
        grant.mode === "direct"
          ? { grant_id: grant.id, merchant_id: directMerchant, checkout_reference: checkoutRef }
          : { grant_id: grant.id, merchant_id: buyMerchant, items: [{ id: buySku, quantity: 1 }] };
      const res = await call<PurchaseResult>("/v1/agent/purchase", { method: "POST", as: "agent", body: JSON.stringify(body) });
      setPurchase(res);
    });

  const items = catalog[mode === "direct" ? directMerchant : buyMerchant] ?? [];

  return (
    <div className="grid two">
      <div className="grid">
        <div className="panel">
          <h1>Delegate a bounded purchase</h1>
          <p className="muted">
            “Allow my shopping agent to make one purchase up to $150 from either of these two merchants before tomorrow evening.”
          </p>
          {parts && (
            <p className="muted">
              Acting as agent <code>{parts.agents[0]?.id}</code> (proposes) and user <code>{parts.users[0]?.id}</code> (approves).
            </p>
          )}
          <div className="grid two">
            <div>
              <label>Authorization profile</label>
              <select value={profile} onChange={(e) => setProfile(e.target.value as any)}>
                <option value="ap2">AP2 v0.2 (Delegate SD-JWT mandates)</option>
                <option value="vi">Verifiable Intent draft v0.1</option>
              </select>
            </div>
            <div>
              <label>Mode</label>
              <select value={mode} onChange={(e) => setMode(e.target.value as any)}>
                <option value="autonomous">Autonomous (constraints, agent signs closed mandates)</option>
                <option value="direct">Direct / human present (user approves exact checkout)</option>
              </select>
            </div>
          </div>
          {mode === "autonomous" ? (
            <div className="grid two">
              <div>
                <label>Maximum total (USD)</label>
                <input value={maxTotal} onChange={(e) => setMaxTotal(e.target.value)} />
              </div>
              <div>
                <label>Expires (ISO-8601 with offset)</label>
                <input value={expires} onChange={(e) => setExpires(e.target.value)} />
              </div>
              <div>
                <label>Permitted merchants</label>
                {(parts?.merchants ?? []).map((m) => (
                  <div key={m.id} className="row">
                    <input
                      type="checkbox"
                      style={{ width: "auto" }}
                      checked={merchants.includes(m.id)}
                      onChange={(e) => setMerchants(e.target.checked ? [...merchants, m.id] : merchants.filter((x) => x !== m.id))}
                    />
                    <span>
                      {m.name} <span className="muted">{m.website}</span>
                    </span>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div className="grid two">
              <div>
                <label>Merchant</label>
                <select value={directMerchant} onChange={(e) => setDirectMerchant(e.target.value)}>
                  {(parts?.merchants ?? []).map((m) => (
                    <option key={m.id} value={m.id}>{m.name}</option>
                  ))}
                </select>
              </div>
              <div>
                <label>Item (the merchant issues the final checkout)</label>
                <select value={directSku} onChange={(e) => setDirectSku(e.target.value)}>
                  {items.map((p: any) => (
                    <option key={p.id} value={p.id}>{p.title} — {money(p.unit_price_minor)}</option>
                  ))}
                </select>
              </div>
            </div>
          )}
          <div className="row" style={{ marginTop: 12 }}>
            <button className="primary" onClick={propose} disabled={busy || !parts}>1. Agent proposes</button>
            <button onClick={review} disabled={busy || !proposal || proposal.status !== "awaiting_consent"}>2. User reviews (challenge)</button>
            <button className="primary" onClick={approve} disabled={busy || !challenge || !!grant}>3. User approves &amp; signs</button>
            {proposal && !grant && mode === "autonomous" && (
              <button onClick={changeTerms} disabled={busy} title="Demonstrates that a change after review invalidates the challenge">
                Agent changes terms (+$50)
              </button>
            )}
          </div>
          {error && <p className="notice" style={{ marginTop: 12, background: "#fdecea", borderColor: "#f3b6b1", color: "#7a1a14" }}>{error}</p>}
        </div>

        {proposal && (
          <div className={`panel step ${grant ? "done" : "active"}`}>
            <h3>Proposal</h3>
            <div className="row">
              <code>{proposal.id}</code>
              <Badge kind={proposal.status === "approved" ? "ok" : "info"}>{proposal.status}</Badge>
              <span className="muted">digest {proposal.consent_snapshot_digest.slice(0, 16)}…</span>
            </div>
          </div>
        )}

        {grant && (
          <div className="panel step done">
            <h3>Grant</h3>
            <div className="row">
              <Link href={`/authorizations`}><code>{grant.id}</code></Link>
              <Badge kind="ok">{grant.status}</Badge>
              <span className="muted">{grant.profile} · {grant.mode} · agent key {grant.agent_key_thumbprint?.slice(0, 12)}…</span>
            </div>
            <details style={{ marginTop: 8 }}>
              <summary className="muted">Protocol artifact summary (digests, vct, kids)</summary>
              <JsonView value={grant.artifact_summary} maxHeight={240} />
            </details>
            <h3 style={{ marginTop: 14 }}>Agent executes</h3>
            {grant.mode === "autonomous" && (
              <div className="grid two">
                <div>
                  <label>Merchant</label>
                  <select value={buyMerchant} onChange={(e) => setBuyMerchant(e.target.value)}>
                    {(parts?.merchants ?? []).map((m) => (
                      <option key={m.id} value={m.id}>{m.name}</option>
                    ))}
                  </select>
                </div>
                <div>
                  <label>Item</label>
                  <select value={buySku} onChange={(e) => setBuySku(e.target.value)}>
                    {(catalog[buyMerchant] ?? []).map((p: any) => (
                      <option key={p.id} value={p.id}>{p.title} — {money(p.unit_price_minor)}</option>
                    ))}
                  </select>
                </div>
              </div>
            )}
            <div className="row" style={{ marginTop: 10 }}>
              <button className="primary" onClick={buy} disabled={busy}>4. Agent obtains checkout, builds mandates, TAP-signs and submits</button>
            </div>
          </div>
        )}
      </div>

      <div className="grid">
        {challenge && !grant && <ReviewScreen review={challenge.review} digest={challenge.snapshot_digest} />}
        {grant && !purchase && (
          <div className="panel">
            <h2>Approved</h2>
            <p className="muted">The user signing component signed the {grant.profile === "ap2" ? "open/closed AP2 mandates" : "VI Layer 2 mandate"} over the reviewed snapshot. The agent now holds only what it needs to present.</p>
          </div>
        )}
        {purchase && (
          <>
            <div className="panel">
              <div className="row" style={{ justifyContent: "space-between" }}>
                <h2 style={{ margin: 0 }}>Gateway response · HTTP {purchase.status_code}</h2>
                <Badge kind={decisionKind(purchase.response.diagnostic?.decision)}>{purchase.response.diagnostic?.decision ?? purchase.response.detail}</Badge>
              </div>
              {purchase.checkout && (
                <p className="muted">
                  Checkout {purchase.checkout.checkout_id} at {purchase.checkout.merchant.name}: {money(purchase.checkout.total_minor, purchase.checkout.currency)}
                </p>
              )}
              {purchase.response.claim && (
                <p>
                  Execution <Link href={`/executions/${purchase.response.claim.id}`}><code>{purchase.response.claim.id}</code></Link> · state{" "}
                  <Badge kind={purchase.response.claim.state === "consumed" ? "ok" : "warn"}>{purchase.response.claim.state}</Badge>
                  {purchase.response.claim.order_id && <span className="muted"> · order {purchase.response.claim.order_id}</span>}
                </p>
              )}
              <details>
                <summary className="muted">TAP-signed request the agent sent</summary>
                <JsonView value={{ path: purchase.request.path, headers: purchase.request.headers }} maxHeight={200} />
              </details>
            </div>
            <DiagnosticCard diagnostic={purchase.response.diagnostic} />
          </>
        )}
      </div>
    </div>
  );
}
