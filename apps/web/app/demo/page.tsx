"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { ApiError, Grant, Participants, PurchaseResult, call, money, participants } from "@/lib/api";
import { DiagnosticCard } from "@/components/DiagnosticCard";
import { Badge, JsonView, decisionKind } from "@/components/JsonView";

type Step = { label: string; result?: PurchaseResult; note?: string };

const FAR_FUTURE_HOURS = 26;

function isoIn(hours: number): string {
  return new Date(Date.now() + hours * 3600 * 1000).toISOString();
}

export default function DemoPage() {
  const [parts, setParts] = useState<Participants | null>(null);
  const [profile, setProfile] = useState<"ap2" | "vi">("ap2");
  const [steps, setSteps] = useState<Step[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [fault, setFault] = useState<string>("");
  const [grant, setGrant] = useState<Grant | null>(null);
  const [tamper, setTamper] = useState<Record<string, boolean>>({});
  const [tap, setTap] = useState<Record<string, boolean>>({});
  const [lastRequest, setLastRequest] = useState<PurchaseResult["request"] | null>(null);

  useEffect(() => {
    participants().then(setParts).catch((e) => setError(String(e)));
    call<{ faults: { payment?: string } }>("/v1/demo/faults").then((f) => setFault(f.faults.payment ?? "")).catch(() => undefined);
  }, []);

  const run = async (fn: () => Promise<void>) => {
    setBusy(true);
    setError(null);
    try {
      await fn();
    } catch (e: any) {
      setError(e instanceof ApiError ? `${e.status}: ${JSON.stringify(e.body?.detail ?? e.body)}` : String(e));
    } finally {
      setBusy(false);
    }
  };

  const makeGrant = async (opts: Record<string, any> = {}): Promise<Grant> => {
    const p = await call("/v1/authorization-proposals", {
      method: "POST",
      as: "agent",
      body: JSON.stringify({
        user_id: parts?.users[0]?.id,
        agent_id: parts?.agents[0]?.id,
        profile,
        mode: "autonomous",
        currency: "USD",
        max_total_minor: "15000",
        merchant_ids: ["merchant_a", "merchant_b"],
        expires_at: isoIn(FAR_FUTURE_HOURS),
        display_time_zone: "+00:00",
        ...opts,
      }),
    });
    const ch = await call(`/v1/authorization-proposals/${p.id}/consent-challenge`, { method: "POST", as: "user" });
    const g = await call<Grant>(`/v1/authorization-proposals/${p.id}/approve`, {
      method: "POST",
      as: "user",
      body: JSON.stringify({ challenge_id: ch.challenge_id, nonce: ch.nonce, snapshot_digest: ch.snapshot_digest }),
    });
    setGrant(g);
    return g;
  };

  const buy = (grantId: string, merchant: string, sku: string, extra: Record<string, any> = {}) =>
    call<PurchaseResult>("/v1/agent/purchase", {
      method: "POST",
      as: "agent",
      body: JSON.stringify({ grant_id: grantId, merchant_id: merchant, items: [{ id: sku, quantity: 1 }], ...extra }),
    });

  const scenario = (name: string, fn: () => Promise<Step[]>) =>
    run(async () => {
      setSteps([{ label: `Running ${name}…` }]);
      const out = await fn();
      setSteps(out);
    });

  const demoA = () =>
    scenario("Demo A", async () => {
      const g = await makeGrant();
      const r = await buy(g.id, "merchant_a", "SKU-HEADPHONES");
      setLastRequest(r.request);
      return [{ label: "User permits one purchase up to $150; agent buys $120 headphones", result: r }];
    });

  const demoB = () =>
    scenario("Demo B", async () => {
      const g = await makeGrant({ merchant_ids: ["merchant_a"] });
      const r = await buy(g.id, "merchant_a", "SKU-SPEAKER");
      return [{ label: "TAP verifies the recognised agent, but the $155 checkout exceeds the $150 cap", result: r }];
    });

  const demoC = () =>
    scenario("Demo C", async () => {
      const g = await makeGrant();
      const r1 = await buy(g.id, "merchant_a", "SKU-HEADPHONES", { tamper: { alter_payee_after_signing: { id: "merchant_b", name: "Merchant B (test)" } } });
      const r2 = await buy(g.id, "merchant_a", "SKU-HEADPHONES", { tamper: { payment_amount_minor: 100 } });
      const r3 = await buy(g.id, "merchant_a", "SKU-HEADPHONES", { tamper: { wrong_agent_key: true } });
      return [
        { label: "Recipient replaced after signing → disclosure digest no longer matches", result: r1 },
        { label: "Agent signs a payment mandate for $1 while the checkout is $120 → binding mismatch", result: r2 },
        { label: "Closed mandates signed with a key the user never delegated to", result: r3 },
      ];
    });

  const demoD = () =>
    scenario("Demo D", async () => {
      const g = await makeGrant();
      const first = await buy(g.id, "merchant_a", "SKU-HEADPHONES");
      const replay = await call<PurchaseResult>("/v1/agent/replay", { method: "POST", as: "agent", body: JSON.stringify({ request: first.request }) });
      const retry = await buy(g.id, "merchant_a", "SKU-HEADPHONES", { checkout_reference: first.request.checkout_id });
      const other = await buy(g.id, "merchant_b", "SKU-MOUSE");
      return [
        { label: "First purchase executes", result: first },
        { label: "Same signed request delivered again → transport replay rejected by TAP nonce record", result: replay },
        { label: "Freshly signed retry of the same business operation → original outcome returned (idempotent)", result: retry },
        { label: "Different purchase with the consumed grant → new authorization required", result: other },
      ];
    });

  const demoE = () =>
    scenario("Demo E", async () => {
      const g = await makeGrant();
      const r = await buy(g.id, "merchant_a", "SKU-HEADPHONES");
      return [{ label: "Open the execution and compare the merchant and payment views side by side", result: r, note: r.response.claim ? `/executions/${r.response.claim.id}` : undefined }];
    });

  const recovery = (kind: "lose_response" | "crash_before_submit" | "decline") =>
    scenario(`Recovery: ${kind}`, async () => {
      const g = await makeGrant();
      const r = await buy(g.id, "merchant_a", "SKU-HEADPHONES", { fault: kind });
      const worker = await call("/v1/demo/worker/run-once", { method: "POST" });
      const after = r.response.claim ? await call(`/v1/executions/${r.response.claim.id}`, { as: "user" }) : null;
      return [
        { label: `Injected fault: ${kind}`, result: r },
        { label: `Worker run: ${JSON.stringify(worker)} → claim now ${after?.claim?.state ?? "n/a"}; grant ${after?.grant?.status ?? "n/a"}`, note: kind === "crash_before_submit" ? "Stale claims are only reconciled after 30 s; advance the clock (AAW_FIXED_CLOCK=1) or run the worker again later." : undefined },
      ];
    });

  const custom = () =>
    run(async () => {
      const g = grant ?? (await makeGrant());
      const t: Record<string, any> = {};
      if (tamper.wrong_agent_key) t.wrong_agent_key = true;
      if (tamper.underpay) t.payment_amount_minor = 100;
      if (tamper.alter_amount) t.alter_payment_amount_after_signing = 1;
      if (tamper.drop_checkout) t.drop_checkout_jwt = true;
      if (tamper.extra_disclosure) t.extra_disclosure = true;
      const tp: Record<string, any> = {};
      if (tap.wrong_key) tp.wrong_key = true;
      if (tap.browser_tag) tp.tag = "agent-browser-auth";
      if (tap.tamper_body) tp.tamper_body = true;
      if (tap.expired) tp.age_seconds = 1000;
      if (tap.no_digest) tp.no_content_digest = true;
      const r = await buy(g.id, "merchant_a", "SKU-HEADPHONES", { tamper: t, tap: tp, fault: fault || undefined });
      setLastRequest(r.request);
      setSteps([{ label: "Custom injection", result: r }]);
    });

  const replayLast = () =>
    run(async () => {
      if (!lastRequest) return;
      const r = await call<PurchaseResult>("/v1/agent/replay", { method: "POST", as: "agent", body: JSON.stringify({ request: lastRequest }) });
      setSteps((s) => [...s, { label: "Replayed last signed request", result: r }]);
    });

  const setGlobalFault = (value: string) =>
    run(async () => {
      await call("/v1/demo/faults", { method: "POST", body: JSON.stringify({ payment: value || null }) });
      setFault(value);
    });

  return (
    <div className="grid two">
      <div className="grid">
        <div className="panel">
          <h1>Demo scenarios</h1>
          <label>Profile</label>
          <select value={profile} onChange={(e) => setProfile(e.target.value as any)}>
            <option value="ap2">AP2 v0.2</option>
            <option value="vi">Verifiable Intent draft v0.1</option>
          </select>
          <div className="grid" style={{ marginTop: 12 }}>
            <button onClick={demoA} disabled={busy || !parts}>A · Valid autonomous purchase ($120 of $150)</button>
            <button onClick={demoB} disabled={busy || !parts}>B · Authentic request, invalid purchase ($155)</button>
            <button onClick={demoC} disabled={busy || !parts}>C · Checkout / recipient tampering</button>
            <button onClick={demoD} disabled={busy || !parts}>D · Replay and concurrency</button>
            <button onClick={demoE} disabled={busy || !parts}>E · Private evidence views</button>
            <div className="row">
              <button onClick={() => recovery("lose_response")} disabled={busy || !parts}>Recovery · lost response</button>
              <button onClick={() => recovery("crash_before_submit")} disabled={busy || !parts}>Recovery · worker crash</button>
              <button onClick={() => recovery("decline")} disabled={busy || !parts}>Processor declines</button>
            </div>
          </div>
        </div>
        <div className="panel">
          <h2>Failure injection</h2>
          <h3>Mandate tampering (agent side)</h3>
          {[
            ["wrong_agent_key", "Sign closed mandates with an undelegated key"],
            ["underpay", "Payment mandate for $1 against a $120 checkout"],
            ["alter_amount", "Alter the payment amount after signing"],
            ["drop_checkout", "Omit the checkout_jwt disclosure"],
            ["extra_disclosure", "Attach an unreferenced disclosure"],
          ].map(([k, label]) => (
            <div className="row" key={k}>
              <input type="checkbox" style={{ width: "auto" }} checked={!!tamper[k]} onChange={(e) => setTamper({ ...tamper, [k]: e.target.checked })} />
              <span style={{ fontSize: 13 }}>{label}</span>
            </div>
          ))}
          <h3 style={{ marginTop: 12 }}>TAP request</h3>
          {[
            ["wrong_key", "Sign with an unregistered key"],
            ["browser_tag", "Use tag agent-browser-auth for a payment"],
            ["tamper_body", "Change the body after signing (Content-Digest)"],
            ["expired", "Present a signature created 1000 s ago"],
            ["no_digest", "Do not cover content-digest"],
          ].map(([k, label]) => (
            <div className="row" key={k}>
              <input type="checkbox" style={{ width: "auto" }} checked={!!tap[k]} onChange={(e) => setTap({ ...tap, [k]: e.target.checked })} />
              <span style={{ fontSize: 13 }}>{label}</span>
            </div>
          ))}
          <h3 style={{ marginTop: 12 }}>Payment processor fault (process-wide default)</h3>
          <select value={fault} onChange={(e) => setGlobalFault(e.target.value)}>
            <option value="">none</option>
            <option value="decline">decline</option>
            <option value="lose_response">lose_response</option>
            <option value="crash_before_submit">crash_before_submit</option>
          </select>
          <div className="row" style={{ marginTop: 12 }}>
            <button className="primary" onClick={custom} disabled={busy || !parts}>Run purchase with these settings</button>
            <button onClick={replayLast} disabled={busy || !lastRequest}>Replay last signed request</button>
            <button onClick={() => setGrant(null)} disabled={busy}>Use a fresh grant next time</button>
          </div>
          {grant && <p className="muted">Reusing grant <code>{grant.id}</code></p>}
          {error && <p className="notice">{error}</p>}
        </div>
      </div>
      <div className="grid">
        {steps.map((s, i) => (
          <div key={i} className="grid">
            <div className="panel">
              <div className="row" style={{ justifyContent: "space-between" }}>
                <strong>{s.label}</strong>
                {s.result && <Badge kind={decisionKind(s.result.response.diagnostic?.decision)}>{s.result.response.diagnostic?.decision ?? `HTTP ${s.result.status_code}`}</Badge>}
              </div>
              {s.result?.checkout && (
                <span className="muted">
                  checkout {money(s.result.checkout.total_minor, s.result.checkout.currency)} at {s.result.checkout.merchant.name} · HTTP {s.result.status_code}
                  {s.result.response.idempotent_replay && " · idempotent replay"}
                </span>
              )}
              {s.result?.response.claim && (
                <div>
                  <Link href={`/executions/${s.result.response.claim.id}`}>execution {s.result.response.claim.id}</Link> · {s.result.response.claim.state}
                </div>
              )}
              {s.note && (
                <p className="muted">
                  {s.note.startsWith("/") ? <Link href={s.note}>open evidence viewer →</Link> : s.note}
                </p>
              )}
            </div>
            {s.result?.response.diagnostic && <DiagnosticCard diagnostic={s.result.response.diagnostic} title="Diagnostic" />}
            {s.result && !s.result.response.diagnostic && <JsonView value={s.result.response} maxHeight={200} />}
          </div>
        ))}
        {!steps.length && (
          <div className="panel">
            <h2>What the demos show</h2>
            <ul style={{ fontSize: 14, paddingLeft: 18 }}>
              <li>Which agent sent the request and whether it is authentic (TAP request signature, registry key, nonce).</li>
              <li>What authority the user delegated (user-signed open mandates with the agent key in <code>cnf</code>).</li>
              <li>Whether this exact purchase fits that authority (deterministic constraints and checkout ↔ payment binding).</li>
              <li>What a signature does not prove: the merchant&apos;s product description or delivery.</li>
            </ul>
          </div>
        )}
      </div>
    </div>
  );
}
