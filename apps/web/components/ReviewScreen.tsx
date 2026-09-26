"use client";

import { money } from "@/lib/api";

/**
 * Trusted review screen (plan §8). Renders only validated snapshot data returned by
 * the wallet API; nothing on this screen is editable and the digest shown is the
 * digest the user signs over.
 */
export function ReviewScreen({ review, digest }: { review: Record<string, any>; digest: string }) {
  const v = review.validity ?? {};
  const total = review.maximum_delivered_total ?? {};
  const exact = review.exact_checkout;
  return (
    <div className="panel" style={{ borderColor: "#16202a" }}>
      <h2>Review before you approve</h2>
      <p className="notice">
        Simulated user device. This is the exact representation you are approving; if the proposal changes, this
        screen and its challenge are invalidated.
      </p>
      <dl className="kv" style={{ marginTop: 12 }}>
        <dt>Delegated agent</dt>
        <dd>
          {review.agent?.display_name} <span className="muted">({review.agent?.id}, provider {review.agent?.provider})</span>
          <br />
          <span className="muted">agent key thumbprint </span>
          <code>{review.agent?.mandate_key_thumbprint}</code>
        </dd>
        <dt>Purchases permitted</dt>
        <dd>{review.purchase_count}</dd>
        <dt>Permitted merchants</dt>
        <dd>
          {(review.permitted_merchants ?? []).map((m: any) => (
            <div key={m.id}>
              {m.name} <span className="muted">{m.website}</span>
            </div>
          ))}
        </dd>
        <dt>Maximum delivered total</dt>
        <dd>
          <strong>{total.display ?? money(total.minor, total.currency)}</strong>
        </dd>
        <dt>Valid from</dt>
        <dd>
          {v.not_before_local} <span className="muted">({v.not_before_utc} UTC)</span>
        </dd>
        <dt>Expires</dt>
        <dd>
          {v.expires_at_local} <span className="muted">({v.expires_at_utc} UTC, shown in {v.display_time_zone})</span>
        </dd>
        <dt>You are approving</dt>
        <dd>{review.approval_type === "exact_items" ? "exact items and total of one checkout" : "constraints the agent must stay within"}</dd>
        {exact && (
          <>
            <dt>Exact checkout</dt>
            <dd>
              {exact.merchant?.name} · total {money(exact.total?.minor, exact.total?.currency)}
              <ul style={{ margin: "4px 0 0", paddingLeft: 18 }}>
                {exact.line_items?.map((li: any) => (
                  <li key={li.id}>
                    {li.quantity} × {li.title} <span className="muted">({li.id}, {money(li.unit_price_minor, exact.total?.currency)})</span>
                  </li>
                ))}
              </ul>
              <span className="muted">checkout hash </span>
              <code>{exact.checkout_hash}</code>
            </dd>
          </>
        )}
        {review.required_line_items && (
          <>
            <dt>Required items</dt>
            <dd>
              {review.required_line_items.map((li: any) => (
                <div key={li.id}>
                  {li.quantity} × one of {li.acceptable_items.map((a: any) => a.title).join(" / ")}
                </div>
              ))}
            </dd>
          </>
        )}
        <dt>Payment instrument</dt>
        <dd>{review.payment_instrument?.description}</dd>
        <dt>Shared with the merchant</dt>
        <dd>{(review.data_sharing?.merchant_receives ?? []).join("; ")}</dd>
        <dt>Shared with payment participants</dt>
        <dd>{(review.data_sharing?.payment_receives ?? []).join("; ")}</dd>
        <dt>Never shared</dt>
        <dd>{(review.data_sharing?.never_shared ?? []).join("; ")}</dd>
        <dt>Protocol profile</dt>
        <dd>
          {review.profile} <span className="muted">{review.profile_version}</span> · {review.mode}
        </dd>
        <dt>Snapshot digest</dt>
        <dd>
          <code>{digest}</code>
        </dd>
      </dl>
      <p className="muted" style={{ marginTop: 10 }}>{review.simulated_participants_notice}</p>
    </div>
  );
}
