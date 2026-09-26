"use client";

export const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

export type Participants = {
  users: { id: string; display_name: string; token?: string }[];
  agents: { id: string; display_name: string; provider: string; mandate_key_thumbprint: string; tap_key_id: string; token?: string }[];
  merchants: { id: string; name: string; website: string; checkout_kid: string }[];
  notice: string;
};

export type Diagnostic = {
  decision: "ALLOW" | "REQUIRE_NEW_AUTHORIZATION" | "DENY" | "RECONCILIATION_REQUIRED";
  request_authentication: string;
  delegation_verification: string;
  constraint_verification: string;
  binding_verification: string;
  execution_state: string;
  reason_codes: string[];
  evaluated_total_minor?: string | null;
  authorized_max_minor?: string | null;
  currency?: string | null;
  profile?: string | null;
  profile_version?: string | null;
  ruleset_version?: string;
  trace_id?: string | null;
  execution_outcome?: string;
  details?: Record<string, unknown>;
};

export type Claim = {
  id: string;
  grant_id: string;
  state: string;
  checkout_digest: string;
  amount_minor: number;
  currency: string;
  payee_id: string;
  decision: string;
  trace_id: string;
  order_id?: string | null;
  claimed_at: number;
  resolved_at?: number | null;
  payment_attempt?: { id: string; state: string; psp_confirmation_id?: string | null; fault?: string | null };
};

export type Grant = {
  id: string;
  agent_id: string;
  agent_key_thumbprint?: string;
  profile: string;
  profile_version: string;
  mode: string;
  status: string;
  expires_at: number;
  not_before: number;
  constraints: {
    currency: string;
    max_total_minor: string;
    merchants: { id: string; name: string; website?: string }[];
    expires_at: string;
  };
  bound_checkout_digest?: string | null;
  version: number;
  created_at: number;
  artifact_summary?: Record<string, unknown>;
};

export type Proposal = {
  id: string;
  status: string;
  profile: string;
  mode: string;
  consent_snapshot: Record<string, any>;
  consent_snapshot_digest: string;
  grant_id?: string | null;
};

export type PurchaseResult = {
  status_code: number;
  response: { diagnostic?: Diagnostic; claim?: Claim | null; receipts?: Record<string, string>; detail?: string; idempotent_replay?: boolean; checkout_receipt?: string };
  request: { path: string; headers: Record<string, string>; body: string; nonce: string; checkout_id: string; trace_id: string };
  checkout?: { checkout_id: string; total_minor: number; currency: string; line_items: { id: string; title: string; quantity: number; unit_price_minor: number }[]; checkout_hash: string; merchant: { id: string; name: string } };
};

let cached: Participants | null = null;

export async function participants(): Promise<Participants> {
  if (cached) return cached;
  const r = await fetch(`${API_URL}/v1/participants`);
  if (!r.ok) throw new Error(`participants: ${r.status}`);
  cached = (await r.json()) as Participants;
  return cached;
}

export async function userHeaders(): Promise<Record<string, string>> {
  const p = await participants();
  const token = p.users[0]?.token;
  return token ? { Authorization: `Bearer ${token}` } : {};
}

export async function agentHeaders(): Promise<Record<string, string>> {
  const p = await participants();
  const token = p.agents[0]?.token;
  return token ? { "X-Agent-Token": token } : {};
}

export class ApiError extends Error {
  status: number;
  body: any;
  constructor(status: number, body: any) {
    super(typeof body?.detail === "string" ? body.detail : `HTTP ${status}`);
    this.status = status;
    this.body = body;
  }
}

export async function call<T = any>(path: string, init: RequestInit & { as?: "user" | "agent" | "none" } = {}): Promise<T> {
  const { as = "none", ...rest } = init;
  const auth = as === "user" ? await userHeaders() : as === "agent" ? await agentHeaders() : {};
  const r = await fetch(`${API_URL}${path}`, {
    ...rest,
    headers: { "Content-Type": "application/json", ...auth, ...(rest.headers ?? {}) },
  });
  let body: any = null;
  try {
    body = await r.json();
  } catch {
    body = null;
  }
  if (!r.ok) throw new ApiError(r.status, body);
  return body as T;
}

export function money(minor: number | string | null | undefined, currency = "USD"): string {
  if (minor === null || minor === undefined) return "—";
  const n = typeof minor === "string" ? parseInt(minor, 10) : minor;
  return `${currency} ${(n / 100).toFixed(2)}`;
}

export function ts(epoch?: number | null): string {
  if (!epoch) return "—";
  return new Date(epoch * 1000).toLocaleString();
}
