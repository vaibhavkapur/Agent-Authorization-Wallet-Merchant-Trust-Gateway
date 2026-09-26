"use client";

import type { ReactNode } from "react";

export function JsonView({ value, maxHeight }: { value: unknown; maxHeight?: number }) {
  return (
    <pre className="json" style={maxHeight ? { maxHeight } : undefined}>
      {JSON.stringify(value, null, 2)}
    </pre>
  );
}

export function Badge({ kind, children }: { kind: "ok" | "warn" | "bad" | "info" | "neutral"; children: ReactNode }) {
  return <span className={`badge ${kind}`}>{children}</span>;
}

export function decisionKind(decision?: string): "ok" | "warn" | "bad" | "info" | "neutral" {
  switch (decision) {
    case "ALLOW":
      return "ok";
    case "REQUIRE_NEW_AUTHORIZATION":
      return "warn";
    case "DENY":
      return "bad";
    case "RECONCILIATION_REQUIRED":
      return "info";
    default:
      return "neutral";
  }
}

export function statusKind(status?: string): "ok" | "warn" | "bad" | "info" | "neutral" {
  switch (status) {
    case "valid":
    case "active":
    case "consumed":
      return "ok";
    case "failed":
    case "cancelled":
    case "expired":
      return "bad";
    case "claimed":
    case "executing":
    case "execution_unknown":
    case "requires_new_authorization":
      return "warn";
    case "not_applicable":
    case "skipped":
      return "neutral";
    default:
      return "neutral";
  }
}
