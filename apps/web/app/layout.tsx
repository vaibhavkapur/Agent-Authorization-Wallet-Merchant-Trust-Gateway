import type { Metadata } from "next";
import type { ReactNode } from "react";
import Link from "next/link";
import "./globals.css";

export const metadata: Metadata = {
  title: "Agent Authorization Wallet",
  description: "Delegated purchase authorization with AP2, Verifiable Intent and TAP verification (local demo).",
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>
        <header className="top">
          <strong>Agent Authorization Wallet</strong>
          <nav>
            <Link href="/">Delegate</Link>
            <Link href="/authorizations">Authorizations</Link>
            <Link href="/executions">Executions</Link>
            <Link href="/demo">Demo &amp; failure injection</Link>
          </nav>
          <span className="muted" style={{ marginLeft: "auto" }}>
            Simulated participants · local verification is not network accreditation
          </span>
        </header>
        <main>{children}</main>
      </body>
    </html>
  );
}
