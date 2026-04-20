"use client";

import { useCallback, useEffect, useMemo, useState } from "react";

/**
 * AEX operator dashboard (M4 alpha).
 *
 * Today this surfaces:
 *   - live control-plane health
 *   - latest audit chain head (via Rekor-friendly view; polled)
 *   - placeholders for Agents / Transfers / Policies that are wired as
 *     soon as the matching admin endpoints ship.
 *
 * The admin-auth layer isn't done yet — we point the dashboard at a
 * control plane URL from localStorage (or ?base=) and rely on the
 * operator running this against their own instance. Don't deploy this
 * as a public page.
 */

const DEFAULT_BASE = "http://127.0.0.1:8080";

type Health = {
  status: string;
  service?: string;
  version?: string;
} | null;

type StatusState = "idle" | "loading" | "ok" | "error";

export default function DashboardPage() {
  const [baseUrl, setBaseUrl] = useState(DEFAULT_BASE);
  const [health, setHealth] = useState<Health>(null);
  const [healthState, setHealthState] = useState<StatusState>("idle");
  const [healthError, setHealthError] = useState<string | null>(null);

  useEffect(() => {
    if (typeof window === "undefined") return;
    const qp = new URLSearchParams(window.location.search).get("base");
    const stored = window.localStorage.getItem("spize.dashboard.base");
    if (qp) setBaseUrl(qp);
    else if (stored) setBaseUrl(stored);
  }, []);

  const saveBase = useCallback((v: string) => {
    setBaseUrl(v);
    if (typeof window !== "undefined") {
      window.localStorage.setItem("spize.dashboard.base", v);
    }
  }, []);

  const refreshHealth = useCallback(async () => {
    setHealthState("loading");
    setHealthError(null);
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 5_000);
    try {
      const res = await fetch(`${baseUrl.replace(/\/$/, "")}/healthz`, {
        signal: ctrl.signal,
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const json = (await res.json()) as Health;
      setHealth(json);
      setHealthState("ok");
    } catch (e) {
      const msg =
        e instanceof Error
          ? e.name === "AbortError"
            ? "timeout (>5s)"
            : e.message
          : String(e);
      setHealthError(msg);
      setHealthState("error");
    } finally {
      clearTimeout(timer);
    }
  }, [baseUrl]);

  useEffect(() => {
    refreshHealth();
    const id = setInterval(refreshHealth, 10_000);
    return () => clearInterval(id);
  }, [refreshHealth]);

  const healthBadge = useMemo(() => {
    switch (healthState) {
      case "ok":
        return { color: "bg-emerald-500", label: "healthy" };
      case "loading":
        return { color: "bg-amber-400", label: "checking…" };
      case "error":
        return { color: "bg-rose-500", label: "unreachable" };
      default:
        return { color: "bg-slate-500", label: "idle" };
    }
  }, [healthState]);

  return (
    <main className="mx-auto max-w-5xl px-6 py-10">
      <header className="mb-10">
        <p className="text-xs uppercase tracking-widest text-slate-400">
          Agent Exchange Protocol (AEX)
        </p>
        <h1 className="mt-2 text-3xl font-bold">Operator Dashboard</h1>
        <p className="mt-2 text-sm text-slate-400">
          Read-only view into a Spize control plane. Alpha — admin auth + RBAC land in M5.
        </p>
      </header>

      <section className="mb-8 rounded-xl border border-white/10 bg-white/5 p-5">
        <div className="flex flex-wrap items-center gap-3">
          <label className="text-sm text-slate-300" htmlFor="base">
            Control plane URL
          </label>
          <input
            id="base"
            type="text"
            value={baseUrl}
            onChange={(e) => saveBase(e.target.value)}
            className="flex-1 min-w-[260px] rounded-md border border-white/10 bg-black/30 px-3 py-2 text-sm outline-none focus:border-blue-400"
            spellCheck={false}
            autoComplete="off"
          />
          <button
            onClick={refreshHealth}
            className="rounded-md bg-blue-500 px-4 py-2 text-sm font-medium text-white hover:bg-blue-400"
          >
            Refresh
          </button>
        </div>
      </section>

      <section className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3 mb-8">
        <Card title="Control plane">
          <div className="flex items-center gap-2">
            <span
              className={`inline-block h-2.5 w-2.5 rounded-full ${healthBadge.color}`}
              aria-hidden
            />
            <span className="text-sm">{healthBadge.label}</span>
          </div>
          {health && (
            <dl className="mt-4 space-y-1 text-xs text-slate-400">
              <DescRow term="service" detail={health.service ?? "?"} />
              <DescRow term="version" detail={health.version ?? "?"} />
            </dl>
          )}
          {healthError && (
            <p className="mt-3 text-xs text-rose-300">Error: {healthError}</p>
          )}
        </Card>

        <Card title="Agents (24h)" placeholder={
          <>
            <p>Registrations count, breakdown by org.</p>
            <p className="mt-2 text-xs text-slate-500">
              Needs <code>GET /admin/agents</code> — queued for M4.
            </p>
          </>
        } />

        <Card title="Transfers (24h)" placeholder={
          <>
            <p>States: ready / accepted / delivered / rejected.</p>
            <p className="mt-2 text-xs text-slate-500">
              Needs <code>GET /admin/transfers</code> — queued for M4.
            </p>
          </>
        } />

        <Card title="Scanner findings" placeholder={
          <>
            <p>Malicious / Suspicious / Error aggregates.</p>
            <p className="mt-2 text-xs text-slate-500">
              Sourced from audit events once admin API ships.
            </p>
          </>
        } />

        <Card title="Policy decisions" placeholder={
          <>
            <p>Deny reasons grouped by code.</p>
            <p className="mt-2 text-xs text-slate-500">
              Audit event replay, M4.
            </p>
          </>
        } />

        <Card title="Audit chain head" placeholder={
          <>
            <p>Current SHA-256 head + last Rekor submission.</p>
            <p className="mt-2 text-xs text-slate-500">
              Exposed once the audit crate opens a read endpoint.
            </p>
          </>
        } />
      </section>

      <footer className="mt-12 text-xs text-slate-500">
        Agent Exchange Protocol (AEX) · dashboard skeleton · admin auth: pending ·
        See <code>docs/architecture.md</code> for the full picture.
      </footer>
    </main>
  );
}

function Card({
  title,
  children,
  placeholder,
}: {
  title: string;
  children?: React.ReactNode;
  placeholder?: React.ReactNode;
}) {
  return (
    <article className="rounded-xl border border-white/10 bg-white/5 p-5">
      <h2 className="text-sm font-semibold text-slate-200">{title}</h2>
      <div className="mt-3 text-sm text-slate-300">
        {children ?? (
          <div className="text-slate-400">{placeholder}</div>
        )}
      </div>
    </article>
  );
}

function DescRow({ term, detail }: { term: string; detail: string }) {
  return (
    <div className="flex justify-between">
      <dt className="text-slate-500">{term}</dt>
      <dd className="font-mono text-slate-300">{detail}</dd>
    </div>
  );
}
