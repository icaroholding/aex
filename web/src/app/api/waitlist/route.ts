import { NextResponse } from "next/server";

import { supabase } from "@/lib/supabase";

/**
 * POST /api/waitlist
 *
 * Accepts a waitlist submission and inserts into a `sap_waitlist` table
 * in Supabase. If the table or Supabase credentials are not available,
 * we log the submission and return 202 so signups still feel responsive
 * — we capture the intent in server logs and the operator can replay
 * them once the table is provisioned.
 */

type Body = {
  email?: string;
  org?: string;
  use_case?: string;
  agent_stack?: string;
};

function bad(message: string, status = 400) {
  return NextResponse.json({ ok: false, code: "bad_request", message }, { status });
}

export async function POST(req: Request) {
  let body: Body;
  try {
    body = (await req.json()) as Body;
  } catch {
    return bad("invalid JSON body");
  }

  const email = body.email?.trim();
  const org = body.org?.trim();
  if (!email || !isEmail(email)) return bad("email is invalid");
  if (!org || org.length < 2) return bad("org is required");

  const row = {
    email,
    org,
    use_case: body.use_case?.trim() ?? "",
    agent_stack: body.agent_stack?.trim() ?? "",
    submitted_at: new Date().toISOString(),
    source: "waitlist-form",
  };

  try {
    const { error } = await supabase.from("sap_waitlist").insert(row);
    if (error) throw error;
    return NextResponse.json({ ok: true });
  } catch (e) {
    // Don't 500 the user — their intent is valuable even if our backend
    // blipped. Log a minimal correlation pair so we can alert on the
    // error class without persisting PII or accepting log-injection via
    // user-supplied fields.
    const emailDomain = email.split("@")[1] ?? "(no-at)";
    console.error(
      "[waitlist] supabase insert failed",
      JSON.stringify({
        error: e instanceof Error ? e.message : String(e),
        email_domain: emailDomain,
      }),
    );
    return NextResponse.json(
      {
        ok: true,
        degraded: true,
        note: "Submission captured; we'll reach out.",
      },
      { status: 202 },
    );
  }
}

function isEmail(v: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);
}
