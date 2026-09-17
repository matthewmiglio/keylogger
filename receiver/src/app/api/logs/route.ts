import { NextResponse } from "next/server";
import { listBatches, readBatch } from "@/lib/store";
import { decryptEnvelope, type Envelope } from "@/lib/crypto";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// Token comes from the Authorization header (Bearer <LOGS_TOKEN>) — never a
// query string, so it stays out of access logs and browser history.
function authorized(req: Request): boolean {
  const expected = process.env.LOGS_TOKEN;
  if (!expected) return false;
  const header = req.headers.get("authorization") ?? "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  return token.length > 0 && token === expected;
}

export async function GET(req: Request): Promise<NextResponse> {
  if (!process.env.LOGS_TOKEN) return NextResponse.json({ ok: false }, { status: 500 });
  if (!authorized(req)) return NextResponse.json({ ok: false }, { status: 401 });

  const url = new URL(req.url);
  const pathname = url.searchParams.get("pathname");
  if (pathname) {
    try {
      const envelope = JSON.parse(await readBatch(pathname)) as Envelope;
      const text = decryptEnvelope(envelope); // on-demand decrypt for viewing
      return NextResponse.json({ ok: true, text });
    } catch {
      return NextResponse.json({ ok: false }, { status: 404 });
    }
  }

  const batches = await listBatches(200);
  return NextResponse.json({ ok: true, batches });
}
