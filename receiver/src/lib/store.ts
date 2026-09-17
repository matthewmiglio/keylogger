import { put, list } from "@vercel/blob";

export type BatchInfo = {
  pathname: string;
  uploadedAt: Date;
  size: number;
};

const hasBlob = () => Boolean(process.env.BLOB_READ_WRITE_TOKEN);

// Local-dev fallback when no Blob token is configured: keep batches in
// memory. Keyed on globalThis so /api/sync and /api/logs (separate route
// bundles in dev) share one map; survives only within the dev process.
// Stores the encrypted envelope — plaintext is only produced on demand by
// the viewer route.
type MemoryBatch = { uploadedAt: Date; text: string };
const globalStore = globalThis as typeof globalThis & {
  __wsBatches?: Map<string, MemoryBatch>;
};
const memoryBatches: Map<string, MemoryBatch> =
  (globalStore.__wsBatches ??= new Map());

export function batchPathname(deviceId: string, ts: number): string {
  const rand = Math.random().toString(36).slice(2, 10);
  return `batches/${ts}-${deviceId}-${rand}.txt`;
}

// `envelope` is the JSON wire representation (nonce/ciphertext/tag/device id).
export async function saveBatch(
  deviceId: string,
  ts: number,
  envelope: string
): Promise<void> {
  const pathname = batchPathname(deviceId, ts);
  if (!hasBlob()) {
    memoryBatches.set(pathname, { uploadedAt: new Date(), text: envelope });
    return;
  }
  await put(pathname, envelope, {
    contentType: "text/plain",
    addRandomSuffix: false,
    access: "public", // unguessable URL; content is ciphertext at rest anyway
  });
}

export async function listBatches(limit = 200): Promise<BatchInfo[]> {
  if (!hasBlob()) {
    return [...memoryBatches.entries()]
      .map(([pathname, v]) => ({
        pathname,
        uploadedAt: v.uploadedAt,
        size: v.text.length,
      }))
      .sort((a, b) => b.uploadedAt.getTime() - a.uploadedAt.getTime())
      .slice(0, limit);
  }
  const { blobs } = await list({ prefix: "batches/", limit });
  return blobs
    .map((b) => ({ pathname: b.pathname, uploadedAt: b.uploadedAt, size: b.size }))
    .sort((a, b) => b.uploadedAt.getTime() - a.uploadedAt.getTime())
    .slice(0, limit);
}

// Returns the stored envelope JSON for one batch.
export async function readBatch(pathname: string): Promise<string> {
  if (!hasBlob()) {
    const b = memoryBatches.get(pathname);
    if (!b) throw new Error("not found");
    return b.text;
  }
  const { blobs } = await list({ prefix: pathname, limit: 1 });
  const blob = blobs.find((b) => b.pathname === pathname);
  if (!blob) throw new Error("not found");
  const res = await fetch(blob.url, { cache: "no-store" });
  if (!res.ok) throw new Error(`blob read ${res.status}`);
  return res.text();
}
