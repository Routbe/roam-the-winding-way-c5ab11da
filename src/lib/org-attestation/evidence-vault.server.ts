/**
 * Short-lived sealing of mandate/public-body evidence (KBO extract, Staatsblad, ...) for the
 * admin review queue (db/0300 trust_evidence_reviews). AES-256-GCM under ROUT_EVIDENCE_KEK
 * (read per call, never at module scope); the AES key is HKDF-derived from the KEK.
 *
 *   sealed = "REV1" || nonce(12) || ciphertext || tag(16)
 *   AAD    = "rout:org_evidence:v1:" || workspaceId || ":" || reviewId || 0x1f || sha256(plaintext)
 *
 * Workspace and review id (chosen by the server) are bound into the AAD with a fresh 96-bit
 * CSPRNG nonce per file, so a ciphertext moved to another workspace or dossier does not open.
 * Every failure is the same EvidenceVaultError (no oracle).
 */
import { gcm } from "@noble/ciphers/aes.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { randomBytes } from "@noble/hashes/utils.js";

const KEK_RE = /^[A-Za-z0-9]{40,512}$/; // 40+ alphanumerics ≈ 238+ bits
const MAGIC = Uint8Array.of(0x52, 0x45, 0x56, 0x31); // "REV1"
const NONCE_LEN = 12;
export const MAX_EVIDENCE_BYTES = 5 * 1024 * 1024;
export const ALLOWED_MIME = ["application/pdf", "image/png", "image/jpeg"] as const;
export type EvidenceMime = (typeof ALLOWED_MIME)[number];

export class EvidenceVaultError extends Error {
  constructor() { super("evidence_vault_error"); this.name = "EvidenceVaultError"; }
}

const enc = new TextEncoder();

function deriveKey(env: Record<string, string | undefined>): Uint8Array {
  const kek = env["ROUT_EVIDENCE_KEK"];
  if (!kek || !KEK_RE.test(kek)) throw new EvidenceVaultError();
  return hkdf(sha256, enc.encode(kek), enc.encode("rout.trust.evidence.salt.v1"), enc.encode("rout.trust.evidence.key.v1"), 32);
}

export function evidenceConfigured(env: Record<string, string | undefined> = process.env): boolean {
  const kek = env["ROUT_EVIDENCE_KEK"];
  return typeof kek === "string" && KEK_RE.test(kek);
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

function aad(workspaceId: string, reviewId: string, digest: Uint8Array): Uint8Array {
  const ws = workspaceId.toLowerCase();
  const id = reviewId.toLowerCase();
  if (!UUID_RE.test(ws) || !UUID_RE.test(id)) throw new EvidenceVaultError();
  const head = enc.encode(`rout:org_evidence:v1:${ws}:${id}\u001f`);
  const out = new Uint8Array(head.length + digest.length);
  out.set(head); out.set(digest, head.length);
  return out;
}

/** Recognises the file by its magic bytes; the declared type must match. */
export function sniffMime(bytes: Uint8Array): EvidenceMime | null {
  if (bytes.length >= 5 && bytes[0] === 0x25 && bytes[1] === 0x50 && bytes[2] === 0x44 && bytes[3] === 0x46 && bytes[4] === 0x2d) return "application/pdf";
  if (bytes.length >= 8 && bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4e && bytes[3] === 0x47 && bytes[4] === 0x0d && bytes[5] === 0x0a && bytes[6] === 0x1a && bytes[7] === 0x0a) return "image/png";
  if (bytes.length >= 3 && bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff) return "image/jpeg";
  return null;
}

export function sealEvidence(workspaceId: string, reviewId: string, plaintext: Uint8Array, env: Record<string, string | undefined> = process.env): { sealed: Uint8Array; sha256: Uint8Array } {
  if (plaintext.length < 1 || plaintext.length > MAX_EVIDENCE_BYTES) throw new EvidenceVaultError();
  const key = deriveKey(env);
  try {
    const digest = sha256(plaintext);
    const nonce = randomBytes(NONCE_LEN);
    const ct = gcm(key, nonce, aad(workspaceId, reviewId, digest)).encrypt(plaintext);
    const sealed = new Uint8Array(MAGIC.length + NONCE_LEN + ct.length);
    sealed.set(MAGIC); sealed.set(nonce, MAGIC.length); sealed.set(ct, MAGIC.length + NONCE_LEN);
    return { sealed, sha256: digest };
  } finally {
    key.fill(0);
  }
}

export function openEvidence(workspaceId: string, reviewId: string, sealed: Uint8Array, expectedSha256: Uint8Array, env: Record<string, string | undefined> = process.env): Uint8Array {
  if (sealed.length < MAGIC.length + NONCE_LEN + 17) throw new EvidenceVaultError();
  for (let i = 0; i < MAGIC.length; i++) if (sealed[i] !== MAGIC[i]) throw new EvidenceVaultError();
  const key = deriveKey(env);
  try {
    const nonce = sealed.subarray(MAGIC.length, MAGIC.length + NONCE_LEN);
    const pt = gcm(key, nonce, aad(workspaceId, reviewId, expectedSha256)).decrypt(sealed.subarray(MAGIC.length + NONCE_LEN));
    const d = sha256(pt);
    let diff = d.length ^ expectedSha256.length;
    for (let i = 0; i < d.length; i++) diff |= d[i]! ^ (expectedSha256[i] ?? 0);
    if (diff !== 0) { pt.fill(0); throw new EvidenceVaultError(); }
    return pt;
  } catch {
    throw new EvidenceVaultError();
  } finally {
    key.fill(0);
  }
}
