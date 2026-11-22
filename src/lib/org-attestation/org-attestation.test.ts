import { describe, expect, it } from "vitest";
import { belgianCheck, emailOnDomain, expectedProof, normalizeDomain, normalizeLei, normalizeVat, organisationNullifier, unquoteTxt } from "./proofs";
import { interpretDoh, interpretWellKnown } from "./dns-verifier.server";
import { EvidenceVaultError, openEvidence, sealEvidence, sniffMime } from "./evidence-vault.server";
import { checkVat, checkLei } from "./vies-gleif.server";

const WS = "11111111-2222-4333-8444-555555555555";
const NONCE = "0123456789abcdef0123456789abcdef";
const PEPPER = "p".repeat(40);
const KEK = { ROUT_EVIDENCE_KEK: "A".repeat(64) };
const pdf = () => new TextEncoder().encode("%PDF-1.7 test document");

describe("layer 1 proofs", () => {
  it("expects the TXT value <workspace_id>:<nonce> at _rout.<domain>", () => {
    expect(expectedProof(WS, NONCE)).toBe(`${WS}:${NONCE}`);
    expect(normalizeDomain(" Example.BE. ")).toBe("example.be");
    expect(normalizeDomain("not a domain")).toBeNull();
    expect(unquoteTxt('"abc" "def"')).toBe("abcdef");
  });
  it("accepts a DNS answer only when DNSSEC-validated (AD flag)", () => {
    const answer = { Status: 0, Answer: [{ type: 16, data: `"${WS}:${NONCE}"` }] };
    expect(interpretDoh({ ...answer, AD: true }, expectedProof(WS, NONCE)).status).toBe("present");
    expect(interpretDoh({ ...answer, AD: false }, expectedProof(WS, NONCE))).toEqual({ status: "absent", reason: "dnssec_required" });
  });
  it("never reports a resolver failure as an absent record", () => {
    expect(interpretDoh({ Status: 2 }, "x").status).toBe("error");
    expect(interpretDoh({ Status: 3 }, "x").status).toBe("absent");
  });
  it("reads the well-known proof", () => {
    expect(interpretWellKnown(JSON.stringify({ rout: `${WS}:${NONCE}` }), expectedProof(WS, NONCE)).status).toBe("present");
    expect(interpretWellKnown(JSON.stringify({ rout: `${WS}:ffff` }), expectedProof(WS, NONCE)).status).toBe("absent");
  });
  it("accepts a work e-mail only on exactly the workspace domain", () => {
    expect(emailOnDomain("Jan@Example.be", "example.be")).toBe("jan@example.be");
    expect(emailOnDomain("jan@mail.example.be", "example.be")).toBeNull();
  });
});

describe("layer 2 registers", () => {
  it("validates Belgian enterprise numbers with the mod-97 check", () => {
    expect(belgianCheck("0403170701")).toBe(true);
    expect(normalizeVat("BE 0403.170.701")).toEqual({ country: "BE", number: "0403170701" });
    expect(normalizeVat("BE0403170702")).toBeNull();
  });
  it("validates LEI checksums", () => {
    expect(normalizeLei("5493001KJTIIGC8Y1R12")).toBe("5493001KJTIIGC8Y1R12");
    expect(normalizeLei("5493001KJTIIGC8Y1R13")).toBeNull();
  });
  it("derives a 32-byte keyed nullifier that differs per pepper and never contains the number", () => {
    const a = organisationNullifier("vat_vies", "BE0403170701", PEPPER);
    expect(a).toHaveLength(32);
    expect(Buffer.from(a).toString("hex")).not.toEqual(Buffer.from(organisationNullifier("vat_vies", "BE0403170701", "q".repeat(40))).toString("hex"));
    expect(() => organisationNullifier("vat_vies", "BE0403170701", "short")).toThrow();
  });
  it("returns the VIES outcome without the register number", async () => {
    const fake = (async () => new Response(JSON.stringify({ isValid: true, name: "NV TEST", requestDate: "2026-11-22" }))) as typeof fetch;
    const r = await checkVat("BE0403170701", PEPPER, fake);
    expect(r.ok && r.country).toBe("BE");
    expect(JSON.stringify(r)).not.toContain("0403170701");
  });
  it("treats an unreachable register as unavailable, not as not-found", async () => {
    const down = (async () => new Response("", { status: 503 })) as typeof fetch;
    expect(await checkLei("5493001KJTIIGC8Y1R12", PEPPER, down)).toEqual({ ok: false, reason: "register_unavailable" });
  });
});

describe("evidence vault", () => {
  it("round-trips under the same review id", () => {
    const { sealed, sha256 } = sealEvidence(WS, pdf(), KEK);
    expect(new TextDecoder().decode(openEvidence(WS, sealed, sha256, KEK))).toBe("%PDF-1.7 test document");
  });
  it("refuses a ciphertext moved to another review", () => {
    const { sealed, sha256 } = sealEvidence(WS, pdf(), KEK);
    expect(() => openEvidence("99999999-2222-4333-8444-555555555555", sealed, sha256, KEK)).toThrow(EvidenceVaultError);
  });
  it("refuses to seal without a valid ROUT_EVIDENCE_KEK", () => {
    expect(() => sealEvidence(WS, pdf(), {})).toThrow(EvidenceVaultError);
    expect(() => sealEvidence(WS, pdf(), { ROUT_EVIDENCE_KEK: "short" })).toThrow(EvidenceVaultError);
  });
  it("rejects files over 5 MB", () => {
    expect(() => sealEvidence(WS, new Uint8Array(5 * 1024 * 1024 + 1), KEK)).toThrow(EvidenceVaultError);
  });
  it("recognises the file type from its contents", () => {
    expect(sniffMime(pdf())).toBe("application/pdf");
    expect(sniffMime(new TextEncoder().encode("hello"))).toBeNull();
  });
});
