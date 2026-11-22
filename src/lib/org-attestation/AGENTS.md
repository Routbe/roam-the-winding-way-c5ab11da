## Organisation assurance (db/0300)
- Every trust write goes through the rout_trust_* / rout_admin_trust_* SECURITY DEFINER functions in the caller's db context; the database decides manager and 2FA-admin rights. Why: route gates only hide UI.
- Register numbers, work e-mails and codes reach Neon only as keyed BLAKE3/HMAC values under the identity pepper; review documents only as REV1 AES-256-GCM under ROUT_EVIDENCE_KEK, bound to the review id. Why: no plaintext identifiers or documents in the database.
- DNS proofs count only with a DNSSEC-validated (AD) answer, and a lookup error is never reported as an absent record. Why: a resolver outage must not lapse a seal.
