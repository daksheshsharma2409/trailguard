# Threat Model

_Last updated: 2026-10-26_

## Scope

This threat model covers the **runtime audit log** component of trailguard.
The static analysis scanner (RBAC coverage scan) is a developer tool with
no production attack surface and is excluded.

---

## Assets

| Asset | Sensitivity | Notes |
|-------|-------------|-------|
| Audit log entries | High | Contains PII and write history |
| HMAC signing key | Critical | Compromise allows forging entries |
| Prisma database credentials | Critical | Full DB access |
| trailguard.config.ts | Medium | Controls which routes are audited |

---

## Threat Actors

| Actor | Trust Level | Description |
|-------|-------------|-------------|
| Authenticated app user | Low–Medium | Normal end user of the consuming app |
| Privileged app user | Medium | Admin-level app user |
| Compromised application | None | Attacker with code execution in the app process |
| Malicious DB admin | None | Person with direct DB write access |
| Compromised secrets manager | None | Attacker who exfiltrated the HMAC key |

---

## Threats and Mitigations

### T1 — Tampering with audit log rows

**Threat:** A malicious DB admin modifies a row to cover their tracks.  
**Impact:** High (integrity violation, compliance failure).  
**Mitigation:** HMAC-SHA256 chain. Every row's hash is computed over its content
including `prevHash`. Modification of any row is detectable by `trailguard verify`.  
**Residual risk:** An attacker with both DB access **and** the HMAC key can recompute
hashes for a contiguous run. Defence-in-depth: store the key out-of-band and rotate it;
use signed checkpoints to lock in chain heads periodically.

### T2 — Deletion of audit log rows

**Threat:** A DB admin `DELETE`s rows to erase evidence.  
**Impact:** High.  
**Mitigation:** Sequence numbers (`seq`) are monotonically increasing. A gap in `seq`
during verify indicates deleted rows.  
**Residual risk:** Deleting a suffix of the log (the tail) is undetectable without
checkpoints. Checkpoints signed with a key outside DB scope close this window.

### T3 — Insertion of forged rows

**Threat:** An attacker inserts plausible-looking audit entries.  
**Impact:** Medium (noise, false evidence).  
**Mitigation:** Each row must chain from the previous row's hash. Insertion in the
middle breaks the chain from the insertion point onward. Insertion at the tail requires
the current HMAC key.  
**Residual risk:** Same as T1 if the key is compromised.

### T4 — HMAC key exfiltration

**Threat:** The signing key is leaked from an env var or secrets manager.  
**Impact:** Critical — all mitigations for T1–T3 are nullified.  
**Mitigation:** trailguard never logs the key. The key is read once at startup. Use a
secrets manager (Vault, AWS Secrets Manager) rather than .env in production.  
**Residual risk:** Inherent to symmetric HMAC. Consider key rotation schedules and
short-lived keys.

### T5 — Missing audit coverage (RBAC gap)

**Threat:** A developer adds a sensitive route without attaching audit middleware,
creating a silent coverage gap.  
**Impact:** Medium (compliance failure, undetected data access).  
**Mitigation:** The static scanner (T1.x–T2.x tasks) flags unaudited routes. Running
`trailguard scan` in CI enforces coverage.  
**Residual risk:** Scanner is heuristic-based; novel patterns may be missed. False
negatives possible.

### T6 — Replay of audit entries

**Threat:** An attacker replays a legitimate write event to trigger duplicate processing.  
**Impact:** Low for audit log itself (replay detected via `seq`).  
**Out of scope:** Replay of application-level requests is an application concern.

---

## Non-Threats (Out of Scope)

- Encryption at rest — responsibility of the database deployment
- Transport security — responsibility of the application's database connection
- Application-level authentication/authorisation — trailguard audits, not enforces
- Dashboard or UI — explicitly excluded per context.md

---

## Residual Risk Statement

trailguard provides **tamper-evident** logging, not **tamper-proof**. An attacker with
simultaneous access to the database **and** the HMAC key can rewrite the audit trail
without detection. Operators should treat the HMAC key with the same care as a CA
private key.
