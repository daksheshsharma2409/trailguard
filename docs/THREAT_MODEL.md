# Threat Model

_Last updated: 2026-10-26_

## 1. Overview and Security Goals

`trailguard` provides **tamper-evident** audit logging and static authorization governance for Express + Prisma + MySQL backends.

The primary security goals are:
1. **Tamper Evidence:** Any unauthorized mutation, reordering, or gap in audit log records must be deterministically detectable upon verification.
2. **Static Assurance:** Direct database writes that bypass the audit client and routes lacking required authentication or authorization must be flagged in development and CI.
3. **Drift Detection:** Inconsistencies between statically declared permissions (e.g., "only ADMIN can delete users") and runtime audit events must be flagged.
4. **Secret Minimization:** PII and sensitive data must be redacted using salted/keyed one-way HMAC tags (`[REDACTED:<tag>]`) prior to persistence.

---

## 2. Threat Model Matrix

The following matrix documents the specific capabilities of potential adversaries, detection guarantees, verification mechanisms, and residual risks:

| Attacker Capability | Detected? | By What Mechanism | Residual Risk & Mitigations |
|---|---|---|---|
| **1. DB Write Only**<br>*(e.g., SQL injection, rogue application DB account modifying `trailguard_audit_log` or `trailguard_audit_head`)* | ✅ **YES** | **HMAC signature verification & forward link:** Modifying any row's columns breaks its HMAC-SHA256 signature. Modifying `payload` breaks the next row's `prevHash`. Modifying convenience columns (`before`/`after`) breaks the cross-check against canonical `payload`. | **None.** The row modification is pinpointed to the exact sequence number (`seq`). |
| **2. DB Admin**<br>*(Full database administrator access; can execute arbitrary DDL/DML, drop tables, or rewrite rows)* | ✅ **YES** | **Monotonic gapless sequence & HMAC chaining:** If a middle row is deleted, `seq` has a gap (`SEQ_GAP`). If rows are reordered, `seq` and `prevHash` mismatch. If the admin rewrites a range of rows and attempts to recompute hashes, verification fails because the admin lacks the HMAC key held outside the DB. | If the admin deletes the *entire table* or drops the database, audit history is destroyed unless external backups or checkpoints exist. |
| **3. Key Theft**<br>*(Adversary exfiltrates `TRAILGUARD_KEY` from environment variables, process memory, or secrets manager)* | ⚠️ **PARTIAL** | **External Signed Checkpoints:** Past entries that were already hashed, signed, and shipped to an external append-only sink (e.g., S3 Object Lock, external syslog, CI artifacts) **cannot be rewritten without detection**. Any attempt to alter historical entries contradicts the recorded `(seq, hash)` checkpoints. | An attacker with **both** the key and DB write access can forge future audit entries or rewrite entries produced after the most recent checkpoint. **Mitigation:** Store keys in HSM/AWS Secrets Manager, rotate keys, and emit checkpoints frequently (`checkpoint.every: 50`). |
| **4. Truncation**<br>*(Attacker deletes the last $N$ rows and rewinds `AuditHead.lastSeq` and `lastHash`)* | ✅ **YES** *(with checkpoints)* | **Checkpoint high-water mark verification:** During `trailguard verify --checkpoints <file>`, the verifier compares the highest checkpoint `seq` against the database `lastSeq`. If `dbLastSeq < checkpoint.seq`, verification aborts with `TRUNCATION_DETECTED`. | Any writes that occurred *after* the latest emitted checkpoint and were truncated before a new checkpoint was created are lost if no external copy exists. **Mitigation:** Stream checkpoints synchronously or trigger on shutdown/periodic timers. |
| **5. App-Level Bypass**<br>*(Developer or attacker in codebase uses raw Prisma client, raw SQL, or separate microservice)* | ⚠️ **PARTIAL** | **Static Scanner (`AUD001`, `AUD003`):** `trailguard scan` scans repository ASTs with `ts-morph` and flags any direct `prisma.<model>.<write>()` call on audited models or mutating raw SQL (`$executeRaw`). | Mutations executed outside the scanned codebase (e.g., raw MySQL CLI console, unmanaged microservices, legacy ETL pipelines) are not routed through `auditClient` and cannot be captured. **Mitigation:** Enforce MySQL table-level permissions granting `INSERT` only to the application user and audit raw binlogs. |
| **6. Replay**<br>*(Attacker attempts to replay an earlier legitimate audit entry or duplicate sequence number)* | ✅ **YES** | **Gapless sequence & head locking:** Audit sequences are strictly assigned under `SELECT ... FOR UPDATE` row lock on `AuditHead`. A duplicate `seq` violates the primary key constraint. Re-inserting a past entry at the head fails because its `prevHash` will not match the current `lastHash`. | Replay of application-level HTTP requests (e.g., double spend) is an application idempotency concern, though the audit log will faithfully record both events with unique `seq` and timestamps. |

---

## 3. Assets and Sensitivity

| Asset | Sensitivity | Protection Mechanism |
|---|---|---|
| **HMAC Secret Key** (`TRAILGUARD_KEY`) | **Critical** | Symmetric signing key. Never printed in CLI, logs, or error messages. Must be stored in process environment or cloud secrets manager. |
| **Database Audit Log** (`trailguard_audit_log`) | **High** | Append-only transaction log containing business diffs, actor metadata, and cryptographic hashes. |
| **Database Head Row** (`trailguard_audit_head`) | **High** | Single serialized mutex row holding current `(lastSeq, lastHash)`. Locked via `SELECT ... FOR UPDATE`. |
| **Signed Checkpoints** (`checkpoints.jsonl`) | **High** | Cryptographic commitments of `(seq, hash, ts, keyId)` shipped outside the database. |
| **Audit Context** (ALS) | **Medium** | In-memory `AsyncLocalStorage` store holding actor ID, actor role, IP, user-agent, and request ID. |
| **Configuration** (`trailguard.config.ts`) | **Medium** | Defines audited models, role extractors, and rule levels. Validated with strict Zod schema. |

---

## 4. Attacker Profiles

1. **External Unauthenticated Attacker:** Probes HTTP endpoints for missing authentication (`RBAC001`), missing role checks (`RBAC002`), or unguarded audit routers (`AUD002`). Defended by static CI gates.
2. **Malicious Insider / Rogue Employee:** Authenticated user performing actions beyond their authorized scope. Defended by `trailguard drift` cross-referencing runtime actor roles against the static RBAC matrix.
3. **Compromised Node.js App Server:** Attacker achieves remote code execution in Node.js process. They gain access to `TRAILGUARD_KEY`. Mitigated by external signed checkpoints preventing history rewrite.
4. **Malicious Database Administrator (DBA):** Attacker has root MySQL access and attempts to manipulate audit rows or drop evidence. Defended by HMAC verification, gapless sequence tracking, and checkpoint comparisons.

---

## 5. Architectural Security Controls

### 5.1 Atomicity & Concurrency Isolation
Audit rows are appended in the **same database transaction** as the underlying business write:
```
BEGIN;
  SELECT ... FROM Student WHERE id = '...';   -- Pre-image
  UPDATE Student SET ...;                     -- Mutation
  SELECT * FROM trailguard_audit_head FOR UPDATE; -- Lock head
  INSERT INTO trailguard_audit_log ...;       -- Append audit record
  UPDATE trailguard_audit_head SET ...;       -- Advance head
COMMIT;
```
If the business mutation fails, the audit record is not created. If the audit append fails, the business mutation rolls back.

### 5.2 Deterministic Canonical Payloads
MySQL JSON columns do not preserve key ordering. To prevent false integrity failures, hashing is computed strictly on canonical JSON (RFC 8785) stored in the `payload` `LongText` column.

### 5.3 Salted Redaction
Sensitive fields (e.g., passwords, credit card numbers, PII) are replaced with `[REDACTED:<tag>]` using a 4-hex-character HMAC tag. This proves that a field was changed without revealing the plaintext value, and prevents rainbow table inversion.

---

## 6. Honest Limitations & Non-Goals

1. **Tamper-Evident, Not Tamper-Proof:** No purely software-based library can prevent a root DBA with key access from deleting database files. The goal is that any modification is provably evident.
2. **Zero-Knowledge Bypasses:** Writes originating from raw database connections, separate services, or direct SQL clients that do not use `auditClient` cannot be logged.
3. **Read Logging:** Read operations (`SELECT`) are not audited in v1 due to performance and storage overhead.
4. **Throughput Scaling:** Locking `AuditHead` serializes write commits on audited models. Applications requiring tens of thousands of writes per second should partition audited models or use external log streaming.
