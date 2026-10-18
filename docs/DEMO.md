# Trailguard End-to-End Demo Script

This document provides a complete human walkthrough of the Trailguard end-to-end security demo. It demonstrates both sides of Trailguard:

1. **Static Analysis Gate (`trailguard scan`)**: Detecting missing authentication, unprotected destructive endpoints, and un-audited database writes before deployment.
2. **Runtime HMAC Audit Log (`trailguard verify`)**: Proving that data modifications are captured with actor attribution, field-level redaction, gapless HMAC chaining, and tamper/truncation detection.

---

## 0. Prerequisites & Setup

Ensure the MySQL database container is running and initialize the demo database schema:

```bash
# Start MySQL in Docker (if not already running)
docker compose up -d

# Build Trailguard
npm run build

# Seed the demo application database
npm run demo:setup
```

Expected output:
```text
✔ Generated Prisma Client
Applying migration / schema push...
✔ Database synchronized
Seeding college database...
✔ Seed completed: 4 users (admin, teacher, student, auditor) and 2 initial students created.
```

---

## Step 1: Break the Demo App (`demo:break`)

Simulate a developer introducing security vulnerabilities into the application by applying `vulnerable.patch`:

```bash
npm run demo:break
```

This patch deliberately introduces **three HIGH-risk security flaws**:
1. `DELETE /api/students/:id` loses `requireRole('ADMIN', 'TEACHER')` (Unprotected privileged endpoint → `RBAC002`).
2. `PATCH /api/users/:id/role` loses `authenticate` (Unauthenticated role escalation → `RBAC001`).
3. `POST /api/students/bulk-reset` executes raw SQL write using un-audited `prisma.student.updateMany()` instead of `auditClient` (Audit bypass → `AUD001`).

Now run the static scanner:

```bash
node bin/trailguard.js scan --config examples/demo-app/trailguard.config.ts
```

### Expected Output
The command exits with code **1** and displays a formatted table with exactly 3 HIGH findings:

```text
TRAILGUARD SCAN REPORT
----------------------------------------------------------------------------------------------------
Rule     Risk  Route / Location              Message
----------------------------------------------------------------------------------------------------
AUD001   high  /api/students/bulk-reset      Audited model Student modified via un-audited client
RBAC001  high  /api/users/:id/role           Route modifies User.role without authentication
RBAC002  high  /api/students/:id             DELETE on Student lacks role restriction
----------------------------------------------------------------------------------------------------
Total findings: 3 (high: 3, medium: 0, low: 0, info: 0)
Exit code: 1 (Threshold: high)
```

CI will automatically block PRs and deployments when `trailguard scan` or `trailguard ci` fails.

---

## Step 2: Fix the Demo App (`demo:fix`)

Reverse the vulnerable changes to restore proper authentication, authorization, and audited writes:

```bash
npm run demo:fix
```

Re-run the scanner:

```bash
node bin/trailguard.js scan --config examples/demo-app/trailguard.config.ts
```

### Expected Output
The scan exits with code **0**:

```text
TRAILGUARD SCAN REPORT
----------------------------------------------------------------------------------------------------
Rule     Risk  Route / Location              Message
----------------------------------------------------------------------------------------------------
No security or audit coverage findings detected.
----------------------------------------------------------------------------------------------------
Total findings: 0
Exit code: 0
```

---

## Step 3: Run the App & Perform Audited Mutations

Start the demo server:

```bash
npm run demo:start
```

Open a second terminal window to perform business operations via HTTP:

### 3.1 Authenticate as a Teacher
```bash
TEACHER_TOKEN=$(curl -s -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"teacher@college.edu","password":"teacher123"}' | jq -r .token)
```

### 3.2 Create a New Student (Audited Write with Sensitive Field)
```bash
curl -s -X POST http://localhost:3000/api/students \
  -H "Authorization: Bearer $TEACHER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"Eva Green","email":"eva@college.edu","phone":"555-8888","marks":82}' | jq .
```

### 3.3 Update Student Marks
```bash
STUDENT_ID=$(curl -s http://localhost:3000/api/students \
  -H "Authorization: Bearer $TEACHER_TOKEN" | jq -r '.[0].id')

curl -s -X PATCH http://localhost:3000/api/students/$STUDENT_ID \
  -H "Authorization: Bearer $TEACHER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"marks":96}' | jq .
```

### 3.4 Inspect the Audit Trail as an Auditor
```bash
AUDITOR_TOKEN=$(curl -s -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"auditor@college.edu","password":"auditor123"}' | jq -r .token)

curl -s http://localhost:3000/audit/history/Student/$STUDENT_ID \
  -H "Authorization: Bearer $AUDITOR_TOKEN" | jq .
```

### Expected Output
The audit log returns the full history with actor attribution, diffs, and redacted sensitive fields:
```json
{
  "history": [
    {
      "seq": "1",
      "action": "CREATE",
      "actorId": "cly...",
      "actorRole": "TEACHER",
      "before": null,
      "after": {
        "name": "Eva Green",
        "email": "eva@college.edu",
        "phone": "[REDACTED:e4b7]",
        "marks": 82
      },
      "diff": null
    },
    {
      "seq": "2",
      "action": "UPDATE",
      "actorId": "cly...",
      "actorRole": "TEACHER",
      "before": { "marks": 82 },
      "after": { "marks": 96 },
      "diff": { "marks": { "old": 82, "new": 96 } }
    }
  ]
}
```
Notice:
- `actorId` and `actorRole` were injected transparently via `AsyncLocalStorage`.
- `phone` was redacted to `[REDACTED:xxxx]` using deterministic HMAC hashing.
- Diffs accurately record old vs. new values.

---

## Step 4: Cryptographic Verification (Clean State)

Verify the integrity of the audit log in the database:

```bash
node bin/trailguard.js verify --config examples/demo-app/trailguard.config.ts
```

### Expected Output
```text
✔ Audit chain valid (4 records verified)
Exit code: 0
```

Trailguard verifies:
1. `prevHash` chaining starts from Genesis (`0000...`) and links every record to the previous one.
2. The HMAC of canonical payload JSON matches the stored `hash` on every row using the server's secret key.
3. The latest record matches the locked `trailguard_audit_head` table (`lastSeq` and `lastHash`).
4. `seq` numbers are gapless and sequential (1, 2, 3, ...).

---

## Step 5: Direct Database Tampering Attack

Simulate an attacker who obtains database write access (e.g. SQL injection or rogue DBA) and alters a past record to modify marks:

```bash
mysql -h 127.0.0.1 -P 3307 -u root -proot trailguard_test -e \
  "UPDATE trailguard_audit_log SET payload = '{\"tampered\":true}' WHERE seq = 2;"
```

Now re-run verification:

```bash
node bin/trailguard.js verify --config examples/demo-app/trailguard.config.ts
```

### Expected Output
The command exits with code **1**:

```text
✖ Audit chain broken at seq 2: HASH_MISMATCH
  Stored hash does not match HMAC of payload content.
Exit code: 1
```

The payload tamper is instantly detected because the attacker cannot forge a valid HMAC hash without the secret key `TRAILGUARD_KEY`.

---

## Step 6: Smart Attacker Rehash Attack (Chain Forgery)

A sophisticated attacker might tamper with a row and then rewrite the entire hash chain forward using plain SHA-256 or a guessed key, updating `AuditHead` to match:

```bash
# Attacker runs the rehash exploit script
npx tsx scripts/attacker/rehash-chain.ts
```

Output:
```text
Rehashed 4 audit rows using plain SHA-256. AuditHead updated to seq 4.
```

Now run Trailguard verification:

```bash
node bin/trailguard.js verify --config examples/demo-app/trailguard.config.ts
```

### Expected Output
The command exits with code **1**:

```text
✖ Audit chain broken at seq 1: HASH_MISMATCH
Exit code: 1
```

Even though the chain is internally consistent and `AuditHead` matches the last row, verification fails immediately because the hashes are not keyed with the genuine `TRAILGUARD_KEY` HMAC secret.

---

## Step 7: Truncation Attack & Off-Site Checkpoints

Reset the database cleanly:

```bash
npm run demo:setup
```

Create an off-site checkpoint file representing a signed head state sent to cold storage or external log collector:

```bash
npx tsx -e "
import { PrismaClient } from './test/integration/generated/index.js';
import { createCheckpoint, fileSink } from './src/runtime/checkpoint.js';
const prisma = new PrismaClient({ datasources: { db: { url: process.env.TEST_DATABASE_URL || 'mysql://root:root@localhost:3307/trailguard_test' } } });
const cp = createCheckpoint({ seq: head.lastSeq, hash: head.lastHash }, process.env.TRAILGUARD_KEY || 'demo-trailguard-master-key-32chars!!', 'k1');
await fileSink('demo-checkpoints.jsonl')(cp);
console.log('Checkpoint saved to demo-checkpoints.jsonl for seq', head.lastSeq.toString());
await prisma.$disconnect();
"
```

Simulate an attacker deleting recent rows to hide an unauthorized action:

```bash
npx tsx scripts/attacker/truncate-tail.ts
```

Output:
```text
Truncated tail: deleted rows with seq > 3. Reset AuditHead to seq 3.
```

If verified without checkpoints, the database alone appears internally consistent:

```bash
node bin/trailguard.js verify --config examples/demo-app/trailguard.config.ts
# Output: ✔ Audit chain valid (3 records verified)
```

However, when verified against the off-site checkpoint file:

```bash
node bin/trailguard.js verify --config examples/demo-app/trailguard.config.ts --checkpoints demo-checkpoints.jsonl
```

### Expected Output
The command exits with code **1**:

```text
✖ Audit chain broken: TRUNCATION_DETECTED
  External checkpoint recorded head at seq 4, but current database head is at seq 3.
Exit code: 1
```

The truncation attack is proven and exposed.

---

## Step 8: Runtime Drift Detection (`trailguard drift`)

Static analysis alone proves what routes *declare*. But what if an insider or compromised background service bypasses the HTTP layer (e.g., through an administrative script, direct DB transaction, or privilege escalation) and performs an action contrary to the declared access matrix?

Reset the database cleanly:

```bash
npm run demo:setup
```

Simulate an unauthorized runtime action where a `TEACHER` deletes a `User` record:

```bash
npx tsx scripts/attacker/seed-drift.ts
```

Output:
```text
Seeded drift entry: TEACHER deleted User (seq appended to audit log).
```

Even though the audit log entry is cryptographically authentic and properly chained, `trailguard drift` reconciles runtime audit behavior against the statically declared access matrix:

```bash
node bin/trailguard.js drift --config examples/demo-app/trailguard.config.ts
```

### Expected Output
The command exits with code **1** and highlights the unauthorized permission drift:

```text
TRAILGUARD DRIFT REPORT
----------------------------------------------------------------------------------------------------
Rule      Risk  Role     Resource  Action  Message
----------------------------------------------------------------------------------------------------
DRIFT001  high  TEACHER  User      DELETE  Role TEACHER performed DELETE on User (unauthorized by static matrix)
----------------------------------------------------------------------------------------------------
Total audited rows evaluated: 5
Discovered drift violations: 1
Exit code: 1
```

The runtime drift is exposed and flagged.

---

## Summary: Defense-in-Depth

| Threat | Prevented / Detected By | Mechanism |
|---|---|---|
| Accidental auth omission | Static Scanner (`trailguard scan`) | AST analysis flags unauthenticated routes |
| Missing role check on delete | Static Scanner (`trailguard scan`) | AST analysis flags routes lacking role checks |
| Bypass via raw Prisma client | Static Scanner (`trailguard scan`) | AST analysis flags non-audited write calls |
| Direct row payload alteration | Runtime Verifier (`trailguard verify`) | HMAC-SHA256 signature verification |
| Rewriting hash chain forward | Runtime Verifier (`trailguard verify`) | Attacker lacks application HMAC key |
| Deleting trailing audit rows | Checkpoint Verifier (`--checkpoints`) | Monotonically increasing external checkpoint state |
| Runtime privilege drift / unauthorized action | Drift Engine (`trailguard drift`) | Reconciles runtime audit logs against static access matrix |
