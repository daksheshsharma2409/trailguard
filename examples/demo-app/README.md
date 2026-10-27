# Trailguard Demo Application: College Portal

A demonstration Express + Prisma + PostgreSQL college management portal protected by **Trailguard**.

## Architecture & Features

- **Express + TypeScript:** RESTful routing with layered middleware.
- **Prisma + PostgreSQL:** Data models for `User`, `Student`, `AuditLog`, and `AuditHead`.
- **JWT Authentication:** 15-minute token expiry, hashed passwords (`bcryptjs`).
- **RBAC:** Roles for `ADMIN`, `TEACHER`, `STUDENT`, and `AUDITOR`.
- **Trailguard Static Scanner:** Continuous verification of route authentication, role guards, and Prisma write safety (`trailguard scan`).
- **Trailguard Runtime Audit Log:** Tamper-evident, HMAC-chained logging for mutations to sensitive models (`Student`, `User`) with automatic PII redaction (`passwordHash`, `phone`).
- **Guarded Audit Endpoints:** `/audit/*` history, logs, and verification endpoints protected by `[authenticate, requireRole('ADMIN', 'AUDITOR')]`.

## Quick Start

### 1. Start PostgreSQL Database
```bash
docker compose up -d
```

### 2. Setup Database & Seed Initial Data
```bash
npm run demo:setup
```
This pushes the Prisma schema and runs `seed.ts` under `runWithAuditContext({ actorId: 'system:seed', actorRole: 'SYSTEM' })`.

Initial seeded credentials:
- **Admin:** `admin@college.edu` / `admin123`
- **Teacher:** `teacher@college.edu` / `teacher123`
- **Auditor:** `auditor@college.edu` / `auditor123`

### 3. Start the Server
```bash
npm run demo:start
```
The server starts on `http://localhost:3000`.

## Interactive Walkthrough

### 1. Authenticate as Teacher
```bash
curl -s -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"teacher@college.edu","password":"teacher123"}'
```
Copy the returned `token`.

### 2. Create a Student
```bash
curl -s -X POST http://localhost:3000/api/students \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"name":"David Miller","email":"david@college.edu","marks":88,"phone":"555-0301"}'
```

### 3. Update Student Marks
```bash
curl -s -X PATCH http://localhost:3000/api/students/1 \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"marks":95}'
```

### 4. Inspect Audit History (as Auditor or Admin)
Login as auditor:
```bash
curl -s -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"auditor@college.edu","password":"auditor123"}'
```
Query audit history for Student 1:
```bash
curl -s -X GET http://localhost:3000/audit/history/Student/1 \
  -H "Authorization: Bearer <AUDITOR_TOKEN>"
```
Notice:
- Full before/after/diff fields are recorded.
- Actor information (`actorId`, `actorRole`) reflects the authenticated user.
- Sensitive fields like `phone` are redacted (`[REDACTED:xxxx]`).
- Cryptographic hash links each entry to its predecessor.

## Security Verification

### Static RBAC Scan (Clean State)
```bash
npx trailguard scan examples/demo-app/src/app.ts --config examples/demo-app/trailguard.config.ts
```
Expected output: **0 findings**.

### Audit Chain Verification
```bash
npx trailguard verify --config examples/demo-app/trailguard.config.ts
```
Expected output: `✔ valid (N records)`.
