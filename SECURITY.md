# Security Policy

trailguard is a security-related tool, so we take vulnerability reports seriously.

## Supported versions

| Version | Supported |
|---|---|
| Latest published release | ✅ |
| Older releases | ❌ |

## Reporting a vulnerability

Please **do not open a public issue** for security problems.

Use GitHub's private reporting: go to the repository's **Security** tab → **Report a vulnerability**. If that isn't available, email **your-email@example.com** (replace with your real contact).

Include:
- what the problem is and which version you used,
- steps or a minimal example to reproduce it,
- the impact you think it has.

You can expect an acknowledgement within about 7 days. We'll work with you on a fix and credit you in the release notes if you'd like.

## What counts as a vulnerability here

- A way to alter or delete audit entries without `verify` detecting it (beyond the limits listed below)
- Secrets (such as the HMAC key) being written to logs, reports, or the database
- Unsafe handling in exports or the audit router (for example CSV formula injection or an unguarded endpoint)
- A scanner bug that makes an unprotected route look protected in a way the docs say it shouldn't

## Known limits (not vulnerabilities)

These are documented design limits, described in the README and `docs/THREAT_MODEL.md`:

- The audit log is **tamper-evident, not tamper-proof**. Someone who steals both the HMAC key and database access can forge future entries. Checkpoints stored outside the database protect earlier history.
- Writes that bypass the audited client (other services, raw SQL, a database console) are not logged.
- Static analysis is heuristic and can miss dynamic routes.