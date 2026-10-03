# ADR 0005: Database-Level Immutability for Evidence and Audit Logs

## Status
Accepted

## Context
In the KUT Security Suit, the `evidence_custody` and `audit_log` tables store sensitive security event information and digital forensics custody logs. While the application logic enforces an append-only behavior, there was no database-level enforcement. An attacker who gains database access could modify or delete these critical records, compromising the integrity of the system and forging custody trails.

## Decision
We decided to implement PostgreSQL triggers on both `evidence_custody` and `audit_log` tables to enforce append-only behavior directly at the database level.

- Created `prevent_custody_mutation` trigger function and attached it to `BEFORE UPDATE` and `BEFORE DELETE` events on `evidence_custody`.
- Created `prevent_audit_log_mutation` trigger function and attached it to `BEFORE UPDATE` and `BEFORE DELETE` events on `audit_log`.
- Documented maintenance override mechanisms using `ALTER TABLE ... DISABLE TRIGGER ALL`.

## Consequences
- **Positive:** Increased defense-in-depth against data tampering. Even if application layer vulnerabilities are exploited to gain SQL injection, or direct DB credentials are compromised, evidence and audit logs cannot be easily altered or deleted.
- **Negative:** Routine database maintenance or purging of old records (if ever authorized) will require elevated privileges and manual disabling of triggers.
