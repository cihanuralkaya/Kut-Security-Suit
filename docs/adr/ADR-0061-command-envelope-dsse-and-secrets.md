# ADR-0061: Signed Command Envelope (DSSE) and Local Secure Store (COSE)

## Status
Accepted (2026-10-22, decision sprint WP-PM-025; gate G12 approved by the owner, crypto review under G3). Supersedes the v1 canonical-bytes layout of ADR-0015 for new commands after cutover.

## Context
The v1 envelope hashes a custom canonical layout. Go `encoding/json` and the float64 behaviour of protobuf `Struct` break Go and Rust parity. The signed command id differs from the id stored in the database, signatures are discarded on write, and the verifier is not called in production. Dual approval needs more than one signature on one body.

## Decision
- Command envelope v2 is DSSE (pre-authentication encoding, PAE). The `payloadType` is `application/vnd.kut.cmd.v2`.
- The payload is the deterministic `signed_body` without `key_id`. The key id travels in each DSSE signature entry, not in the payload.
- Multiple signatures use the DSSE `signatures` list: the command issuer and the approver sign the same body.
- The signed `command_id` equals the database id, and the database stores `signed_body BYTEA` and the envelope. `CommandVerifier` is bound in production wiring.
- The command plane is always on, independent of the tenant scope mode.
- The TrustStatement is DSSE too, with `payloadType` `application/vnd.kut.trust.v2`.
- The agent local store is COSE_Encrypt0 (RFC 9052) with OS key wrapping: DPAPI-NG or TPM on Windows, TPM2 or a root-owned file on Linux, Keychain on macOS. Tink is used only on the server. No custom storage format.
- Secrets are held in a secrets manager outside the repository; OpenBao (MPL-2.0, unmodified) is the candidate and its license is to be verified before use (gate G8).

## Consequences
- The rework of the wire-freeze slice (WP-CP-004) and the agent verifier (WP-EP-001) follows this ADR; nothing is frozen before acceptance.
- Test vectors for DSSE and COSE live under `contracts/testvectors/` (ADR-0044); Go and Rust runners must agree.
- Verification failure means reject plus a security event (invariant 1); there is no bypass flag.

## Alternatives
- Keep the v1 canonical bytes: rejected, parity and multi-signature.
- JWS or COSE_Sign for commands: rejected, DSSE has simple PAE and native multi-signature.
- A custom encrypted store (a project-specific format): rejected, Rust must read what Go writes.

## Source decision
D1, D2 (roadmap section 3, with the owner's DSSE detail). Reserved by D19.
