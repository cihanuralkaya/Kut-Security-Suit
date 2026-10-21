# ADR-0063: Object Storage Behind an S3 API

## Status
Accepted (2026-10-22, decision sprint WP-PM-025; gate G12 approved by the owner)

## Context
Evidence, support bundles and lake data need object storage with retention locking. The best-known open server, MinIO, is AGPL.

## Decision
- Storage code talks to an S3-compatible API abstraction. The MinIO client library may be used; the MinIO server is not bundled (ADR-0053).
- The bundled store, if any, is chosen in a separate ADR (SeaweedFS is a candidate; its license must be verified first, gate G8).
- Evidence buckets use Object Lock (WORM) where the backend supports it.

## Consequences
- Customers can bring their own S3-compatible storage.
- Backends need a conformance test for the features used (Object Lock, versioning).
- Air-gap installs need a bundled option, decided in the follow-up ADR.

## Alternatives
- Bundle MinIO: rejected, AGPL.
- Filesystem only: rejected, no WORM and no scale-out.

## Source decision
D17 (roadmap section 3). Reserved by D19.
