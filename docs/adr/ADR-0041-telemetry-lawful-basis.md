# ADR-0041: Lawful Basis for Endpoint Telemetry

## Status
Accepted (2026-10-22, decision sprint WP-PM-025; gate G12 approved by the owner, counsel review under G9)

## Context
Endpoint telemetry (process, file, network and user events) is personal data of employees. Consent is a weak basis in an employment relationship (EDPB Guidelines 05/2020, the KVKK explicit-consent guide) and can be withdrawn, which would switch security monitoring off. The pilot needs a basis that holds up before the first customer.

## Decision
- Telemetry rests on legitimate interest, not consent: KVKK art. 5/2(f), with art. 5/2(ç) and art. 12 for the security measures themselves; GDPR art. 6(1)(f), 13, 35 and 88 where it applies.
- A notice (KVKK art. 10, GDPR art. 13) is delivered to data subjects and a DPIA plus a legitimate-interest assessment (LIA) are written and kept current.
- Consent is used only for BYOD devices and optional features (for example screenshot capture, content collection beyond security telemetry).
- The pilot gate (G14) requires a counsel-approved DPIA and this ADR accepted (G9).

## Consequences
- Telemetry minimisation, a data catalogue and per-field retention are required (WP-SEC-040..045).
- BYOD enrollment needs a separate opt-in flow and a way to withdraw.
- Customers get a DPA template and a notice template; the product does not ship a consent banner for core telemetry.

## Alternatives
- Consent for everything: rejected, not freely given at work and revocable.
- Contract necessity: rejected, does not cover monitoring of employees.
- Legal obligation only: rejected, covers some logging duties but not all telemetry.

## Source decision
D26 (roadmap section 3). Reserved by D19.
