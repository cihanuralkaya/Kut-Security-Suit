# ADR 0020: Security Data Classification and Sensitivity Guardrails

## Status
Accepted

## Context
When processing telemetry, prompts, and incident investigation data through AI models, transmitting sensitive data (credentials, sovereign IPs, PII) to external cloud AI providers violates data sovereignty, KVKK, and GDPR (Roadmap §6, §108 `AI-004`). The system requires automated classification of all data entering the AI plane.

## Decision
We implemented `DataClassifier` in `server/internal/aiprovider`:

1. **Four-Tier Sensitivity Hierarchy:**
   - `Restricted`: Credentials, private keys, AWS tokens, SSN, TCKN, sovereign RFC1918 internal IPs.
   - `Confidential`: Incident details, internal domain hostnames (`*.internal`), user emails.
   - `Internal`: System metrics, error logs, general telemetry metadata.
   - `Public`: Known CVEs, public MITRE ATT&CK techniques, general documentation.

2. **Integration with ModelRouter:**
   - If classified as `Restricted`, `ModelRouter` enforces local-only inference (Ollama / vLLM / llama.cpp) and strictly forbids routing to cloud LLMs.

## Consequences

### Positive
- Automated governance preventing confidential data from leaving the organization.
- Integrates seamlessly with `DataDLP` for redaction and `ModelRouter` for sovereign routing.

### Negative
- False-positive classification of test credentials or documentation IPs may unnecessarily constrain routing to local models.
