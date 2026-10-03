# ADR 0011: AI Secret Broker for Credential Isolation

## Status
Accepted

## Context
In autonomous security operations and agentic workflows (Roadmap §5, §11, §108 `AI-003`), AI agents frequently need to query external threat intelligence APIs, trigger webhooks, query cloud providers, or interact with ITSM systems. Providing raw API keys, passwords, or tokens directly into the context window or tool execution environment of an LLM introduces severe security risks:
1. **Prompt Injection / Jailbreak Exfiltration:** Malicious instructions in analyzed data could compel the model to output its credentials.
2. **Memory / Conversation Leakage:** Secrets remain recorded in LLM context logs, chat histories, or telemetry traces.

## Decision
We implemented the `SecretBroker` in `server/internal/aiprovider`:

1. **Opaque Handle Model:**
   - Agents and tools reference secrets exclusively through opaque, ephemeral handles (e.g., `sec-virustotal-7a1b...`).
   - Handles enforce scope restrictions (`Scope`) and optional time-to-live (`ExpiresAt`).

2. **Scoped Runtime Injection:**
   - The method `ExecuteWithSecret` accepts an opaque handle and a caller closure.
   - The secret is passed strictly in-memory directly to the executed operation, never exposed to the agent or LLM prompt buffer.

3. **Text Scrubbing Guardrail:**
   - The broker provides `ScrubText` to inspect tool outputs and log buffers, stripping any known raw secret string and replacing it with `<SECRET:name>`.

## Consequences

### Positive
- AI agents never hold or view raw credentials in their prompt contexts.
- Prompt injection cannot directly exfiltrate credentials because the model never receives them.
- Centralized auditing and revocation of credential access per tool and per agent.

### Negative
- Direct agent-side HTTP clients cannot be used without routing through the broker's execution wrapper.
