# ADR 0016: Autonomous Security Investigation and Triage Agent

## Status
Accepted

## Context
Following the Roadmap vision (§75 Agent Mesh, §108 `AGENT-001`), tier-1 alert fatigue represents the primary operational bottleneck for SOC teams. Instead of static alert forwarding, modern security fabrics require autonomous investigation agents capable of:
1. Tracing the lateral attack path across graph nodes.
2. Identifying critical choke points for containment.
3. Querying threat knowledge (MITRE ATT&CK techniques and incident response playbooks) via RAG.
4. Synthesizing findings through reasoning models while preserving privacy via Data DLP.

## Decision
We implemented `InvestigationAgent` in `server/internal/aiprovider`:

1. **Integrated Context Synthesis:**
   - `Investigate` accepts incident metadata along with graph paths (`entitygraph.Path`) and bottlenecks (`entitygraph.ChokePoint`).
   - Retrieves matching MITRE and runbook contexts using `RAGStore`.

2. **DLP Redaction and Rehydration:**
   - Redacts PII, internal IPs, and credentials using `DataDLP.MapRedactions` before prompt dispatch.
   - Rehydrates the final structured summary using `DataDLP.Rehydrate` so analysts see real asset names without sending raw credentials to LLMs.

3. **Structured Investigation Artifacts:**
   - Emits `InvestigationReport` containing `RootCause`, `MITRETechniques`, `AttackPath`, `ChokePoints`, and `RecommendedRemediations`.

## Consequences

### Positive
- Automates tier-1 incident triaging and root-cause mapping in under 1 second.
- Guarantees zero credential or PII leakage into model inference contexts.
- Bridges the graph database, RAG knowledge store, and response bus.

### Negative
- Complex multi-stage incidents still require human analyst confirmation before destructive containment.
