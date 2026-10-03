# ADR 0013: Attack Path Engine and Choke Point Identification

## Status
Accepted

## Context
Traditional EDR and SIEM tools present security incidents as isolated events or static alert lists. Modern enterprise security platforms (Roadmap §24, §108 `XDR-006`) require graph-based attack path modeling to:
1. Discover multi-hop lateral movement from an initial entry point to crown jewel assets.
2. Quantify path risk based on edge rarity and hop count.
3. Pinpoint critical choke points (nodes where multiple attack paths converge) for high-leverage automated containment.

## Decision
We implemented the Attack Path Engine in `server/internal/entitygraph`:

1. **Cycle-Safe Directed Path Finding:**
   - `FindPaths(source, target Node, maxHops int) []Path` executes a depth-first traversal with a visited set to uncover all possible lateral paths within an operator-specified hop limit.

2. **Rarity-Based Anomaly Scoring:**
   - `ScorePath(p Path) float64` evaluates the frequency of relationship observations. Unprecedented or rarely observed connections (count <= 3) significantly increase the path risk score. Shorter hop paths to high-value targets are prioritized.

3. **Critical Choke Point Analysis:**
   - `IdentifyChokePoints(paths []Path, excludeStart, excludeTarget Node) []ChokePoint` counts the frequency of intermediate nodes across distinct paths. Containing or quarantining the top choke point disrupts the highest volume of attack avenues.

## Consequences

### Positive
- Enables SOC analysts and autonomous response agents to understand lateral movement topology.
- Allows SOAR and Command Plane to execute targeted surgical containment at choke points rather than blunt fleet-wide isolations.
- Deterministic, zero-dependency in-memory graph analysis.

### Negative
- Very dense or cyclic graphs with large hop limits (`maxHops > 10`) could encounter exponential path growth; guarded by hop limits.
