# Agent improvement baseline

The optimization cycle follows the requested agent-improvement workflow: establish a baseline, classify failure modes, apply measurable changes, and require regression evidence.

| Metric | v0.1 baseline | v0.2 target |
| --- | ---: | ---: |
| MCP tools | 2 | 6 |
| Diagnostic rule families | 3 | 15 |
| Synthetic evaluation cases | 0 | 16 |
| Synthetic success rate | unmeasured | 100% |
| PC control catalog | absent | 38 controls / 12 domains |
| Supported platforms | implicit | Windows, Linux, macOS |
| Catalog design coverage | 0% | 100% on each supported platform |
| Collection consent gate | absent | required |
| Output redaction | absent | tested for common sensitive formats |

The runtime observation score is intentionally not filled with synthetic data. It only exists after an end user explicitly runs selected probes on their own machine; those results must never be committed to this public repository.
