# Security Model

Vuln-Swarm assumes scans target repositories you own or are authorized to assess.

## Exploit Execution

Agent A creates sandbox probes from known vulnerability classes and runs them in Docker. The default sandbox:

- mounts the target repository read-only
- disables networking
- enforces CPU and memory limits
- applies `no-new-privileges`
- never mounts the host Docker socket into child containers

## LLM Cost Controls

- RAG retrieval is local ChromaDB plus local sentence-transformer embeddings.
- Agent A uses deterministic scanners before any LLM call.
- Agent B uses deterministic AST-aware patchers first.
- Gemini patch planning is batched into a single structured JSON call for unresolved findings.
- Status and report reads never call the LLM.

## GitHub Automation

PR creation requires `GITHUB_TOKEN` and `create_pr=true`. If validation passes but PR automation fails, the validation report is marked `needs_human` with the GitHub error.

## Secret Findings

Secret values are redacted in reports. If a secret is detected, the fix report sets `history_purge_required=true`; rotation and history rewrite are still required even if current source code is patched.
