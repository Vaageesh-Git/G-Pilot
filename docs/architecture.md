# Architecture

```mermaid
flowchart LR
  Client["React Dashboard"] --> API["FastAPI API"]
  API --> Runner["Pipeline Runner"]
  Runner --> Graph["LangGraph StateGraph"]
  Graph --> A["Agent A: Offensive Security"]
  A --> B["Agent B: Remediation"]
  B --> C["Agent C: Validation"]
  C -->|fixed| GH["GitHub PR"]
  C -->|not fixed and retries left| B
  A --> Chroma["ChromaDB: vulnerabilities / exploits / fixes"]
  B --> Chroma
  C --> Chroma
  A --> Docker["Docker Sandbox"]
  B --> Docker
  C --> Docker
```

## Shared State

```json
{
  "vulnerabilities": [],
  "fixes": [],
  "validation_status": "pending",
  "retry_count": 0
}
```

The graph is cyclic:

`START -> Agent A -> Agent B -> Agent C -> END`

If Agent C rejects the fix and `retry_count < max_retry_count`, control loops back to Agent B with structured feedback.
