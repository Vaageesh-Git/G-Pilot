# API Examples

Start a GitHub scan:

```bash
curl -X POST http://localhost:8000/scan-repo \
  -H "Content-Type: application/json" \
  -d '{
    "github_repository": "acme/app",
    "branch": "main",
    "create_pr": false
  }'
```

Start a GitHub scan with PR automation:

```bash
curl -X POST http://localhost:8000/scan-repo \
  -H "Content-Type: application/json" \
  -d '{
    "github_repository": "acme/app",
    "branch": "feature/security-pass",
    "base_branch": "main",
    "create_pr": true
  }'
```

Webhook-style trigger with a known commit SHA:

```bash
curl -X POST http://localhost:8000/scan-repo \
  -H "Content-Type: application/json" \
  -d '{
    "github_repository": "acme/app",
    "branch": "main",
    "commit_sha": "abc123def456",
    "base_branch": "main",
    "create_pr": true
  }'
```

Check progress:

```bash
curl http://localhost:8000/status/<job-id>
```

Read structured reports:

```bash
curl http://localhost:8000/report/<job-id>
```
