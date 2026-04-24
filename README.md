# Vuln-Swarm

Production-oriented multi-agent security automation system for detecting, validating, fixing, and re-validating software vulnerabilities.

## Architecture

- **Backend:** FastAPI
- **Orchestration:** LangGraph cyclic state graph
- **Vector DB:** ChromaDB with `vulnerabilities`, `exploits`, and `fixes` collections
- **Embeddings:** `sentence-transformers`
- **LLM:** Groq `llama-3.3-70b-versatile`, temperature `0.2`
- **Execution:** Docker sandbox with network disabled by default
- **Git:** branch, commit, push, and GitHub PR automation
- **Frontend:** React dashboard

## Quick Start

```bash
cp .env.example .env
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
uvicorn vuln_swarm.api.app:app --reload --port 8000
```

In another terminal:

```bash
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173`.

## Required Environment

- `GROQ_API_KEY`: Groq API key for structured agent calls.
- `GITHUB_TOKEN`: GitHub user, bot, or GitHub App installation token with access to the target repos. Required only when `create_pr=true`.
- `VULN_SWARM_DATA_DIR`: optional data directory, defaults to `.data`.

## API

- `POST /scan-repo`: starts the Agent A -> B -> C pipeline.
- `GET /status/{id}`: returns job status and trace summary.
- `GET /report/{id}`: returns the latest strict JSON reports.
- `POST /retry/{id}`: retries failed or unfixed runs.

`POST /scan-repo` now uses GitHub-only targeting. Provide `github_repository` in `owner/repo` form plus optional `branch`, `commit_sha`, and `base_branch`.

## Knowledge Base

The default ingestion paths include the two PDF files in this workspace:

- `Vurnabilities .pdf`
- `Vurnabilities Solutions.pdf`

Run manual ingestion:

```bash
cd backend
python -m vuln_swarm.rag.ingest --force
```

## Safety Model

Exploit execution is isolated in Docker with:

- read-only repository mount
- `--network none`
- CPU and memory limits
- command timeout
- no host Docker socket mount

Automated patching is intentionally conservative. Deterministic AST-aware fixers handle common Python vulnerabilities first; Groq structured patch planning is used for the remaining cases when enabled by `GROQ_API_KEY`.
