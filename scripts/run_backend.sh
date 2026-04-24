#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../backend"
uvicorn vuln_swarm.api.app:app --reload --port 8000
