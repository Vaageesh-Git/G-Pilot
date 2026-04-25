import json
from pathlib import Path
from vuln_swarm.core.config import get_settings

store_dir = get_settings().data_dir / "runs"
latest = sorted(store_dir.glob("*.json"), key=lambda p: p.stat().st_mtime)[-1]
with open(latest) as f:
    data = json.load(f)
    print("Fix Report:", json.dumps(data.get("fix_report"), indent=2))
