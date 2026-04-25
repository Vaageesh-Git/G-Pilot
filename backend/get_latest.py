import json
from pathlib import Path
from vuln_swarm.core.config import get_settings

store_dir = get_settings().data_dir / "runs"
if store_dir.exists():
    jobs = sorted(store_dir.glob("*.json"), key=lambda p: p.stat().st_mtime)
    if jobs:
        latest = jobs[-1]
        with open(latest) as f:
            data = json.load(f)
            if "vulnerability_report" in data and data["vulnerability_report"]:
                vulns = data["vulnerability_report"].get("vulnerabilities", [])
                print(f"Agent A found {len(vulns)} vulnerabilities.")
                for v in vulns[:3]:
                    print("-", v.get("title"))
            else:
                print("No vulnerabilities.")
