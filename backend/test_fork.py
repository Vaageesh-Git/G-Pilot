import asyncio
import httpx
from vuln_swarm.core.config import get_settings

async def main():
    settings = get_settings()
    url = f"https://api.github.com/repos/Shreyashgol/mcp-client/forks"
    headers = {
        "Authorization": f"Bearer {settings.github_token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    
    async with httpx.AsyncClient() as client:
        res = await client.post(url, headers=headers)
        print("Status", res.status_code)
        try:
            print("Response:", res.json())
        except Exception:
            print("Body:", res.text)

asyncio.run(main())
