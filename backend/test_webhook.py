import asyncio
import httpx

async def main():
    async with httpx.AsyncClient() as client:
        payload = {
            "repository": {
                "full_name": "Shreyashgol/cnn_leaf_disease_prediction"
            },
            "after": "1d76048aa29662888a55f5483511eb2df8610df8", # or a new commit
            "ref": "refs/heads/main"
        }
        res = await client.post(
            "http://localhost:8000/webhook/github",
            json=payload,
            headers={"X-GitHub-Event": "push"}
        )
        print("Status Code:", res.status_code)
        print("Response:", res.json())

asyncio.run(main())
