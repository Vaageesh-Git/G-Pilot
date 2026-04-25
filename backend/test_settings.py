from vuln_swarm.core.config import get_settings
settings = get_settings()
print(f"GEMINI_API_KEY: {settings.gemini_api_key}")
print(f"GITHUB_TOKEN: {settings.github_token}")
from vuln_swarm.core.llm import GeminiJsonClient
client = GeminiJsonClient(settings)
print(f"LLM enabled: {client.enabled}")
