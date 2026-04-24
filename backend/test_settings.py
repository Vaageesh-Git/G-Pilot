from vuln_swarm.core.config import get_settings
settings = get_settings()
print(f"GROQ_API_KEY: {settings.groq_api_key}")
print(f"GITHUB_TOKEN: {settings.github_token}")
from vuln_swarm.core.llm import GroqJsonClient
client = GroqJsonClient(settings)
print(f"LLM enabled: {client.enabled}")
