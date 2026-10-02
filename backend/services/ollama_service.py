import requests
import json
import logging
from config import Config

logger = logging.getLogger(__name__)

class OllamaService:
    def __init__(self, base_url=None):
        self.base_url = (base_url or Config.OLLAMA_BASE_URL).rstrip("/")

    def check_health(self):
        """Check if Ollama service is reachable and return status."""
        try:
            resp = requests.get(f"{self.base_url}/api/tags", timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                models = [m.get("name") for m in data.get("models", [])]
                return {
                    "status": "online",
                    "available": True,
                    "models": models,
                    "url": self.base_url
                }
            return {
                "status": "degraded",
                "available": False,
                "error": f"HTTP {resp.status_code}",
                "url": self.base_url
            }
        except Exception as e:
            logger.warning(f"Ollama health check failed: {e}")
            return {
                "status": "offline",
                "available": False,
                "error": str(e),
                "url": self.base_url
            }

    def list_models(self):
        """Get list of available Ollama models with their details."""
        try:
            resp = requests.get(f"{self.base_url}/api/tags", timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                return data.get("models", [])
            return []
        except Exception as e:
            logger.error(f"Error fetching Ollama models: {e}")
            return []

    def generate_embedding(self, text, model=None):
        """Generate text embedding vector using nomic-embed-text or specified model."""
        embed_model = model or Config.OLLAMA_EMBED_MODEL
        try:
            payload = {
                "model": embed_model,
                "prompt": text.strip()
            }
            resp = requests.post(
                f"{self.base_url}/api/embeddings",
                json=payload,
                timeout=30
            )
            if resp.status_code == 200:
                return resp.json().get("embedding", [])
            else:
                logger.error(f"Ollama embeddings error HTTP {resp.status_code}: {resp.text}")
                return []
        except Exception as e:
            logger.error(f"Failed to generate embedding: {e}")
            return []

    def generate_completion(self, prompt, model=None, system_prompt=None, temperature=0.1):
        """Generate text completion from selected LLM."""
        chosen_model = model or Config.OLLAMA_MAIN_MODEL
        payload = {
            "model": chosen_model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": 1800,
                "num_thread": 8,
            }
        }
        if system_prompt:
            payload["system"] = system_prompt

        try:
            logger.info(f"Dispatching prompt to Ollama model [{chosen_model}]...")
            resp = requests.post(
                f"{self.base_url}/api/generate",
                json=payload,
                timeout=300  # allow time for local LLM reasoning
            )
            if resp.status_code == 200:
                result = resp.json()
                return {
                    "success": True,
                    "response": result.get("response", ""),
                    "model": chosen_model,
                    "total_duration": result.get("total_duration", 0),
                    "eval_count": result.get("eval_count", 0),
                }
            else:
                logger.error(f"Ollama generate error HTTP {resp.status_code}: {resp.text}")
                return {
                    "success": False,
                    "error": f"Ollama error ({resp.status_code}): {resp.text}",
                    "model": chosen_model
                }
        except requests.exceptions.Timeout:
            logger.error(f"Timeout waiting for Ollama model {chosen_model}")
            return {
                "success": False,
                "error": f"Model {chosen_model} timed out during generation. Please try a faster model like Qwen3:8b.",
                "model": chosen_model
            }
        except Exception as e:
            logger.error(f"Ollama generation failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "model": chosen_model
            }

ollama_service = OllamaService()
