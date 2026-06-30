import httpx
import logging
from typing import List, Dict

logger = logging.getLogger(__name__)

async def fetch_recent_hf_models() -> List[Dict]:
    url = "https://huggingface.co/api/models?sort=createdAt&direction=-1&limit=50"
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(url, timeout=10.0)
            if response.status_code == 200:
                return response.json()
    except Exception as e:
        logger.error(f"Error fetching from HF: {e}")
    return []

async def monitor_loop():
    logger.info("Running HF monitor loop...")
    models = await fetch_recent_hf_models()
    logger.info(f"Fetched {len(models)} new models from HF")
    # In a real system, we'd trigger background scan jobs here
    # and use notifications.py if threats are found.
    pass
