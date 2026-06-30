import os
import logging
from arq.connections import RedisSettings
import main

logger = logging.getLogger(__name__)

async def scan_job(ctx, temp_path, filename, ext, scan_id, content_size, source, url, ip_address, user_agent, ai_provider, ai_model, user_id, api_key):
    logger.info(f"Starting background ARQ job for scan {scan_id}")
    await main._process_scan(temp_path, filename, ext, scan_id, content_size, source, url, ip_address, user_agent, ai_provider, ai_model, user_id, api_key)
    logger.info(f"Finished background ARQ job for scan {scan_id}")

class WorkerSettings:
    functions = [scan_job]
    redis_settings = RedisSettings.from_dsn(os.getenv("REDIS_URL", "redis://localhost:6379/0"))
    max_jobs = 10
