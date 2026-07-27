"""ARQ background worker for scan jobs.

Tuning notes (high concurrency / stable queues):
  - max_jobs bounds concurrent scans per worker process; scans are
    I/O-heavy (file reads + AI HTTP calls) so a moderately high default
    is safe, and it is env-tunable without a code change.
  - job_timeout guarantees a wedged scan (hung AI call, pathological
    file) is reaped instead of occupying a slot forever.
  - max_tries=1: _process_scan is NOT idempotent (it inserts a
    ScanRecord and emits progress frames). A retry after a partial
    failure would duplicate records and re-bill AI calls; failures are
    surfaced to the user via the 'failed' progress stage instead.
  - keep_result is short: results are persisted to Postgres/Redis by
    _process_scan itself, so the ARQ result blob is only useful for
    debugging and should not accumulate in Redis memory.
  - health_check_interval lets `arq --check` and container orchestrators
    verify liveness.
"""
import logging
import os

from arq.connections import RedisSettings

import main

logger = logging.getLogger(__name__)


async def scan_job(ctx, temp_path, filename, ext, scan_id, content_size, source, url,
                   ip_address, user_agent, ai_provider, ai_model, user_id, api_key):
    logger.info("Starting background ARQ job for scan %s", scan_id)
    try:
        await main._process_scan(temp_path, filename, ext, scan_id, content_size, source,
                                 url, ip_address, user_agent, ai_provider, ai_model,
                                 user_id, api_key)
        logger.info("Finished background ARQ job for scan %s", scan_id)
    except Exception:
        # _process_scan handles its own cleanup (temp file removal in its
        # finally block) and marks the scan failed. Log with context here so
        # a crashing job never takes the worker loop down and never triggers
        # an ARQ retry storm.
        logger.exception("Scan job %s crashed", scan_id)


async def startup(ctx):
    logger.info("AegisML scan worker started (max_jobs=%s)", WorkerSettings.max_jobs)


async def shutdown(ctx):
    logger.info("AegisML scan worker shutting down")


class WorkerSettings:
    functions = [scan_job]
    redis_settings = RedisSettings.from_dsn(os.getenv("REDIS_URL", "redis://localhost:6379/0"))
    on_startup = startup
    on_shutdown = shutdown

    # Concurrency & memory management
    max_jobs = int(os.getenv("WORKER_MAX_JOBS", "10"))
    job_timeout = int(os.getenv("WORKER_JOB_TIMEOUT", str(15 * 60)))       # reap wedged scans
    keep_result = int(os.getenv("WORKER_KEEP_RESULT", "60"))               # seconds; real results live in DB
    max_tries = 1                                                          # scans are not idempotent
    health_check_interval = int(os.getenv("WORKER_HEALTH_INTERVAL", "60"))
    # Drop jobs that sat in the queue longer than this before starting —
    # after 30 min the client has long since given up polling.
    expires = int(os.getenv("WORKER_JOB_EXPIRES", str(30 * 60)))
