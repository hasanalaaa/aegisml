import logging
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from .cve_fetcher import fetch_and_store_ai_cves

logger = logging.getLogger("aegisml.threat_intel.scheduler")

scheduler = AsyncIOScheduler()

def start_scheduler():
    """Initialise and start the background scheduler."""
    logger.info("Starting Threat Intel Background Scheduler...")
    
    # Run the CVE fetcher every day at 2:00 AM
    scheduler.add_job(
        fetch_and_store_ai_cves,
        trigger=CronTrigger(hour=2, minute=0),
        id="fetch_ai_cves_daily",
        name="Daily NVD CVE Fetch",
        replace_existing=True
    )
    
    scheduler.start()
    logger.info("Scheduler started successfully.")

def shutdown_scheduler():
    """Gracefully shutdown the scheduler."""
    logger.info("Shutting down Threat Intel Background Scheduler...")
    scheduler.shutdown()
