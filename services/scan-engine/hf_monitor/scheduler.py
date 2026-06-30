from apscheduler.schedulers.asyncio import AsyncIOScheduler
from hf_monitor.monitor import monitor_loop
import logging
import datetime

logger = logging.getLogger(__name__)
scheduler = AsyncIOScheduler()
_status = {
    "total_scanned": 0,
    "last_run": None,
    "is_running": False
}

def wrapped_monitor_loop():
    import asyncio
    _status["last_run"] = datetime.datetime.now().isoformat()
    # Note: apscheduler handles async functions directly if configured correctly
    # Since we are in AsyncIOScheduler, we can just pass the async func.
    pass

async def reset_monthly_scans():
    from database import AsyncSessionLocal
    from auth.models import User
    from sqlalchemy import update
    try:
        async with AsyncSessionLocal() as session:
            await session.execute(update(User).values(scans_this_month=0))
            await session.commit()
            logger.info("Monthly scan counts reset to 0.")
    except Exception as e:
        logger.error(f"Error resetting monthly scans: {e}")

def start_scheduler():
    if not scheduler.running:
        scheduler.add_job(monitor_loop, 'interval', minutes=30, id="hf_monitor")
        scheduler.add_job(reset_monthly_scans, 'cron', day=1, hour=0, minute=0, id="reset_scans")
        scheduler.start()
        _status["is_running"] = True
        logger.info("HF Monitor scheduler started")

def shutdown_scheduler():
    if scheduler.running:
        scheduler.shutdown()
        _status["is_running"] = False
        logger.info("HF Monitor scheduler stopped")

def get_scheduler_status():
    return _status
