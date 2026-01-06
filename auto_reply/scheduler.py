import os
import logging
import threading
import time
from datetime import datetime

from django.conf import settings
from django.contrib.auth import get_user_model

logger = logging.getLogger(__name__)

_scheduler = None
_loop_thread = None
_loop_stop = False
_busy_lock = threading.Lock()


def _should_start_scheduler() -> bool:
    """Ensure we only start once in the Django autoreload 'main' process."""
    # Allow explicit opt-out in any environment
    if os.environ.get("DISABLE_IN_APP_SCHEDULER") == "1":
        return False
    # When runserver uses the auto-reloader, Django sets RUN_MAIN='true' in the child.
    run_main = os.environ.get("RUN_MAIN") == "true"
    # If not using runserver (e.g., gunicorn) there might be no RUN_MAIN; allow start in DEBUG.
    if settings.DEBUG:
        return run_main or os.environ.get("RUN_MAIN") is None
    # In non-DEBUG, only start if explicitly enabled via env.
    return os.environ.get("ENABLE_IN_APP_SCHEDULER") == "1"


def start_scheduler():
    global _scheduler
    if _scheduler is not None:
        return
    if not _should_start_scheduler():
        return

    interval_seconds = 28

    # Try APScheduler first
    try:
        from apscheduler.schedulers.background import BackgroundScheduler  # type: ignore
        from apscheduler.executors.pool import ThreadPoolExecutor  # type: ignore
        from apscheduler.jobstores.memory import MemoryJobStore  # type: ignore

        # max_workers=150: Future-proof for up to 150 users
        # Only active threads = number of actual users (e.g., 50 users = 50 threads)
        # Unused capacity doesn't consume resources
        executors = {"default": ThreadPoolExecutor(max_workers=150)}
        jobstores = {"default": MemoryJobStore()}

        scheduler = BackgroundScheduler(jobstores=jobstores, executors=executors, timezone=str(getattr(settings, "TIME_ZONE", "UTC")))
        scheduler.add_job(
            func=_pull_for_all_connected_users,
            trigger="interval",
            seconds=interval_seconds,
            id="gmail_pull_all_users",
            replace_existing=True,
            coalesce=True,
            max_instances=1,
        )
        # Cleanup old ReplyLog entries every 24 hours (runs at midnight UTC)
        scheduler.add_job(
            func=_cleanup_old_replies,
            trigger="interval",
            hours=24,
            id="cleanup_old_replies",
            replace_existing=True,
            coalesce=True,
            max_instances=1,
        )
        scheduler.start()
        _scheduler = scheduler
        logger.info("Started in-app Gmail pull scheduler (APScheduler) every %ss", interval_seconds)
        return
    except Exception as exc:
        logger.warning("APScheduler not available, falling back to simple loop: %s", exc)

    # Fallback: simple background thread loop
    def _loop():
        global _loop_stop
        logger.info("Started in-app Gmail pull simple loop every %ss", interval_seconds)
        while not _loop_stop:
            started = time.time()
            acquired = _busy_lock.acquire(blocking=False)
            if acquired:
                try:
                    _pull_for_all_connected_users()
                except Exception:
                    logger.exception("Auto-pull loop error")
                finally:
                    _busy_lock.release()
            else:
                logger.debug("Previous auto-pull still running, skipping tick")
            elapsed = time.time() - started
            # Sleep remaining interval (avoid thrashing)
            delay = max(1.0, interval_seconds - elapsed)
            time.sleep(delay)

    t = threading.Thread(target=_loop, name="gmail-auto-pull", daemon=True)
    t.start()
    globals()["_loop_thread"] = t


def _pull_for_all_connected_users():
    from .models import GmailToken
    from .gmail_service import gmail_pull_for_user
    import concurrent.futures

    User = get_user_model()
    tokens = list(GmailToken.objects.select_related("user").all())
    
    if not tokens:
        return

    processed_total = 0
    matched_total = 0
    sent_total = 0
    skipped_total = 0

    # Helper function for the thread
    def process_one_user(token):
        try:
            # q="" is fine now as gmail_service handles the default fallback logic internally
            return gmail_pull_for_user(user=token.user, max_results=20)
        except Exception as exc:
            # For 404 errors (deleted messages), just log without traceback
            exc_str = str(exc)
            if '404' in exc_str or 'not found' in exc_str.lower():
                logger.warning("Gmail auto-pull: Message not found (404) for user %s", token.user.pk)
            else:
                logger.exception("Gmail auto-pull failed for user %s: %s", token.user.pk, exc)
            return {}

    # Use ThreadPoolExecutor to run in parallel
    # max_workers=20 ensures we can process 60 users in ~3 batches (very fast)
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        future_to_user = {executor.submit(process_one_user, t): t.user for t in tokens}
        
        for future in concurrent.futures.as_completed(future_to_user):
            result = future.result()
            processed_total += result.get("processed", 0)
            matched_total += result.get("matched", 0)
            sent_total += result.get("sent", 0)
            skipped_total += result.get("skipped", 0)

    logger.debug(
        "Gmail auto-pull run done (Parallel) processed=%s matched=%s sent=%s skipped=%s",
        processed_total,
        matched_total,
        sent_total,
        skipped_total,
    )

def _cleanup_old_replies():
    """
    Cleanup job: Delete ReplyLog entries older than 150 days.
    Runs automatically every 24 hours via APScheduler.
    """
    from .gmail_service import cleanup_old_reply_logs
    
    try:
        deleted_count = cleanup_old_reply_logs(days_to_keep=150)
        if deleted_count > 0:
            logger.info("Cleanup: Deleted %d old ReplyLog entries", deleted_count)
    except Exception as exc:
        logger.exception("Cleanup job failed: %s", exc)