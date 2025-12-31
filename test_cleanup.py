#!/usr/bin/env python
import os
import django
from datetime import timedelta

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'gmail_auto_reply.settings')
django.setup()

from auto_reply.models import ReplyLog
from django.utils import timezone
from auto_reply.gmail_service import cleanup_old_reply_logs

print("\n" + "="*70)
print("150-DAY AUTO-DELETE CLEANUP TEST")
print("="*70)

# Show current state
print("\nBEFORE CLEANUP:")
print(f"Total ReplyLog entries: {ReplyLog.objects.count()}")

# Show breakdown by age
now = timezone.now()
entries_0_50_days = ReplyLog.objects.filter(sent_at__gte=now - timedelta(days=50)).count()
entries_51_100_days = ReplyLog.objects.filter(sent_at__gte=now - timedelta(days=100), sent_at__lt=now - timedelta(days=50)).count()
entries_101_150_days = ReplyLog.objects.filter(sent_at__gte=now - timedelta(days=150), sent_at__lt=now - timedelta(days=100)).count()
entries_150plus_days = ReplyLog.objects.filter(sent_at__lt=now - timedelta(days=150)).count()

print(f"  - Last 50 days: {entries_0_50_days}")
print(f"  - 51-100 days ago: {entries_51_100_days}")
print(f"  - 101-150 days ago: {entries_101_150_days}")
print(f"  - Older than 150 days: {entries_150plus_days}")

# Now test the cleanup function
print("\nRunning cleanup function (150 days threshold)...")
deleted_count = cleanup_old_reply_logs(days_to_keep=150)

print("\nAFTER CLEANUP:")
print(f"Total ReplyLog entries: {ReplyLog.objects.count()}")
print(f"Deleted: {deleted_count} entries")

# Show breakdown again
entries_0_50_days = ReplyLog.objects.filter(sent_at__gte=now - timedelta(days=50)).count()
entries_51_100_days = ReplyLog.objects.filter(sent_at__gte=now - timedelta(days=100), sent_at__lt=now - timedelta(days=50)).count()
entries_101_150_days = ReplyLog.objects.filter(sent_at__gte=now - timedelta(days=150), sent_at__lt=now - timedelta(days=100)).count()
entries_150plus_days = ReplyLog.objects.filter(sent_at__lt=now - timedelta(days=150)).count()

print(f"  - Last 50 days: {entries_0_50_days}")
print(f"  - 51-100 days ago: {entries_51_100_days}")
print(f"  - 101-150 days ago: {entries_101_150_days}")
print(f"  - Older than 150 days: {entries_150plus_days} (should be 0 after cleanup)")

print("\n" + "="*70)
print("SCHEDULER INFORMATION:")
print("="*70)
print("""
The cleanup job is now AUTOMATIC:

✓ Function: cleanup_old_reply_logs(days_to_keep=150)
✓ Location: auto_reply/gmail_service.py (line 451-461)
✓ Schedule: Every 24 hours (runs daily)
✓ Deletes: ReplyLog entries older than 150 days
✓ Logs: Prints deletion count to stderr

TIMELINE EXAMPLE (Today: 2025-12-31):
  Cutoff date: 2025-08-06 (150 days ago)
  
  KEEP: 2025-12-31 to 2025-08-07
  DELETE: Before 2025-08-06
  
  When it reaches 2026-05-31:
  Cutoff date: 2025-12-31
  DELETE: Anything before 2025-12-31
""")
