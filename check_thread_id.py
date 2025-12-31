#!/usr/bin/env python
import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'gmail_auto_reply.settings')
django.setup()

from auto_reply.models import ReplyLog
from django.contrib.auth.models import User
from django.db.models import Count

print("\n" + "="*70)
print("THREAD ID DEDUPLICATION VERIFICATION")
print("="*70)

for user in User.objects.all():
    logs = ReplyLog.objects.filter(user=user)
    if not logs.exists():
        print(f"\n{user.username}: No replies logged yet")
        continue
    
    print(f"\n{user.username}:")
    print(f"  Total replies logged: {logs.count()}")
    
    # Count unique threads
    unique_threads = logs.values('thread_id').distinct().count()
    print(f"  Unique threads with replies: {unique_threads}")
    
    # Show threads with multiple replies
    threads_with_multi = logs.values('thread_id').annotate(count=Count('id')).filter(count__gt=1).order_by('-count')
    
    if threads_with_multi:
        print(f"\n  Threads with MULTIPLE replies (deduplication test):")
        for t in threads_with_multi[:5]:
            thread_id = t['thread_id']
            count = t['count']
            # Get rules applied to this thread
            rules = logs.filter(thread_id=thread_id).values('rule__rule_name').distinct()
            rule_names = ', '.join([r['rule__rule_name'] or 'unknown' for r in rules])
            print(f"    - Thread {thread_id}: {count} replies ({rule_names})")
    else:
        print(f"\n  All threads have single replies (good deduplication)")

print("\n" + "="*70)
print("KEY FIELDS IN DATABASE FOR NO-DUPLICATE LOGIC:")
print("="*70)
print("""
✓ thread_id: Gmail threadId (indexed for fast lookup)
✓ inbound_id: Composite key (threadId + message position)
✓ rule: Foreign key to which rule fired
✓ sent_at: Timestamp for cooldown window checking

DEDUPLICATION STRATEGY:
1. If thread_id exists: Check ReplyLog for (user, thread_id, rule)
2. If thread_id missing: Check ReplyLog for (user, to_email, subject_key)
3. Per-rule check: Only one auto-reply per rule per thread
4. Unique constraint: user + inbound_id (prevents duplicate message pairs)
""")

print("\n" + "="*70)
print("SAMPLE DATABASE ENTRIES:")
print("="*70)
sample_logs = ReplyLog.objects.all()[:5]
for log in sample_logs:
    print(f"\nID: {log.id}")
    print(f"  User: {log.user.username}")
    print(f"  Rule: {log.rule.rule_name if log.rule else 'None'}")
    print(f"  ThreadID: {log.thread_id}")
    print(f"  InboundID: {log.inbound_id}")
    print(f"  To: {log.to_email}")
    print(f"  Sent: {log.sent_at}")
