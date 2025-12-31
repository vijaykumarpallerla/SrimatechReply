import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'gmail_auto_reply.settings')
django.setup()

from auto_reply.models import GmailSyncState
from django.contrib.auth.models import User

print("\n=== Checking GmailSyncState in Database ===\n")

users = User.objects.all()
for user in users:
    print(f"User: {user.username}")
    sync_state = GmailSyncState.objects.filter(user=user).first()
    if sync_state:
        print(f"  ✅ Has GmailSyncState record")
        print(f"  last_history_id: {sync_state.last_history_id}")
        print(f"  updated_at: {sync_state.updated_at}")
    else:
        print(f"  ❌ NO GmailSyncState record found!")
    print()

print("\n=== All GmailSyncState Records ===\n")
all_states = GmailSyncState.objects.all()
print(f"Total records: {all_states.count()}")
for state in all_states:
    print(f"User: {state.user.username}, HistoryId: {state.last_history_id}, Updated: {state.updated_at}")
