from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from auto_reply.models import GmailToken
from auto_reply.gmail_service import gmail_pull_for_user

class Command(BaseCommand):
    help = 'Fetch unread Gmail messages and send auto-replies for all connected users.'

    def add_arguments(self, parser):
        parser.add_argument('--q', default='newer_than:1h', help='Gmail search query')
        parser.add_argument('--max', type=int, default=10, help='Max messages to process per user')
        parser.add_argument('--user', type=str, default=None, help='Limit to one username or email')

    def handle(self, *args, **options):
        q = options['q']
        max_results = options['max']
        only = options['user']
        User = get_user_model()
        users = User.objects.all()
        # If a specific user is requested, resolve to exactly one user
        if only:
            try:
                user = User.objects.filter(username=only).first()
                if not user:
                    user = User.objects.filter(email=only).first()
                if not user:
                    self.stdout.write(self.style.WARNING(f"No user matched: {only}"))
                    return
                users = User.objects.filter(pk=user.pk)
            except Exception as exc:
                self.stdout.write(self.style.WARNING(f"User lookup failed for {only}: {exc}"))
                return
        total_processed = 0
        total_sent = 0
        total_skipped = 0
        for u in users:
            if not GmailToken.objects.filter(user=u).exists():
                continue
            result = gmail_pull_for_user(u, q=q, max_results=max_results)
            if 'error' in result:
                self.stdout.write(self.style.WARNING(f"{u.username}: error {result['error']}"))
                continue
            total_processed += result.get('processed', 0)
            total_sent += result.get('sent', 0)
            total_skipped += result.get('skipped', 0)
            self.stdout.write(self.style.SUCCESS(f"{u.username}: processed={result.get('processed')} sent={result.get('sent')} skipped={result.get('skipped')}"))
        self.stdout.write(self.style.MIGRATE_HEADING(f"Total processed={total_processed} sent={total_sent} skipped={total_skipped}"))
