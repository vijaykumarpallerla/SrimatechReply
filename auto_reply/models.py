from django.db import models
from django.contrib.auth.models import User

# Stores a single filter condition for a rule
class RuleCondition(models.Model):
    rule = models.ForeignKey('AutoReplyRule', on_delete=models.CASCADE, related_name='conditions')
    field = models.CharField(max_length=64)
    condition = models.CharField(max_length=32)
    value = models.TextField(blank=True)  # Changed from CharField(255) to TextField for unlimited keywords
    and_or = models.CharField(max_length=8, default='AND')  # AND/OR logic between conditions

    def __str__(self):
        return f"{self.rule.rule_name}: {self.field} {self.condition} {self.value}"

# Stores a single action for a rule (including email draft/attachments)
class RuleAction(models.Model):
    rule = models.ForeignKey('AutoReplyRule', on_delete=models.CASCADE, related_name='actions')
    action_type = models.CharField(max_length=64)
    params = models.JSONField(blank=True, null=True)  # For extra action parameters
    email_body = models.TextField(blank=True, null=True)
    attachments = models.JSONField(blank=True, null=True)  # List of attachment info (filenames, etc.)
    order = models.PositiveIntegerField(default=0)  # For ordering multiple actions

    def __str__(self):
        return f"{self.rule.rule_name}: {self.action_type}"

class GmailToken(models.Model):
	user = models.OneToOneField(User, on_delete=models.CASCADE)
	access_token = models.TextField()
	refresh_token = models.TextField()
	token_expiry = models.DateTimeField(null=True, blank=True)
	created_at = models.DateTimeField(auto_now_add=True)
	updated_at = models.DateTimeField(auto_now=True)

	def __str__(self):
		return f"GmailToken for {self.user.username}"

class ReplyLog(models.Model):
	"""
	Records sent auto-replies to avoid duplicates within a cooldown window.
	Prefer Gmail thread_id when available; otherwise fallback on recipient+subject hash.
	"""
	user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='reply_logs')
	rule = models.ForeignKey('AutoReplyRule', on_delete=models.SET_NULL, null=True, blank=True, related_name='reply_logs')
	to_email = models.EmailField()
	subject = models.TextField(blank=True, null=True)
	subject_key = models.CharField(max_length=255, blank=True, null=True, help_text="Normalized subject key for dedupe when thread_id missing")
	thread_id = models.CharField(max_length=255, blank=True, null=True, db_index=True)
	message_id = models.CharField(max_length=255, blank=True, null=True)
	inbound_id = models.CharField(max_length=255, blank=True, null=True, db_index=True)
	sent_at = models.DateTimeField(auto_now_add=True, db_index=True)
	meta = models.JSONField(blank=True, null=True)

	class Meta:
		indexes = [
			models.Index(fields=['user', 'thread_id']),
			models.Index(fields=['user', 'to_email', 'subject_key']),
			models.Index(fields=['sent_at']),
		]
		constraints = [
			models.UniqueConstraint(fields=['user', 'inbound_id'], name='uniq_replylog_user_inbound')
		]

	def __str__(self):
		tid = self.thread_id or self.subject_key or '(no-key)'
		return f"ReplyLog to={self.to_email} key={tid} at={self.sent_at:%Y-%m-%d %H:%M:%S}"

class AutoReplyRule(models.Model):
	user = models.ForeignKey(User, on_delete=models.CASCADE)
	rule_name = models.CharField(max_length=100)
	workspace = models.CharField(max_length=64, default='current')
	keywords = models.CharField(max_length=255, help_text="Comma-separated keywords")
	reply_message = models.TextField()
	file_id = models.CharField(max_length=255, blank=True, null=True)
	enabled = models.BooleanField(default=True)
	created_at = models.DateTimeField(auto_now_add=True)
	updated_at = models.DateTimeField(auto_now=True)

	def __str__(self):
		return f"{self.rule_name} ({'Enabled' if self.enabled else 'Disabled'})"

class GmailSyncState(models.Model):
	"""Tracks incremental sync state per user (e.g., last processed historyId)."""
	user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='gmail_sync_state')
	last_history_id = models.CharField(max_length=50, blank=True, null=True)
	updated_at = models.DateTimeField(auto_now=True)

	def __str__(self):
		return f"GmailSyncState(user={self.user_id}, last_history_id={self.last_history_id})"

class UserProfile(models.Model):
	user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
	# Signature fields removed in favor of native Gmail signature
	resume = models.FileField(upload_to='resumes/', blank=True, null=True, help_text="Upload your resume (PDF, DOCX, etc.)")
	uploaded_at = models.DateTimeField(auto_now=True)
	# User's own Cloudinary API key for independent quota (separate from shared key)
	cloudinary_api_key = models.CharField(max_length=255, blank=True, null=True, help_text="Your personal Cloudinary API key for independent attachment storage")

	def __str__(self):
		return f"Profile for {self.user.username}"

from django.db.models.signals import post_save
from django.dispatch import receiver

@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        UserProfile.objects.create(user=instance)

@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    if hasattr(instance, 'profile'):
        instance.profile.save()
