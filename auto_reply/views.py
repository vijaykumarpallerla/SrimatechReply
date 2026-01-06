from django.shortcuts import render, redirect, get_object_or_404
from django.urls import reverse
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from django.http import JsonResponse, HttpResponseBadRequest
from .models import AutoReplyRule
from django.contrib.auth.models import User
from django.contrib.auth.forms import UserCreationForm

import json
from django.contrib.auth import login as auth_login
import sys
import os
from django.core.files.storage import storages
from django.core.files.base import ContentFile
from django.core.mail import EmailMultiAlternatives
from django.conf import settings
from django.utils import timezone
from datetime import timedelta

# Get the configured default storage backend
default_storage = storages['default']
from google_auth_oauthlib.flow import Flow
from google.auth.transport.requests import Request as GoogleRequest
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
import base64
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from .gmail_service import gmail_pull_for_user


@login_required
def rule_create_ui(request):
    # Render the rule editor with blank/default values for a new rule
    class DummyRule:
        rule_name = ''
        workspace = ''
        keywords = ''
        reply_message = ''
        file_id = ''
        enabled = True
        id = None
    return render(request, 'rule_edit_ui.html', {'rule': DummyRule()})

@login_required
def rule_edit_ui(request, rule_id):
	rule = get_object_or_404(AutoReplyRule, id=rule_id, user=request.user)
	conditions = list(rule.conditions.all().order_by('id'))
	actions = list(rule.actions.all().order_by('order', 'id'))
	# Debug: Print conditions to server log
	print(f"[DEBUG] Loaded conditions for rule {rule_id}: {conditions}", file=sys.stderr)
	# Manually serialize to JSON-safe dicts
	conditions_json = json.dumps([
		{'field': c.field, 'condition': c.condition, 'value': c.value, 'and_or': c.and_or}
		for c in conditions
	])
	print(f"[DEBUG] Serialized conditions_json: {conditions_json}", file=sys.stderr)
	actions_json = json.dumps([
		{
			'action_type': a.action_type,
			'email_body': a.email_body,
			'order': a.order,
			'attachments': a.attachments or []
		}
		for a in actions
	])
	print(f"[DEBUG] Serialized actions_json: {actions_json}", file=sys.stderr)
	return render(request, 'rule_edit_ui.html', {
		'rule': rule,
		'conditions': conditions,
		'actions': actions,
		'conditions_json': conditions_json,
		'actions_json': actions_json
	})

@login_required
def rules_dashboard(request):
	# Show Gmail connect status
	from .models import GmailToken, ReplyLog
	
	# With single-step login, we assume connected, but let's just check if we have a token for UI feedback if needed.
	# In the new flow, this should almost always be true after login.
	token_exists = GmailToken.objects.filter(user=request.user).exists()
	
	# We can get the profile email from the user object directly now
	gmail_profile = {'emailAddress': request.user.email}
	
	# Stats
	today_count = ReplyLog.objects.filter(user=request.user, sent_at__date=timezone.now().date()).count()
	total_count = ReplyLog.objects.filter(user=request.user).count()
	
	return render(request, 'rules_dashboard.html', {
		'gmail_connected': token_exists,
		'gmail_profile': gmail_profile,
		'today_count': today_count,
		'total_count': total_count,
	})

@login_required
def rules_list(request):
	rules = AutoReplyRule.objects.filter(user=request.user).order_by('-created_at')
	return JsonResponse({
		'rules': [
			{
				'id': r.id,
				'rule_name': r.rule_name,
				'workspace': r.workspace,
				'keywords': r.keywords,
				'reply_message': r.reply_message,
				'file_id': r.file_id,
				'enabled': r.enabled,
				'created_at': r.created_at,
				'updated_at': r.updated_at,
			} for r in rules
		]
	})

@login_required
@require_POST
def rule_create(request):
	rule_name = request.POST.get('rule_name')
	workspace = request.POST.get('workspace', 'current')
	keywords = request.POST.get('keywords', '')
	reply_message = request.POST.get('reply_message', '')
	file_id = request.POST.get('file_id', '')
	enabled = request.POST.get('enabled', 'false') == 'true'
	if not rule_name:
		if request.headers.get('x-requested-with') == 'XMLHttpRequest':
			return JsonResponse({'error': 'Missing required fields'}, status=400)
		else:
			return redirect('/')
	rule = AutoReplyRule.objects.create(
		user=request.user,
		rule_name=rule_name,
		workspace=workspace,
		keywords=keywords,
		reply_message=reply_message,
		file_id=file_id,
		enabled=enabled
	)

	# --- Save filter conditions ---
	from .models import RuleCondition, RuleAction
	# Log incoming file keys
	if request.FILES:
		print(f"[DEBUG] rule_create FILES keys: {list(request.FILES.keys())}", file=sys.stderr)
	# Collect all condition indices present in POST, then save only complete rows
	cond_indices = set()
	for k in request.POST.keys():
		if k.startswith('filter_field_') or k.startswith('filter_condition_') or k.startswith('filter_value_'):
			try:
				idx = int(k.split('_')[-1])
				cond_indices.add(idx)
			except Exception:
				pass
	for cond_idx in sorted(cond_indices):
		field = request.POST.get(f'filter_field_{cond_idx}')
		condition = request.POST.get(f'filter_condition_{cond_idx}')
		value = request.POST.get(f'filter_value_{cond_idx}')
		and_or = request.POST.get(f'and_or_{cond_idx}', 'AND')
		if not (field and condition and value and value.strip()):
			print(f"[DEBUG] Skipping incomplete condition index {cond_idx}: field={field}, condition={condition}, value={value}", file=sys.stderr)
			continue
		print(f"[DEBUG] Creating condition {cond_idx}: field={field}, condition={condition}, value={value}, and_or={and_or}", file=sys.stderr)
		RuleCondition.objects.create(
			rule=rule,
			field=field,
			condition=condition,
			value=value,
			and_or=and_or
		)

	# --- Save multiple actions ---
	action_idx = 0
	while True:
		action_type = request.POST.get(f'action_type_{action_idx}')
		email_body = request.POST.get(f'action_email_body_{action_idx}', '')
		# Fallback for legacy single action
		if not action_type and action_idx == 0:
			action_type = request.POST.get('action')
			if email_body == '':
				email_body = request.POST.get('reply_message', '')
		if not (action_type and action_type != 'None'):
			break
		# Save action now
		ra = RuleAction.objects.create(
			rule=rule,
			action_type=action_type,
			email_body=email_body,
			order=action_idx
		)
		# Handle attachments posted as attachment_{gidx} and group labels
		attachments_meta = []
		# Collect all group indices from POST label keys and FILES keys to be robust
		group_indices = []
		for k in request.POST.keys():
			if k.startswith('attachment_group_label_'):
				try:
					gi = int(k.split('_')[-1])
					group_indices.append(gi)
				except Exception:
					pass
		for fk in request.FILES.keys():
			if fk.startswith('attachment_'):
				try:
					gi = int(fk.split('_')[-1])
					group_indices.append(gi)
				except Exception:
					pass
		group_indices = sorted(set(group_indices))
		print(f"[DEBUG] rule_create attachment group indices detected: {group_indices}", file=sys.stderr)
		
		# Set user-specific Cloudinary credentials before uploading
		if hasattr(default_storage, 'set_user_credentials'):
			default_storage.set_user_credentials(request.user)
		
		for gi in group_indices:
			label = request.POST.get(f'attachment_group_label_{gi}', '')
			files = request.FILES.getlist(f'attachment_{gi}')
			print(f"[DEBUG] rule_create group {gi} files count: {len(files)}", file=sys.stderr)
			for f in files:
				print(f"[DEBUG] rule_create saving attachment group {gi} file {f.name} size={f.size}", file=sys.stderr)
				# Store file in media under rule_attachments/<rule.id>/<action_idx>/
				subdir = os.path.join('rule_attachments', str(rule.id), str(action_idx))
				path = default_storage.save(os.path.join(subdir, f.name), ContentFile(f.read()))
				attachments_meta.append({
					'group': gi,
					'label': label,
					'name': f.name,
					'size': f.size,
					'content_type': f.content_type,
					'path': path,
				})
		if attachments_meta:
			ra.attachments = attachments_meta
			ra.save(update_fields=['attachments'])
			print(f"[DEBUG] rule_create saved attachments count: {len(attachments_meta)} for action {action_idx}", file=sys.stderr)
		action_idx += 1

	if request.headers.get('x-requested-with') == 'XMLHttpRequest':
		return JsonResponse({'status': 'success', 'rule_id': rule.id})
	else:
		return redirect('/')

@login_required
@require_POST
def rule_edit(request, rule_id):
	rule = get_object_or_404(AutoReplyRule, id=rule_id, user=request.user)
	# Preserve existing action attachments (keyed by order) so we don't lose them if user edits without re-uploading
	old_action_attachments = {a.order: (a.attachments or []) for a in rule.actions.all()}
	# Collect deletion requests for saved attachments (by storage path)
	delete_paths = request.POST.getlist('delete_saved_attachment')
	rule.rule_name = request.POST.get('rule_name', rule.rule_name)
	rule.workspace = request.POST.get('workspace', rule.workspace)
	rule.keywords = request.POST.get('keywords', rule.keywords)
	rule.reply_message = request.POST.get('reply_message', rule.reply_message)
	rule.file_id = request.POST.get('file_id', rule.file_id)
	rule.enabled = request.POST.get('enabled', str(rule.enabled)) == 'true'
	rule.save()
	from .models import RuleCondition, RuleAction
	RuleCondition.objects.filter(rule=rule).delete()
	if request.FILES:
		print(f"[DEBUG] rule_edit FILES keys: {list(request.FILES.keys())}", file=sys.stderr)
	# Collect all condition indices present and save complete rows only
	cond_indices = set()
	for k in request.POST.keys():
		if k.startswith('filter_field_') or k.startswith('filter_condition_') or k.startswith('filter_value_'):
			try:
				idx = int(k.split('_')[-1])
				cond_indices.add(idx)
			except Exception:
				pass
	for cond_idx in sorted(cond_indices):
		field = request.POST.get(f'filter_field_{cond_idx}')
		condition = request.POST.get(f'filter_condition_{cond_idx}')
		value = request.POST.get(f'filter_value_{cond_idx}')
		and_or = request.POST.get(f'and_or_{cond_idx}', 'AND')
		if not (field and condition and value and value.strip()):
			print(f"[DEBUG] Skipping incomplete condition index {cond_idx}: field={field}, condition={condition}, value={value}", file=sys.stderr)
			continue
		print(f"[DEBUG] Saving condition {cond_idx}: field={field}, condition={condition}, value={value}, and_or={and_or}", file=sys.stderr)
		RuleCondition.objects.create(
			rule=rule,
			field=field,
			condition=condition,
			value=value,
			and_or=and_or
		)
	RuleAction.objects.filter(rule=rule).delete()
	action_idx = 0
	while True:
		action_type = request.POST.get(f'action_type_{action_idx}')
		email_body = request.POST.get(f'action_email_body_{action_idx}', '')
		# Fallback for legacy single action
		if not action_type and action_idx == 0:
			action_type = request.POST.get('action')
			if email_body == '':
				email_body = request.POST.get('reply_message', '')
		if not (action_type and action_type != 'None'):
			break
		print(f"[DEBUG] Saving action {action_idx}: action_type={action_type}, email_body length={len(email_body)}", file=sys.stderr)
		ra = RuleAction.objects.create(
			rule=rule,
			action_type=action_type,
			email_body=email_body,
			order=action_idx
		)
		# Attachments
		attachments_meta = []
		# Start with previously saved attachments for this action, excluding user-deleted ones
		preserved = []
		
		# Set user-specific Cloudinary credentials before deleting attachments
		if hasattr(default_storage, 'set_user_credentials'):
			default_storage.set_user_credentials(request.user)
		
		for att in old_action_attachments.get(action_idx, []) or []:
			try:
				if att.get('path') in delete_paths:
					print(f"[DEBUG] rule_edit deleting saved attachment path={att.get('path')} for action {action_idx}", file=sys.stderr)
					try:
						if att.get('path'):
							default_storage.delete(att.get('path'))
					except Exception as _e:
						print(f"[DEBUG] rule_edit delete error for {att.get('path')}: {_e}", file=sys.stderr)
					continue
			except Exception:
				pass
			preserved.append(att)
		group_indices = []
		for k in request.POST.keys():
			if k.startswith('attachment_group_label_'):
				try:
					gi = int(k.split('_')[-1])
					group_indices.append(gi)
				except Exception:
					pass
		for fk in request.FILES.keys():
			if fk.startswith('attachment_'):
				try:
					gi = int(fk.split('_')[-1])
					group_indices.append(gi)
				except Exception:
					pass
		group_indices = sorted(set(group_indices))
		print(f"[DEBUG] rule_edit attachment group indices detected: {group_indices}", file=sys.stderr)
		
		# Set user-specific Cloudinary credentials before uploading
		if hasattr(default_storage, 'set_user_credentials'):
			default_storage.set_user_credentials(request.user)
		
		for gi in group_indices:
			label = request.POST.get(f'attachment_group_label_{gi}', '')
			files = request.FILES.getlist(f'attachment_{gi}')
			print(f"[DEBUG] rule_edit group {gi} files count: {len(files)}", file=sys.stderr)
			for f in files:
				print(f"[DEBUG] rule_edit saving attachment group {gi} file {f.name} size={f.size}", file=sys.stderr)
				subdir = os.path.join('rule_attachments', str(rule.id), str(action_idx))
				path = default_storage.save(os.path.join(subdir, f.name), ContentFile(f.read()))
				attachments_meta.append({
					'group': gi,
					'label': label,
					'name': f.name,
					'size': f.size,
					'content_type': f.content_type,
					'path': path,
				})
		# Merge preserved and newly uploaded
		combined_attachments = preserved + attachments_meta
		print(f"[DEBUG] rule_edit combined attachments count (preserved {len(preserved)} + new {len(attachments_meta)}) = {len(combined_attachments)} for action {action_idx}", file=sys.stderr)
		ra.attachments = combined_attachments
		ra.save(update_fields=['attachments'])
		action_idx += 1
	if request.headers.get('x-requested-with') == 'XMLHttpRequest':
		return JsonResponse({'status': 'success', 'rule_id': rule.id})
	else:
		return redirect('/')

@login_required
@require_POST
def rule_toggle(request, rule_id):
	rule = get_object_or_404(AutoReplyRule, id=rule_id, user=request.user)
	rule.enabled = not rule.enabled
	rule.save()
	return JsonResponse({'status': 'success', 'enabled': rule.enabled})

@login_required
@require_POST
def rule_delete(request, rule_id):
	rule = get_object_or_404(AutoReplyRule, id=rule_id, user=request.user)
	rule.delete()
	return JsonResponse({'status': 'success'})
def signup(request):
	if request.method == 'POST':
		form = UserCreationForm(request.POST)
		if form.is_valid():
			user = form.save()
			allowed_domain = getattr(settings, 'ALLOWED_EMAIL_DOMAIN', None)
			if allowed_domain and not user.email.endswith(allowed_domain):
				user.delete()
				form.add_error('email', f"Only {allowed_domain} accounts are allowed.")
				return render(request, 'registration/signup.html', {'form': form})
			return redirect('login')
	else:
		form = UserCreationForm()
	return render(request, 'registration/signup.html', {'form': form})

@login_required
def rule_form(request):
	return render(request, 'rule_form.html')

@login_required
@csrf_exempt
def save_rule(request):
	if request.method == 'POST':
		rule_name = request.POST.get('rule_name')
		keywords = request.POST.get('keywords')
		reply_message = request.POST.get('reply_message')
		file_id = request.POST.get('file_id', '')
		enabled = request.POST.get('enabled', 'false') == 'true'
		if not rule_name or not keywords or not reply_message:
			return HttpResponseBadRequest('Missing required fields')
		AutoReplyRule.objects.create(
			user=request.user,
			rule_name=rule_name,
			keywords=keywords,
			reply_message=reply_message,
			file_id=file_id,
			enabled=enabled
		)
		return JsonResponse({'status': 'success'})
	return HttpResponseBadRequest('Invalid request')

def gmail_auth(request):
	return redirect('social:begin', backend='google-oauth2')

def gmail_callback(request):
	return redirect('/')

@login_required
def gmail_pull(request):
	"""
	Manually pull recent unread messages from Gmail, evaluate rules, and send auto-replies via Gmail API.
	Duplicate suppression is enforced via ReplyLog (thread_id or recipient+subject).
	Returns a summary JSON for development/testing.
	"""
	try:
		q = request.GET.get('q', 'newer_than:1h')
		max_results = int(request.GET.get('max', '10'))
		result = gmail_pull_for_user(request.user, q=q, max_results=max_results)
		status = 200 if 'error' not in result else 400
		return JsonResponse(result, status=status)
	except Exception as e:
		return JsonResponse({'error': str(e)}, status=500)

@login_required
@require_POST
def test_fire(request):
	"""
	Evaluate a rule (or all rules) against a sample email and optionally send a reply.
	Accepts form or JSON body with keys:
	  - rule_id (optional): if provided, only that rule is evaluated
	  - subject: required
	  - from_email: optional (fallback recipient if reply_to missing)
	  - reply_to: optional (preferred recipient)
	  - send: 'true' to attempt delivery via Django email backend, defaults to dry-run
	Returns JSON containing match details and send status.
	"""
	try:
		payload = {}
		if request.content_type and 'application/json' in request.content_type:
			try:
				payload = json.loads(request.body.decode('utf-8')) if request.body else {}
			except Exception:
				payload = {}
		# Fallback to form fields
		def g(name, default=None):
			return payload.get(name, request.POST.get(name, default))

		rule_id = g('rule_id')
		subject = g('subject', '') or ''
		from_email = g('from_email') or (request.user.email or '')
		reply_to = g('reply_to')
		send_flag = str(g('send', 'false')).lower() == 'true'
		thread_id = g('thread_id')  # optional Gmail thread id for dedupe
		cooldown_override = g('dedupe_window_hours')
		try:
			cooldown_hours = int(cooldown_override) if cooldown_override is not None else int(getattr(settings, 'REPLY_COOLDOWN_HOURS', 24))
		except Exception:
			cooldown_hours = int(getattr(settings, 'REPLY_COOLDOWN_HOURS', 24))
		if not subject:
			return JsonResponse({'error': 'subject is required'}, status=400)

		# Helper: evaluate conditions
		def tokenize(csv_val):
			if not csv_val:
				return []
			return [t.strip().lower() for t in str(csv_val).split(',') if t.strip()]

		def eval_condition(cond, subj):
			field = (cond.field or '').lower()
			op = (cond.condition or '').lower()
			value = cond.value or ''
			subj_text = subj.lower()
			tokens = tokenize(value)
			if field.startswith('email subject'):
				if op == 'contains':
					# true if ANY token is present
					return any(tok in subj_text for tok in tokens) if tokens else False
				if op == 'does not contain':
					# true if ALL tokens are absent
					return all(tok not in subj_text for tok in tokens) if tokens else True
			# Unsupported: default False
			return False

		def eval_conditions_simple(rule_obj, subj):
			"""Match logic: ANY 'contains' token must appear AND NONE of the 'does not contain' tokens may appear.
			If there are zero 'contains' tokens defined, treat as no match (explicit opt-in)."""
			subj_text = subj.lower()
			contains_tokens = []
			exclude_tokens = []
			for c in rule_obj.conditions.all().order_by('id'):
				field = (c.field or '').lower()
				if not field.startswith('email subject'):
					continue
				op = (c.condition or '').lower()
				vals = tokenize(c.value or '')
				if op == 'contains':
					contains_tokens.extend(vals)
				elif op == 'does not contain':
					exclude_tokens.extend(vals)
			# Require at least one contains token
			if not contains_tokens:
				return False
			any_contains = any(tok in subj_text for tok in contains_tokens if tok)
			if not any_contains:
				return False
			any_excluded_present = any(tok in subj_text for tok in exclude_tokens if tok)
			return not any_excluded_present

		# Load candidate rules
		qs = AutoReplyRule.objects.filter(user=request.user, enabled=True)
		if rule_id:
			qs = qs.filter(id=rule_id)
		matched_rule = None
		# First-match semantics: order by most recently updated so latest tweaks win if overlapping.
		for r in qs.order_by('-updated_at'):
			if eval_conditions_simple(r, subject):
				matched_rule = r
				break
		if not matched_rule:
			return JsonResponse({'matched': False, 'reason': 'No rules matched'}, status=200)

		# Choose first send_email action
		from .models import RuleAction
		action = matched_rule.actions.filter(action_type='send_email').order_by('order', 'id').first()
		if not action:
			return JsonResponse({'matched': True, 'action': None, 'reason': 'No send_email action on rule'}, status=200)

		# Build email
		to_addr = reply_to or from_email
		if not to_addr:
			return JsonResponse({'matched': True, 'action': 'send_email', 'error': 'Missing recipient (reply_to/from_email)'}, status=400)
		email_subject = f"Re: {subject}" if subject else (matched_rule.rule_name or 'Auto reply')
		html_body = action.email_body or matched_rule.reply_message or ''
		# Append user's signature_html if available
		signature_html = ''
		try:
			if hasattr(request.user, 'profile') and request.user.profile.signature_html:
				signature_html = request.user.profile.signature_html.strip()
		except Exception:
			signature_html = ''
		if signature_html:
			html_body += f"<br><br>{signature_html}"

		# Attach files from storage
		attachments_meta = action.attachments or []
		attached = []
	
		# Set user-specific Cloudinary credentials before downloading attachments
		if hasattr(default_storage, 'set_user_credentials'):
			default_storage.set_user_credentials(request.user)
	
		for att in attachments_meta:
			try:
				path = att.get('path')
				name = att.get('name') or 'file'
				ctype = att.get('content_type') or 'application/octet-stream'
				if path and default_storage.exists(path):
					with default_storage.open(path, 'rb') as fh:
						content = fh.read()
						attached.append((name, content, ctype))
			except Exception as _e:
				print(f"[DEBUG] test_fire attachment load error for {att}: {_e}", file=sys.stderr)

		# Prepare response (and possible dedupe info)
		resp = {
			'matched': True,
			'rule_id': matched_rule.id,
			'rule_name': matched_rule.rule_name,
			'recipient': to_addr,
			'action': 'send_email',
			'attachments': len(attached),
			'send': send_flag,
		}

		# Duplicate-reply guard
		try:
			from .models import ReplyLog

			def normalize_subject_key(s: str) -> str:
				s = (s or '').strip().lower()
				# Strip common reply prefixes
				for pref in ('re:', 'fw:', 'fwd:'):
					if s.startswith(pref):
						s = s[len(pref):].strip()
				return s

			subject_key = normalize_subject_key(subject)
			window_start = timezone.now() - timedelta(hours=cooldown_hours)
			dup_qs = ReplyLog.objects.filter(user=request.user, sent_at__gte=window_start)
			if thread_id:
				dup_qs = dup_qs.filter(thread_id=thread_id)
			else:
				dup_qs = dup_qs.filter(to_email__iexact=to_addr, subject_key=subject_key)
			last = dup_qs.order_by('-sent_at').first()
			if last:
				resp['skipped'] = True
				resp['reason'] = f"Recent auto-reply already sent within {cooldown_hours}h"
				resp['last_sent_at'] = last.sent_at.isoformat()
				# For dry-run we always return early; for send request, also skip actual send
				return JsonResponse(resp)
		except Exception as _e:
			# Log but don't block send
			print(f"[DEBUG] test_fire dedupe check error: {_e}", file=sys.stderr)

		if not send_flag:
			return JsonResponse(resp)

		try:
			msg = EmailMultiAlternatives(
				subject=email_subject,
				body=html_body,  # fallback plain
				from_email=getattr(settings, 'DEFAULT_FROM_EMAIL', None) or (request.user.email or None),
				to=[to_addr],
			)
			msg.attach_alternative(html_body, 'text/html')
			for (fname, fcontent, ftype) in attached:
				msg.attach(fname, fcontent, ftype)
			sent = msg.send(fail_silently=False)
			resp['sent'] = bool(sent)
			# Record reply log if sent
			if resp.get('sent'):
				try:
					from .models import ReplyLog
					# Reuse same normalization function defined above
					def normalize_subject_key(s: str) -> str:
						s = (s or '').strip().lower()
						for pref in ('re:', 'fw:', 'fwd:'):
							if s.startswith(pref):
								s = s[len(pref):].strip()
						return s
					ReplyLog.objects.create(
						user=request.user,
						rule=matched_rule,
						to_email=to_addr,
						subject=subject,
						subject_key=normalize_subject_key(subject),
						thread_id=thread_id or None,
						meta={'attachments': len(attached)},
					)
				except Exception as _e:
					print(f"[DEBUG] test_fire reply log save error: {_e}", file=sys.stderr)
			return JsonResponse(resp)
		except Exception as e:
			resp['sent'] = False
			resp['error'] = str(e)
			return JsonResponse(resp, status=500)
	except Exception as e:
		return JsonResponse({'error': str(e)}, status=500)


@login_required
def cloudinary_api_key_view(request):
	"""GET returns current key, POST saves new key for the logged-in user."""
	try:
		from .models import UserProfile
		if request.method == 'GET':
			try:
				profile = getattr(request.user, 'profile', None)
				api_key = (profile.cloudinary_api_key if profile else '') or ''
				return JsonResponse({'status': 'success', 'api_key': api_key})
			except Exception as e:
				return JsonResponse({'status': 'error', 'message': str(e)}, status=500)

		if request.method == 'POST':
			api_key = (request.POST.get('cloudinary_api_key') or '').strip()
			if not api_key:
				return JsonResponse({'status': 'error', 'message': 'API key cannot be empty'}, status=400)
			profile, _ = UserProfile.objects.get_or_create(user=request.user)
			profile.cloudinary_api_key = api_key
			profile.save(update_fields=['cloudinary_api_key'])
			return JsonResponse({'status': 'success', 'message': 'API key saved successfully'})

		return JsonResponse({'status': 'error', 'message': 'Invalid method'}, status=400)
	except Exception as e:
		return JsonResponse({'status': 'error', 'message': str(e)}, status=500)


