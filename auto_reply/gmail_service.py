import sys
import os
import base64
from datetime import timedelta
from django.conf import settings
from django.utils import timezone
from django.core.files.storage import storages
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request as GoogleRequest
from googleapiclient.discovery import build

from .models import GmailToken, AutoReplyRule, ReplyLog, GmailSyncState

# Get the configured default storage backend (Cloudinary or FileSystem)
default_storage = storages['default']

# Cache for Gmail signatures (per user) to avoid repeated API calls
_signature_cache = {}


def _normalize_subject_key(s: str) -> str:
    s = (s or '').strip().lower()
    for pref in ('re:', 'fw:', 'fwd:'):
        if s.startswith(pref):
            s = s[len(pref):].strip()
    return s


def _eval_conditions_simple(rule_obj, subj: str) -> bool:
    def tokenize(csv_val):
        """Parse keywords separated by comma AND/OR semicolon.
        Examples: "java, python" or "java; python" or "java, python; spring"
        """
        if not csv_val:
            return []
        # Split by both comma AND semicolon to get all keywords
        keywords = str(csv_val).replace(';', ',').split(',')
        return [t.strip().lower() for t in keywords if t.strip()]
    
    subj_text = (subj or '').lower()
    has_contains_condition = False
    
    # Iterate over each condition row. ALL rows must pass (AND logic).
    for c in rule_obj.conditions.all().order_by('id'):
        field = (c.field or '').lower()
        if not field.startswith('email subject'):
            continue
            
        op = (c.condition or '').lower()
        vals = tokenize(c.value or '')
        
        if not vals:
            continue

        if op == 'contains':
            has_contains_condition = True
            # OR logic within the row: matches if ANY token is present
            if not any(tok in subj_text for tok in vals):
                return False
        elif op == 'does not contain':
            # matches if NONE of the tokens are present
            if any(tok in subj_text for tok in vals):
                for tok in vals:
                    if tok in subj_text:
                        print(f"[DEBUG] Rule blocked: Found forbidden token '{tok}' in subject '{subj}'", file=sys.stderr)
                return False
    
    # Safety: Ensure there was at least one "contains" condition that passed
    # (If there were no "contains" conditions, we shouldn't fire on everything)
    if not has_contains_condition:
        # Fallback: Check legacy keywords if no specific subject conditions were found
        if rule_obj.keywords:
            kws = tokenize(rule_obj.keywords)
            if any(k in subj_text for k in kws):
                print(f"[DEBUG] Matched rule '{rule_obj.rule_name}' via legacy keywords: {kws}", file=sys.stderr)
                return True
        return False
        
    return True


def _should_skip(user, thread_id, to_email, subject_key, cooldown_hours):
    window_start = timezone.now() - timedelta(hours=cooldown_hours)
    qs = ReplyLog.objects.filter(user=user, sent_at__gte=window_start)
    if thread_id:
        qs = qs.filter(thread_id=thread_id)
    else:
        qs = qs.filter(to_email__iexact=to_email, subject_key=subject_key)
    return qs.exists()


def _build_creds(token: GmailToken) -> Credentials:
    # Use SOCIAL_AUTH credentials (same ones used for login/token creation)
    client_id = settings.SOCIAL_AUTH_GOOGLE_OAUTH2_KEY
    client_secret = settings.SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET
    
    creds = Credentials(
        token=token.access_token,
        refresh_token=token.refresh_token,
        token_uri='https://oauth2.googleapis.com/token',
        client_id=client_id,
        client_secret=client_secret,
    )
    if not creds.valid and creds.refresh_token:
        try:
            print(f"[DEBUG] Attempting to refresh token for user {token.user.username}...", file=sys.stderr)
            creds.refresh(GoogleRequest())
            token.access_token = creds.token
            token.token_expiry = creds.expiry or (timezone.now() + timedelta(minutes=55))
            token.save(update_fields=['access_token', 'token_expiry', 'updated_at'])
            print(f"[DEBUG] Token refreshed successfully for user {token.user.username}", file=sys.stderr)
        except Exception as e:
            print(f"[ERROR] Token refresh FAILED for user {token.user.username}: {type(e).__name__}: {e}", file=sys.stderr)
            # Token refresh failed - may need user to re-login
            raise
    return creds


def gmail_pull_for_user(user, q: str = 'newer_than:1h', max_results: int = 10) -> dict:
    token = GmailToken.objects.filter(user=user).first()
    if not token:
        return {'error': 'not_connected'}

    print(f"[DEBUG] {timezone.now()} gmail_pull_for_user called for user: {user.username}", file=sys.stderr)
    try:
        creds = _build_creds(token)
        service = build('gmail', 'v1', credentials=creds, cache_discovery=False)

        messages = []
        new_history_id = None
        
        # Check for existing sync state
        sync_state = GmailSyncState.objects.filter(user=user).first()
        start_history_id = sync_state.last_history_id if sync_state else None

        if start_history_id:
            try:
                print(f"[DEBUG] Using historyId {start_history_id} for user {user.username}", file=sys.stderr)
                history_resp = service.users().history().list(userId='me', startHistoryId=start_history_id, historyTypes=['messageAdded']).execute()
                new_history_id = history_resp.get('historyId')
                
                # Extract messages from history events
                for history_item in history_resp.get('history', []):
                    for msg_added in history_item.get('messagesAdded', []):
                        msg = msg_added.get('message')
                        if msg:
                            messages.append(msg)
                
                print(f"[DEBUG] Found {len(messages)} new messages via history", file=sys.stderr)
            except Exception as e:
                print(f"[DEBUG] History sync failed (likely expired): {e}. Falling back to list.", file=sys.stderr)
                start_history_id = None # Force fallback

        if not start_history_id:
            # Fallback: Initial sync or history expired
            # Use a short window (e.g., 1h) to catch up, then switch to history
            print(f"[DEBUG] Performing full list sync (fallback) for user {user.username}", file=sys.stderr)
            # Use 'q' parameter if provided, else default to 'newer_than:1h'
            query = q if q else 'newer_than:1h'
            # Remove labelIds=['INBOX'] to include SENT messages as well
            msg_list = service.users().messages().list(userId='me', q=query, maxResults=max_results).execute()
            messages = msg_list.get('messages', [])
            # Get profile to establish current historyId
            profile = service.users().getProfile(userId='me').execute()
            new_history_id = profile.get('historyId')
            
        print(f"[DEBUG] Total messages to process: {len(messages)}", file=sys.stderr)

        def get_header(headers, name):
            for h in headers:
                if h.get('name', '').lower() == name.lower():
                    return h.get('value')
            return None

        def parse_email_address(s):
            if not s:
                return None
            import re
            m = re.search(r'<([^>]+)>', s)
            return (m.group(1) if m else s).strip().strip('"')

        cooldown_hours = int(getattr(settings, 'REPLY_COOLDOWN_HOURS', 24))
        processed = 0
        matched = 0
        sent_count = 0
        skipped = 0
        results = []
        max_history_id = None

        for m in messages:
            print(f"[DEBUG] Loop: Processing message id: {m['id']} for user: {user.username}", file=sys.stderr)
            
            # CRITICAL: Get message metadata FIRST to extract historyId (even if we skip the message)
            try:
                msg = service.users().messages().get(userId='me', id=m['id'], format='metadata').execute()
                print(f"[DEBUG] Got message metadata successfully", file=sys.stderr)
            except Exception as e:
                error_str = str(e)
                if '404' in error_str or 'not found' in error_str.lower():
                    print(f"[DEBUG] Message {m['id']} not found (404), skipping", file=sys.stderr)
                    continue
                else:
                    print(f"[ERROR] Failed to fetch message {m['id']}: {e}", file=sys.stderr)
                    raise
            
            # Update max_history_id from this message (BEFORE checking if we should skip)
            history_id = str(msg.get('historyId') or '')
            if history_id:
                if max_history_id is None or (history_id.isdigit() and int(history_id) > int(max_history_id or '0')):
                    max_history_id = history_id
            
            # CHECK 1: Did WE send this message as an auto-reply?
            # If this message ID is in our ReplyLog as a 'message_id' (the one we sent), skip it.
            if ReplyLog.objects.filter(message_id=m['id']).exists():
                print(f"[DEBUG] Skipping message {m['id']} (historyId={history_id}) because it was sent by the bot.", file=sys.stderr)
                continue
            
            # CHECK 2: Have we already processed this INBOUND email?
            # If this message is in ReplyLog as inbound_id, we already replied to it
            if ReplyLog.objects.filter(inbound_id=m['id']).exists():
                print(f"[DEBUG] Skipping message {m['id']} (historyId={history_id}) because we already replied to it.", file=sys.stderr)
                continue
            
            print(f"[DEBUG] Message {m['id']} is NEW, will process it", file=sys.stderr)

            processed += 1
            thread_id = msg.get('threadId')
            
            # REMOVED: Global thread-level deduplication check
            # We now allow multiple replies per thread if they are from different rules.
            # Specific rule deduplication happens inside the rule loop.
            payload = msg.get('payload', {})
            headers = payload.get('headers', [])
            subject = get_header(headers, 'Subject') or ''
            print(f"[DEBUG] Subject: {subject}", file=sys.stderr)
            reply_to = parse_email_address(get_header(headers, 'Reply-To'))
            from_email = parse_email_address(get_header(headers, 'From'))
            original_message_id = get_header(headers, 'Message-ID')
            
            # Determine Recipient:
            # If From = user's email (SENT mail), reply to To address
            # If From != user's email (INBOX mail), prefer Reply-To, else From
            user_email = user.email
            is_sent_by_user = (from_email and user_email and from_email.lower() == user_email.lower())
            
            if is_sent_by_user:
                # SENT mail: reply to the To address
                to_addr = parse_email_address(get_header(headers, 'To'))
                print(f"[DEBUG] Message is SENT by user. Target recipient: {to_addr}", file=sys.stderr)
            else:
                # INBOX mail: prefer Reply-To, fallback to From
                to_addr = reply_to or from_email
                print(f"[DEBUG] Message is INBOX. Target recipient (Reply-To preferred): {to_addr}", file=sys.stderr)

            if not to_addr:
                print(f"[DEBUG] No recipient found for message id: {m['id']}", file=sys.stderr)
                results.append({'id': m['id'], 'reason': 'No recipient', 'action': 'skip'})
                skipped += 1
                continue

            # Iterate through ALL enabled rules to find matches
            matched_rules = []
            all_rules = list(AutoReplyRule.objects.filter(user=user, enabled=True).order_by('-updated_at'))
            print(f"[DEBUG] Found {len(all_rules)} enabled rules for user {user.username}", file=sys.stderr)
            
            for r in all_rules:
                is_match = _eval_conditions_simple(r, subject)
                print(f"[DEBUG] Checking rule '{r.rule_name}' against subject '{subject}': {is_match}", file=sys.stderr)
                if is_match:
                    matched_rules.append(r)
            
            if not matched_rules:
                print(f"[DEBUG] No rules matched for message {m['id']}", file=sys.stderr)
                results.append({'id': m['id'], 'subject': subject, 'matched': False})
                continue
            
            print(f"[DEBUG] Matched {len(matched_rules)} rules for message {m['id']}", file=sys.stderr)
            
            matched += 1
            subject_key = _normalize_subject_key(subject)

            # Process each matching rule
            for rule in matched_rules:
                print(f"[DEBUG] Processing rule '{rule.rule_name}' (ID {rule.id}) for thread {thread_id}", file=sys.stderr)
                # Per-rule deduplication: Check if THIS rule has already fired for this thread
                if ReplyLog.objects.filter(user=user, thread_id=thread_id, rule=rule).exists():
                    print(f"[DEBUG] Skipping rule '{rule.rule_name}' for thread {thread_id} (already replied with this rule)", file=sys.stderr)
                    continue
                
                print(f"[DEBUG] Rule '{rule.rule_name}' not yet applied to thread {thread_id}. Checking actions...", file=sys.stderr)

                action = rule.actions.filter(action_type='send_email').order_by('order', 'id').first()
                if not action:
                    print(f"[DEBUG] No 'send_email' action found for rule '{rule.rule_name}'", file=sys.stderr)
                    results.append({'id': m['id'], 'subject': subject, 'rule': rule.rule_name, 'matched': True, 'action': None})
                    continue
                
                print(f"[DEBUG] Found action {action.id} for rule '{rule.rule_name}'. Action has {len(action.attachments or [])} attachments in DB", file=sys.stderr)
                print(f"[DEBUG] Action attachments JSON: {action.attachments}", file=sys.stderr)
                print(f"[DEBUG] Fetching signature...", file=sys.stderr)

                # Always reply with a "Re:" prefix unless no subject is present
                email_subject = f"Re: {subject}" if subject else (rule.rule_name or 'Auto reply')
                
                html_body = action.email_body or rule.reply_message or ''
                
                # Fetch Gmail signature with caching to avoid repeated API calls
                signature_html = ''
                cache_key = f"{user.id}_signature"
                
                if cache_key not in _signature_cache:
                    try:
                        print(f"[DEBUG] Fetching Gmail signature (cache miss)...", file=sys.stderr)
                        sendas_list = service.users().settings().sendAs().list(userId='me').execute()
                        gmail_signature = ''
                        for sendas in sendas_list.get('sendAs', []):
                            if sendas.get('isPrimary'):
                                gmail_signature = sendas.get('signature', '')
                                break
                        if not gmail_signature:
                            for sendas in sendas_list.get('sendAs', []):
                                if sendas.get('sendAsEmail') == to_addr:
                                    gmail_signature = sendas.get('signature', '')
                                    break
                        _signature_cache[cache_key] = gmail_signature
                        if gmail_signature:
                            print(f"[DEBUG] Cached Gmail signature for user {user.username}", file=sys.stderr)
                    except Exception as e:
                        print(f"[DEBUG] Failed to fetch Gmail signature: {e}", file=sys.stderr)
                        _signature_cache[cache_key] = ''
                else:
                    print(f"[DEBUG] Using cached Gmail signature for user {user.username}", file=sys.stderr)
                
                # Append cached signature to email body
                signature_html = _signature_cache.get(cache_key, '')
                if signature_html:
                    print(f"[DEBUG] Appending signature to email body", file=sys.stderr)
                    html_body = f"{html_body}<br>{signature_html}"
                
                msg_root = MIMEMultipart('related')
                msg_root['To'] = to_addr
                msg_root['Subject'] = email_subject
                
                # Add email threading headers for proper Gmail thread linking
                if original_message_id:
                    msg_root['In-Reply-To'] = original_message_id
                    msg_root['References'] = original_message_id
                    print(f"[DEBUG] Added threading headers with Message-ID: {original_message_id}", file=sys.stderr)
                
                msg_alt = MIMEMultipart('alternative')
                msg_alt.attach(MIMEText(html_body, 'html'))
                msg_root.attach(msg_alt)
                
                # Local signature image logic removed.
                
                attached_count = 0
                print(f"[DEBUG] gmail_service processing {len(action.attachments or [])} attachments for rule {rule.rule_name}", file=sys.stderr)
                for att in (action.attachments or []):
                    try:
                        path = att.get('path')
                        name = att.get('name') or 'file'
                        ctype = att.get('content_type') or 'application/octet-stream'
                        print(f"[DEBUG] gmail_service checking attachment: path={path}, name={name}", file=sys.stderr)
                        if path and default_storage.exists(path):
                            print(f"[DEBUG] gmail_service attachment exists, opening: {path}", file=sys.stderr)
                            with default_storage.open(path, 'rb') as fh:
                                content = fh.read()
                            print(f"[DEBUG] gmail_service read {len(content)} bytes from {path}", file=sys.stderr)
                            part = MIMEBase(*ctype.split('/', 1))
                            part.set_payload(content)
                            encoders.encode_base64(part)
                            part.add_header('Content-Disposition', 'attachment', filename=name)
                            msg_root.attach(part)
                            attached_count += 1
                            print(f"[DEBUG] gmail_service attached file #{attached_count}: {name}", file=sys.stderr)
                        else:
                            print(f"[DEBUG] gmail_service attachment NOT found or no path: {att}", file=sys.stderr)
                    except Exception as _e:
                        print(f"[DEBUG] gmail_service attachment error for {att}: {_e}", file=sys.stderr)

                raw = base64.urlsafe_b64encode(msg_root.as_bytes()).decode()
                
                from django.db import IntegrityError
                try:
                    # Create log entry for THIS rule
                    log, created = ReplyLog.objects.get_or_create(
                        user=user,
                        rule=rule,
                        to_email=to_addr,
                        subject=subject,
                        subject_key=subject_key,
                        thread_id=thread_id,
                        # We use inbound_id + rule_id as a composite logical key, but since inbound_id is unique constraint
                        # we might need to be careful. Actually, the model has:
                        # constraints = [models.UniqueConstraint(fields=['user', 'inbound_id'], name='uniq_replylog_user_inbound')]
                        # This constraint prevents multiple rows for the same inbound message.
                        # WE NEED TO REMOVE OR MODIFY THIS CONSTRAINT if we want multiple replies for the same inbound message.
                        # For now, we will use a composite inbound_id like "msgid_ruleid" to bypass the DB constraint if we can't migrate.
                        # Wait, we can't easily change the DB schema without migration.
                        # Let's check the model definition again.
                        
                        # Model definition:
                        # inbound_id = models.CharField(max_length=255, blank=True, null=True, db_index=True)
                        # constraints = [models.UniqueConstraint(fields=['user', 'inbound_id'], name='uniq_replylog_user_inbound')]
                        
                        # HACK: To support multiple rules per inbound message without migration, we append the rule ID to the inbound_id
                        # stored in the DB. e.g. "msg123_rule45"
                        inbound_id=f"{m['id']}_{rule.id}",
                        
                        defaults={'meta': {'attachments': attached_count, 'status': 'pending'}},
                    )
                    if not created:
                        print(f"[DEBUG] Skipping duplicate send for message id: {m['id']} rule {rule.id}", file=sys.stderr)
                        continue
                except IntegrityError:
                    print(f"[DEBUG] IntegrityError ignored for testing: {m['id']}", file=sys.stderr)
                    continue

                try:
                    print(f"[DEBUG] gmail_service sending email with {attached_count} attachments to {to_addr}", file=sys.stderr)
                    sent_msg = service.users().messages().send(userId='me', body={'raw': raw, 'threadId': thread_id}).execute()
                    sent_count += 1
                    print(f"[DEBUG] gmail_service email sent successfully! Message ID: {sent_msg.get('id')}, Attachments: {attached_count}", file=sys.stderr)
                    log.message_id = sent_msg.get('id')
                    meta = log.meta or {}
                    meta['status'] = 'sent'
                    log.meta = meta
                    log.save(update_fields=['message_id', 'meta'])
                    results.append({'id': m['id'], 'subject': subject, 'rule': rule.rule_name, 'matched': True, 'sent': True, 'attachments': attached_count})
                except Exception as _e:
                    print(f"[ERROR] gmail_service failed to send email: {_e}", file=sys.stderr)
                    # Mark failed
                    meta = (log.meta or {})
                    meta['status'] = 'failed'
                    meta['error'] = str(_e)
                    log.meta = meta
                    log.save(update_fields=['meta'])
                    results.append({'id': m['id'], 'subject': subject, 'rule': rule.rule_name, 'matched': True, 'sent': False, 'error': str(_e)})

        # Use max_history_id from processed messages, or fall back to new_history_id from API
        final_history_id = max_history_id or new_history_id
        if final_history_id:
            state, _ = GmailSyncState.objects.get_or_create(user=user)
            state.last_history_id = final_history_id
            state.save(update_fields=['last_history_id', 'updated_at'])
            print(f"[DEBUG] Updated historyId to {final_history_id} for user {user.username}", file=sys.stderr)

        return {'processed': processed, 'matched': matched, 'sent': sent_count, 'skipped': skipped, 'details': results, 'last_history_id': final_history_id}
    except Exception as e:
        error_str = str(e)
        if 'unauthorized' in error_str.lower() or 'invalid_grant' in error_str.lower():
            print(f"[ERROR] AUTHORIZATION FAILED for user {user.username}: {error_str}", file=sys.stderr)
            print(f"[ERROR] User needs to RE-LOGIN to refresh tokens", file=sys.stderr)
        raise


def cleanup_old_reply_logs(days_to_keep=150):
    """
    Delete ReplyLog entries older than specified days (default: 150 days).
    Called automatically by scheduler.
    """
    cutoff_date = timezone.now() - timedelta(days=days_to_keep)
    deleted_count, _ = ReplyLog.objects.filter(sent_at__lt=cutoff_date).delete()
    
    if deleted_count > 0:
        print(f"[CLEANUP] Deleted {deleted_count} old ReplyLog entries (older than {days_to_keep} days, before {cutoff_date.strftime('%Y-%m-%d')})", file=sys.stderr)
    else:
        print(f"[CLEANUP] No old ReplyLog entries to delete (keeping entries from last {days_to_keep} days)", file=sys.stderr)
    
    return deleted_count
