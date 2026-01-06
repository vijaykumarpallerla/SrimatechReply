"""
Standalone script to run Gmail auto-reply for a specific user (vijayypallerla@gmail.com)
"""
import os
import sys
import django

# Setup Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'gmail_auto_reply.settings')
django.setup()

from django.contrib.auth.models import User
from auto_reply.models import GmailToken
from auto_reply.gmail_service import gmail_pull_for_user

def main():
    """Run Gmail auto-reply for vijayypallerla@gmail.com only"""
    
    target_email = 'vijayypallerla@gmail.com'
    
    print(f"[APP] Starting Gmail auto-reply for {target_email}")
    print("=" * 60)
    
    try:
        # Get the specific user
        user = User.objects.get(username=target_email)
        print(f"[APP] Found user: {user.username}")
        
        # Check if user has Gmail token
        try:
            token = GmailToken.objects.get(user=user)
            print(f"[APP] Gmail token found for {user.username}")
        except GmailToken.DoesNotExist:
            print(f"[APP] ERROR: No Gmail token found for {user.username}")
            print(f"[APP] Please connect Gmail account first via the web UI")
            return
        
        # Check if user has enabled rules
        from auto_reply.models import AutoReplyRule
        enabled_rules = AutoReplyRule.objects.filter(user=user, enabled=True)
        print(f"[APP] Found {enabled_rules.count()} enabled rules")
        
        if enabled_rules.count() == 0:
            print(f"[APP] WARNING: No enabled rules found for {user.username}")
            print(f"[APP] Enable rules via the web UI first")
            return
        
        # Display rules
        for rule in enabled_rules:
            print(f"[APP]   - Rule: {rule.rule_name}")
        
        print("=" * 60)
        print(f"[APP] Processing emails...")
        print()
        
        # Run the Gmail pull and reply logic
        result = gmail_pull_for_user(user, q='newer_than:1h', max_results=10)
        
        print()
        print("=" * 60)
        print(f"[APP] Processing complete!")
        print(f"[APP] Result: {result}")
        print("=" * 60)
        
    except User.DoesNotExist:
        print(f"[APP] ERROR: User '{target_email}' not found in database")
        print(f"[APP] Please create user via web UI first")
        return
    except Exception as e:
        print(f"[APP] ERROR: {e}")
        import traceback
        traceback.print_exc()
        return

if __name__ == '__main__':
    main()
