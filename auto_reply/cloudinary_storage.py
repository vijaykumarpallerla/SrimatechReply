"""
Cloudinary storage backend for Django file uploads.
Files are stored in Cloudinary cloud; urls return public/secure URLs.
"""

from django.core.files.storage import Storage
from django.conf import settings
import cloudinary
import cloudinary.uploader
import cloudinary.api
import os


def get_user_cloudinary_credentials(user):
    """
    Get Cloudinary credentials for a specific user.
    Returns (cloud_name, api_key, api_secret) tuple.
    Falls back to shared credentials if user hasn't set their own.
    """
    user_api_key = None
    try:
        if hasattr(user, 'profile') and user.profile.cloudinary_api_key:
            user_api_key = user.profile.cloudinary_api_key.strip()
    except Exception:
        pass
    
    if user_api_key:
        # Support multiple formats the user might paste:
        # 1) Simple:    "api_key:api_secret@cloud_name"
        # 2) URL:       "cloudinary://api_key:api_secret@cloud_name"
        # 3) Full env:  "CLOUDINARY_URL=cloudinary://api_key:api_secret@cloud_name"
        try:
            key_str = user_api_key
            if key_str.startswith('CLOUDINARY_URL='):
                key_str = key_str.split('=', 1)[1].strip()
            if key_str.startswith('cloudinary://'):
                from urllib.parse import urlparse
                parsed = urlparse(key_str)
                cloud_name = parsed.hostname
                api_key = parsed.username
                api_secret = parsed.password
                if cloud_name and api_key and api_secret:
                    print(f"[DEBUG] Using user's personal Cloudinary credentials (URL): cloud={cloud_name}, key={'***'}")
                    return (cloud_name, api_key, api_secret)
            # Fallback to simple format
            if '@' in key_str and ':' in key_str:
                auth_part, cloud_name = key_str.rsplit('@', 1)
                api_key, api_secret = auth_part.split(':', 1)
                print(f"[DEBUG] Using user's personal Cloudinary credentials (simple): cloud={cloud_name}, key={'***'}")
                return (cloud_name, api_key, api_secret)
        except Exception as e:
            print(f"[WARNING] Failed to parse user's Cloudinary key, using shared: {e}")
    
    # Fallback to shared credentials from environment
    cloudinary_url = os.environ.get('CLOUDINARY_URL')
    if cloudinary_url:
        from urllib.parse import urlparse
        parsed = urlparse(cloudinary_url)
        return (parsed.hostname, parsed.username, parsed.password)
    else:
        return (
            os.environ.get('CLOUDINARY_CLOUD_NAME'),
            os.environ.get('CLOUDINARY_API_KEY'),
            os.environ.get('CLOUDINARY_API_SECRET')
        )


class CloudinaryStorage(Storage):
    """Django storage backend using Cloudinary for file uploads."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Initialize with shared credentials by default
        cloudinary_url = os.environ.get('CLOUDINARY_URL')
        if cloudinary_url:
            # Parse URL: cloudinary://api_key:api_secret@cloud_name
            from urllib.parse import urlparse
            parsed = urlparse(cloudinary_url)
            self.cloud_name = parsed.hostname
            self.api_key = parsed.username
            self.api_secret = parsed.password
        else:
            # Fallback to individual env vars
            self.cloud_name = os.environ.get('CLOUDINARY_CLOUD_NAME')
            self.api_key = os.environ.get('CLOUDINARY_API_KEY')
            self.api_secret = os.environ.get('CLOUDINARY_API_SECRET')
        
        print(f"[DEBUG] CloudinaryStorage init: cloud_name={self.cloud_name}, api_key={'***' if self.api_key else None}")

    def set_user_credentials(self, user):
        """Set Cloudinary credentials for a specific user"""
        self.cloud_name, self.api_key, self.api_secret = get_user_cloudinary_credentials(user)
        print(f"[DEBUG] CloudinaryStorage set user credentials: cloud={self.cloud_name}")

    def _get_public_id(self, name):
        """Convert file path to Cloudinary public_id, preserving folder structure and extension."""
        # For raw files (non-images), Cloudinary needs the full path WITH extension
        # Just use the path as-is, replacing backslashes with forward slashes
        return name.replace('\\', '/')

    def _save(self, name, content):
        """Upload file to Cloudinary and return the name."""
        # Read file content
        if hasattr(content, 'read'):
            file_data = content.read()
        else:
            file_data = content

        public_id = self._get_public_id(name)

        try:
            # Upload to Cloudinary with explicit credentials and PUBLIC access
            result = cloudinary.uploader.upload(
                file_data,
                public_id=public_id,
                overwrite=True,
                resource_type='raw',
                type='upload',  # Explicitly set upload type
                access_mode='public',  # Force public access (not private)
                cloud_name=self.cloud_name,
                api_key=self.api_key,
                api_secret=self.api_secret,
            )
            print(f"[DEBUG] Cloudinary upload success: {public_id} -> {result.get('secure_url')}")
            return name
        except Exception as e:
            print(f"[ERROR] Cloudinary upload failed for {name}: {e}")
            raise

    def _open(self, name, mode='rb'):
        """Fetch file from Cloudinary using API-authenticated download."""
        import requests
        from io import BytesIO
        import hashlib
        import time
        
        public_id = self._get_public_id(name)
        print(f"[DEBUG] CloudinaryStorage._open fetching: {public_id}", flush=True)
        
        try:
            # Get resource info from Cloudinary API (this is authenticated)
            resource = cloudinary.api.resource(
                public_id,
                resource_type='raw',
                cloud_name=self.cloud_name,
                api_key=self.api_key,
                api_secret=self.api_secret,
            )
            
            # Get the URL from the resource - Cloudinary gives us back authenticated info
            url = resource.get('secure_url') or resource.get('url')
            print(f"[DEBUG] CloudinaryStorage._open got URL: {url}", flush=True)
            
            # Create a signed download URL using Cloudinary's private API
            # For raw files, we need to use the actual authenticated secure_url
            # or generate a signed URL with authentication token
            
            # Cloudinary's secure_url should work without additional auth since it's from the API
            response = requests.get(url, timeout=30, allow_redirects=True)
            
            if response.status_code == 401:
                print(f"[DEBUG] Got 401 on secure_url, this may be a private resource", flush=True)
                # Try using the cloudinary library's private download with auth
                # by calling the authenticated API endpoint directly
                try:
                    from requests.auth import HTTPBasicAuth
                    # Build direct API call to get the private resource
                    api_url = f"https://{self.api_key}:{self.api_secret}@api.cloudinary.com/v1_1/{self.cloud_name}/resources/raw/upload/{public_id}"
                    response = requests.get(api_url, timeout=30)
                    response.raise_for_status()
                except Exception as auth_error:
                    print(f"[DEBUG] API auth attempt failed: {auth_error}", flush=True)
                    # Last resort: try the plain CDN URL without auth
                    from urllib.parse import quote
                    encoded_public_id = quote(public_id, safe='/')
                    plain_url = f"https://res.cloudinary.com/{self.cloud_name}/raw/upload/{encoded_public_id}"
                    print(f"[DEBUG] Trying plain CDN URL: {plain_url}", flush=True)
                    response = requests.get(plain_url, timeout=30)
                    response.raise_for_status()
            else:
                response.raise_for_status()
            
            content = response.content
            print(f"[DEBUG] CloudinaryStorage._open downloaded {len(content)} bytes", flush=True)
            return BytesIO(content)
        except Exception as e:
            print(f"[ERROR] CloudinaryStorage._open failed: {e}", flush=True)
            raise

    def delete(self, name):
        """Delete a file from Cloudinary."""
        public_id = self._get_public_id(name)
        try:
            cloudinary.uploader.destroy(
                public_id, 
                resource_type='raw',
                cloud_name=self.cloud_name,
                api_key=self.api_key,
                api_secret=self.api_secret,
            )
            print(f"[DEBUG] Cloudinary delete success: {public_id}")
        except Exception as e:
            print(f"[ERROR] Cloudinary delete failed for {public_id}: {e}")

    def exists(self, name):
        """Check if a file exists in Cloudinary."""
        public_id = self._get_public_id(name)
        try:
            print(f"[DEBUG] CloudinaryStorage.exists checking: {public_id}", flush=True)
            cloudinary.api.resource(
                public_id, 
                resource_type='raw',
                cloud_name=self.cloud_name,
                api_key=self.api_key,
                api_secret=self.api_secret,
            )
            print(f"[DEBUG] CloudinaryStorage.exists FOUND: {public_id}", flush=True)
            return True
        except Exception as e:
            print(f"[DEBUG] CloudinaryStorage.exists NOT FOUND: {public_id} - {e}", flush=True)
            return False

    def url(self, name):
        """Return the URL for accessing the file."""
        public_id = self._get_public_id(name)
        # For raw files, build URL with full path including extension
        # URL encode the public_id to handle spaces and special characters
        from urllib.parse import quote
        encoded_public_id = quote(public_id, safe='/')
        return f"https://res.cloudinary.com/{self.cloud_name}/raw/upload/{encoded_public_id}"

    def size(self, name):
        """Return the file size."""
        public_id = self._get_public_id(name)
        try:
            resource = cloudinary.api.resource(
                public_id, 
                resource_type='raw',
                cloud_name=self.cloud_name,
                api_key=self.api_key,
                api_secret=self.api_secret,
            )
            return resource.get('bytes', 0)
        except Exception:
            return 0

    def get_accessed_time(self, name):
        """Not supported by Cloudinary."""
        return None

    def get_created_time(self, name):
        """Return the created time from Cloudinary."""
        public_id = self._get_public_id(name)
        try:
            resource = cloudinary.api.resource(
                public_id, 
                resource_type='raw',
                cloud_name=self.cloud_name,
                api_key=self.api_key,
                api_secret=self.api_secret,
            )
            from datetime import datetime
            return datetime.fromisoformat(resource.get('created_at').replace('Z', '+00:00'))
        except Exception:
            return None

    def get_modified_time(self, name):
        """Cloudinary doesn't track modification time separately."""
        return self.get_created_time(name)
