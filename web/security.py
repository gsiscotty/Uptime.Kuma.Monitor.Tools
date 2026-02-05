"""
Security utilities: rate limiting, security headers, input validation.
"""

import re
from functools import wraps
from typing import Optional
from urllib.parse import urlparse

from flask import request, jsonify, current_app, make_response
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address


def get_real_ip():
    """Get the real client IP, handling reverse proxies."""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    if request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    return get_remote_address()


# Initialize rate limiter (configured in app.py)
limiter = Limiter(
    key_func=get_real_ip,
    default_limits=["200 per minute"],
    storage_uri="memory://",
)


def add_security_headers(response):
    """Add security headers to response."""
    import os
    
    # Check if security headers are disabled (for reverse proxy setups)
    disable_security = os.environ.get('DISABLE_SECURITY_HEADERS', 'false').lower() == 'true'
    
    if disable_security:
        # Only add cache control for dynamic pages
        if request.endpoint and 'static' not in request.endpoint:
            response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, private'
            response.headers['Pragma'] = 'no-cache'
            response.headers['Expires'] = '0'
        return response
    
    # Check if running behind a proxy (relaxed security mode)
    relaxed_mode = os.environ.get('RELAXED_SECURITY', 'false').lower() == 'true'
    
    # Prevent clickjacking (allow framing if behind proxy)
    if relaxed_mode:
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    else:
        response.headers['X-Frame-Options'] = 'DENY'
    
    # Prevent MIME type sniffing
    response.headers['X-Content-Type-Options'] = 'nosniff'
    
    # XSS protection (legacy, but doesn't hurt)
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    # Referrer policy
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    
    # Content Security Policy - relaxed for proxy setups
    if relaxed_mode:
        csp = (
            "default-src 'self' *; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com *; "
            "img-src 'self' data: https: *; "
            "font-src 'self' https://fonts.gstatic.com data: *; "
            "connect-src 'self' https: wss: *; "
            "frame-ancestors 'self'; "
            "form-action 'self' *; "
            "base-uri 'self'"
        )
    else:
        csp = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "img-src 'self' data:; "
            "font-src 'self' https://fonts.gstatic.com; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "form-action 'self'; "
            "base-uri 'self'"
        )
    response.headers['Content-Security-Policy'] = csp
    
    # Permissions Policy (formerly Feature-Policy)
    response.headers['Permissions-Policy'] = (
        "accelerometer=(), "
        "camera=(), "
        "geolocation=(), "
        "gyroscope=(), "
        "magnetometer=(), "
        "microphone=(), "
        "payment=(), "
        "usb=()"
    )
    
    # Cache control for sensitive pages
    if request.endpoint and 'static' not in request.endpoint:
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, private'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
    
    return response


def validate_url(url: str) -> tuple[bool, str]:
    """
    Validate and sanitize a URL.
    Returns (is_valid, sanitized_url_or_error).
    """
    if not url:
        return False, "URL is required."
    
    url = url.strip()
    
    # Add protocol if missing
    if not url.startswith(('http://', 'https://')):
        url = f'https://{url}'
    
    try:
        parsed = urlparse(url)
        
        # Must have scheme and netloc
        if not parsed.scheme or not parsed.netloc:
            return False, "Invalid URL format."
        
        # Only allow http and https
        if parsed.scheme not in ('http', 'https'):
            return False, "Only HTTP and HTTPS URLs are allowed."
        
        # Basic hostname validation
        hostname = parsed.netloc.split(':')[0]
        if not hostname:
            return False, "Invalid hostname."
        
        # Prevent SSRF to localhost/internal IPs (basic check)
        # In production, you might want more comprehensive checks
        lower_host = hostname.lower()
        if lower_host in ('localhost', '127.0.0.1', '0.0.0.0', '::1'):
            # Allow localhost for development
            if not current_app.config.get('ALLOW_LOCALHOST', False):
                return False, "Localhost URLs are not allowed."
        
        # Reconstruct clean URL
        clean_url = f"{parsed.scheme}://{parsed.netloc}"
        if parsed.path and parsed.path != '/':
            clean_url += parsed.path.rstrip('/')
        
        return True, clean_url
        
    except Exception as e:
        return False, f"Invalid URL: {str(e)}"


def sanitize_string(s: str, max_length: int = 256, allow_newlines: bool = False) -> str:
    """Sanitize a string input."""
    if not s:
        return ""
    
    s = s.strip()
    
    # Remove control characters (except newlines if allowed)
    if allow_newlines:
        s = re.sub(r'[\x00-\x09\x0b\x0c\x0e-\x1f\x7f]', '', s)
    else:
        s = re.sub(r'[\x00-\x1f\x7f]', '', s)
    
    # Truncate to max length
    if len(s) > max_length:
        s = s[:max_length]
    
    return s


def validate_monitor_ids(ids: list) -> tuple[bool, list[int], str]:
    """
    Validate a list of monitor IDs.
    Returns (is_valid, validated_ids, error_message).
    """
    if not ids:
        return False, [], "No monitor IDs provided."
    
    if not isinstance(ids, list):
        return False, [], "Monitor IDs must be a list."
    
    validated = []
    for id_val in ids:
        try:
            int_id = int(id_val)
            if int_id < 0:
                return False, [], f"Invalid monitor ID: {id_val}"
            validated.append(int_id)
        except (ValueError, TypeError):
            return False, [], f"Invalid monitor ID: {id_val}"
    
    if len(validated) > 1000:
        return False, [], "Too many monitor IDs (max 1000)."
    
    return True, validated, ""


def rate_limit_exceeded_handler(e):
    """Custom handler for rate limit exceeded."""
    return jsonify({
        'error': 'Rate limit exceeded. Please wait before trying again.',
        'retry_after': e.description
    }), 429


class InputValidator:
    """Utility class for common input validations."""
    
    @staticmethod
    def username(value: str) -> tuple[bool, str]:
        """Validate username."""
        if not value:
            return False, "Username is required."
        value = value.strip()
        if len(value) < 3:
            return False, "Username must be at least 3 characters."
        if len(value) > 80:
            return False, "Username must be less than 80 characters."
        if not re.match(r'^[a-zA-Z0-9_]+$', value):
            return False, "Username can only contain letters, numbers, and underscores."
        return True, value
    
    @staticmethod
    def password(value: str) -> tuple[bool, str]:
        """Validate password."""
        if not value:
            return False, "Password is required."
        if len(value) < 8:
            return False, "Password must be at least 8 characters."
        if len(value) > 128:
            return False, "Password must be less than 128 characters."
        if not any(c.isupper() for c in value):
            return False, "Password must contain at least one uppercase letter."
        if not any(c.islower() for c in value):
            return False, "Password must contain at least one lowercase letter."
        if not any(c.isdigit() for c in value):
            return False, "Password must contain at least one number."
        return True, value
    
    @staticmethod
    def totp_token(value: str) -> tuple[bool, str]:
        """Validate TOTP token format."""
        if not value:
            return False, "2FA code is required."
        value = value.strip().replace(' ', '')
        if not re.match(r'^\d{6}$', value):
            return False, "2FA code must be 6 digits."
        return True, value
    
    @staticmethod
    def integer(value, min_val: int = None, max_val: int = None, field_name: str = "Value") -> tuple[bool, int, str]:
        """Validate and convert to integer."""
        try:
            int_val = int(value)
            if min_val is not None and int_val < min_val:
                return False, 0, f"{field_name} must be at least {min_val}."
            if max_val is not None and int_val > max_val:
                return False, 0, f"{field_name} must be at most {max_val}."
            return True, int_val, ""
        except (ValueError, TypeError):
            return False, 0, f"{field_name} must be a number."
