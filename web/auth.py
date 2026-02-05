"""
Authentication module with TOTP 2FA support.
Handles user login, registration, and two-factor authentication.
"""

import secrets
import base64
from functools import wraps
from typing import Optional, Tuple
from datetime import datetime

from flask import session, redirect, url_for, request, flash, current_app
import pyotp
import qrcode
from io import BytesIO

from .models import db, User, AuditLog


def generate_totp_secret() -> str:
    """Generate a new TOTP secret for 2FA."""
    return pyotp.random_base32()


def get_totp_uri(secret: str, username: str, issuer: str = "Kuma Management Console") -> str:
    """Generate the TOTP URI for QR code generation."""
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=username, issuer_name=issuer)


def generate_qr_code(uri: str) -> str:
    """Generate a QR code as a base64 data URI."""
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    
    buffer = BytesIO()
    img.save(buffer, format='PNG')
    buffer.seek(0)
    
    img_base64 = base64.b64encode(buffer.getvalue()).decode()
    return f"data:image/png;base64,{img_base64}"


def verify_totp(secret: str, token: str) -> bool:
    """Verify a TOTP token."""
    if not secret or not token:
        return False
    totp = pyotp.TOTP(secret)
    # Allow 1 window of drift (30 seconds before/after)
    return totp.verify(token, valid_window=1)


def get_client_ip() -> str:
    """Get the client's IP address, handling proxies."""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    if request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    return request.remote_addr or 'unknown'


def get_user_agent() -> str:
    """Get the client's user agent string (truncated)."""
    ua = request.headers.get('User-Agent', 'unknown')
    return ua[:256] if len(ua) > 256 else ua


def login_required(f):
    """Decorator to require authentication."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('auth.login', next=request.url))
        
        # Verify user still exists and is active
        user = User.query.get(session['user_id'])
        if not user or not user.is_active:
            session.clear()
            flash('Your session has expired. Please log in again.', 'warning')
            return redirect(url_for('auth.login'))
        
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    """Decorator to require admin privileges."""
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        user = User.query.get(session['user_id'])
        if not user or not user.is_admin:
            flash('Admin privileges required.', 'error')
            return redirect(url_for('main.index'))
        return f(*args, **kwargs)
    return decorated_function


def kuma_connection_required(f):
    """Decorator to require an active Kuma connection."""
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if 'kuma_connected' not in session or not session.get('kuma_connected'):
            flash('Please connect to Uptime Kuma first.', 'warning')
            return redirect(url_for('kuma.connect'))
        return f(*args, **kwargs)
    return decorated_function


def validate_password(password: str) -> Tuple[bool, str]:
    """
    Validate password meets security requirements.
    Returns (is_valid, error_message).
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if len(password) > 128:
        return False, "Password must be less than 128 characters."
    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter."
    if not any(c.islower() for c in password):
        return False, "Password must contain at least one lowercase letter."
    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one number."
    return True, ""


def authenticate_user(username: str, password: str, totp_token: str = None) -> Tuple[Optional[User], str]:
    """
    Authenticate a user with username/password and optional TOTP.
    Returns (user, error_message). User is None if authentication failed.
    """
    user = User.query.filter_by(username=username).first()
    
    ip = get_client_ip()
    ua = get_user_agent()
    
    if not user:
        # Don't reveal whether username exists
        AuditLog.log(
            AuditLog.EVENT_LOGIN_FAILED,
            username=username,
            details="Invalid username",
            ip_address=ip,
            user_agent=ua,
            success=False
        )
        return None, "Invalid username or password."
    
    if not user.is_active:
        AuditLog.log(
            AuditLog.EVENT_LOGIN_FAILED,
            user_id=user.id,
            username=username,
            details="Account disabled",
            ip_address=ip,
            user_agent=ua,
            success=False
        )
        return None, "Account is disabled. Contact an administrator."
    
    if user.is_locked():
        remaining = (user.locked_until - datetime.utcnow()).seconds // 60 + 1
        AuditLog.log(
            AuditLog.EVENT_LOGIN_FAILED,
            user_id=user.id,
            username=username,
            details=f"Account locked for {remaining} more minutes",
            ip_address=ip,
            user_agent=ua,
            success=False
        )
        return None, f"Account is locked. Try again in {remaining} minutes."
    
    if not user.check_password(password):
        user.record_failed_login(
            max_attempts=current_app.config.get('MAX_LOGIN_ATTEMPTS', 5),
            lockout_minutes=current_app.config.get('LOCKOUT_DURATION', 15)
        )
        db.session.commit()
        
        remaining = current_app.config.get('MAX_LOGIN_ATTEMPTS', 5) - user.failed_login_attempts
        AuditLog.log(
            AuditLog.EVENT_LOGIN_FAILED,
            user_id=user.id,
            username=username,
            details=f"Invalid password. {remaining} attempts remaining.",
            ip_address=ip,
            user_agent=ua,
            success=False
        )
        
        if remaining > 0:
            return None, f"Invalid username or password. {remaining} attempts remaining."
        return None, "Account locked due to too many failed attempts."
    
    # Check 2FA if enabled
    if user.totp_enabled:
        if not totp_token:
            return None, "2FA_REQUIRED"  # Special marker for 2FA needed
        if not verify_totp(user.totp_secret, totp_token):
            user.record_failed_login(
                max_attempts=current_app.config.get('MAX_LOGIN_ATTEMPTS', 5),
                lockout_minutes=current_app.config.get('LOCKOUT_DURATION', 15)
            )
            db.session.commit()
            AuditLog.log(
                AuditLog.EVENT_LOGIN_FAILED,
                user_id=user.id,
                username=username,
                details="Invalid 2FA token",
                ip_address=ip,
                user_agent=ua,
                success=False
            )
            return None, "Invalid 2FA code."
    
    # Successful login
    user.record_successful_login()
    db.session.commit()
    
    AuditLog.log(
        AuditLog.EVENT_LOGIN,
        user_id=user.id,
        username=username,
        details="Successful login",
        ip_address=ip,
        user_agent=ua,
        success=True
    )
    
    return user, ""


def create_user(username: str, password: str, is_admin: bool = False) -> Tuple[Optional[User], str]:
    """
    Create a new user account.
    Returns (user, error_message). User is None if creation failed.
    """
    # Validate username
    if not username or len(username) < 3:
        return None, "Username must be at least 3 characters."
    if len(username) > 80:
        return None, "Username must be less than 80 characters."
    if not username.isalnum() and '_' not in username:
        return None, "Username can only contain letters, numbers, and underscores."
    
    # Check if username exists
    if User.query.filter_by(username=username).first():
        return None, "Username already exists."
    
    # Validate password
    valid, error = validate_password(password)
    if not valid:
        return None, error
    
    # Create user
    user = User(username=username, is_admin=is_admin)
    user.set_password(password)
    
    db.session.add(user)
    db.session.commit()
    
    AuditLog.log(
        AuditLog.EVENT_USER_CREATED,
        user_id=user.id,
        username=username,
        details=f"Admin: {is_admin}",
        ip_address=get_client_ip(),
        user_agent=get_user_agent(),
        success=True
    )
    
    return user, ""


def setup_required() -> bool:
    """Check if initial setup is required (no users exist)."""
    return User.query.count() == 0


def check_ip_allowed(ip: str) -> bool:
    """Check if the IP address is allowed (if allowlist is configured)."""
    allowed_ips = current_app.config.get('ALLOWED_IPS', '')
    if not allowed_ips:
        return True  # No allowlist configured, allow all
    
    allowed_list = [x.strip() for x in allowed_ips.split(',') if x.strip()]
    if not allowed_list:
        return True
    
    # Simple IP matching (could be extended for CIDR)
    return ip in allowed_list
