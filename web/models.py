"""
Database models for user authentication.
Uses SQLAlchemy with SQLite for persistent user storage.
"""

from datetime import datetime
import base64
import hashlib

from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

# Import cryptography at module level for better error detection
try:
    from cryptography.fernet import Fernet
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    Fernet = None

db = SQLAlchemy()


class User(db.Model):
    """User model for web application authentication."""
    
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    totp_secret = db.Column(db.String(32), nullable=True)  # For 2FA
    totp_enabled = db.Column(db.Boolean, default=False)
    recovery_codes_hash = db.Column(db.Text, nullable=True)  # Hashed recovery codes (JSON)
    is_admin = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)
    failed_login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)
    
    def set_password(self, password: str) -> None:
        """Hash and set the user's password."""
        self.password_hash = generate_password_hash(password, method='pbkdf2:sha256:600000')
    
    def check_password(self, password: str) -> bool:
        """Verify the user's password."""
        return check_password_hash(self.password_hash, password)
    
    def generate_recovery_codes(self, count: int = 8) -> list:
        """Generate recovery codes and store their hashes. Returns plaintext codes."""
        import secrets
        import json
        
        codes = []
        hashes = []
        for _ in range(count):
            # Generate 8-character alphanumeric code
            code = secrets.token_hex(4).upper()  # 8 hex characters
            codes.append(code)
            hashes.append(generate_password_hash(code, method='pbkdf2:sha256:100000'))
        
        self.recovery_codes_hash = json.dumps(hashes)
        return codes
    
    def verify_recovery_code(self, code: str) -> bool:
        """Verify a recovery code and remove it if valid."""
        import json
        
        if not self.recovery_codes_hash:
            return False
        
        try:
            hashes = json.loads(self.recovery_codes_hash)
        except:
            return False
        
        code = code.upper().strip()
        for i, code_hash in enumerate(hashes):
            if check_password_hash(code_hash, code):
                # Remove the used code
                hashes.pop(i)
                self.recovery_codes_hash = json.dumps(hashes) if hashes else None
                return True
        
        return False
    
    def get_recovery_codes_count(self) -> int:
        """Get the number of remaining recovery codes."""
        import json
        if not self.recovery_codes_hash:
            return 0
        try:
            return len(json.loads(self.recovery_codes_hash))
        except:
            return 0
    
    def is_locked(self) -> bool:
        """Check if the account is currently locked."""
        if self.locked_until is None:
            return False
        if datetime.utcnow() >= self.locked_until:
            # Lock expired, reset
            self.locked_until = None
            self.failed_login_attempts = 0
            return False
        return True
    
    def record_failed_login(self, max_attempts: int = 5, lockout_minutes: int = 15) -> None:
        """Record a failed login attempt and potentially lock the account."""
        self.failed_login_attempts += 1
        if self.failed_login_attempts >= max_attempts:
            from datetime import timedelta
            self.locked_until = datetime.utcnow() + timedelta(minutes=lockout_minutes)
    
    def record_successful_login(self) -> None:
        """Record a successful login."""
        self.failed_login_attempts = 0
        self.locked_until = None
        self.last_login = datetime.utcnow()
    
    def __repr__(self) -> str:
        return f'<User {self.username}>'


class AuditLog(db.Model):
    """Audit log for security-relevant events."""
    
    __tablename__ = 'audit_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    username = db.Column(db.String(80), nullable=True)  # Store even if user deleted
    event_type = db.Column(db.String(50), nullable=False, index=True)
    event_details = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)  # IPv6 compatible
    user_agent = db.Column(db.String(256), nullable=True)
    success = db.Column(db.Boolean, default=True)
    
    # Event types
    EVENT_LOGIN = 'login'
    EVENT_LOGIN_FAILED = 'login_failed'
    EVENT_LOGOUT = 'logout'
    EVENT_2FA_ENABLED = '2fa_enabled'
    EVENT_2FA_DISABLED = '2fa_disabled'
    EVENT_2FA_RECOVERED = '2fa_recovered'
    EVENT_RECOVERY_FAILED = 'recovery_failed'
    EVENT_RECOVERY_CODES_REGENERATED = 'recovery_codes_regenerated'
    EVENT_PASSWORD_CHANGED = 'password_changed'
    EVENT_USER_CREATED = 'user_created'
    EVENT_KUMA_CONNECT = 'kuma_connect'
    EVENT_KUMA_DISCONNECT = 'kuma_disconnect'
    EVENT_KUMA_RECONNECT = 'kuma_reconnect'
    EVENT_BULK_EDIT = 'bulk_edit'
    EVENT_MONITORS_DELETED = 'monitors_deleted'
    EVENT_TAG_CREATED = 'tag_created'
    EVENT_TAG_DELETED = 'tag_deleted'
    EVENT_GROUP_CREATED = 'group_created'
    EVENT_GROUP_DELETED = 'group_deleted'
    EVENT_SERVER_SAVED = 'server_saved'
    EVENT_SERVER_UPDATED = 'server_updated'
    EVENT_SERVER_DELETED = 'server_deleted'
    EVENT_SERVERS_EXPORTED = 'servers_exported'
    EVENT_SERVERS_IMPORTED = 'servers_imported'
    EVENT_ACTIVITY_LOG_EXPORTED = 'activity_log_exported'
    
    @classmethod
    def log(cls, event_type: str, user_id: int = None, username: str = None,
            details: str = None, ip_address: str = None, user_agent: str = None,
            success: bool = True) -> 'AuditLog':
        """Create and save an audit log entry."""
        entry = cls(
            event_type=event_type,
            user_id=user_id,
            username=username,
            event_details=details,
            ip_address=ip_address,
            user_agent=user_agent,
            success=success
        )
        db.session.add(entry)
        db.session.commit()
        return entry
    
    def __repr__(self) -> str:
        return f'<AuditLog {self.event_type} at {self.timestamp}>'


class KumaSession(db.Model):
    """Store Kuma connection sessions (encrypted credentials in session, not DB)."""
    
    __tablename__ = 'kuma_sessions'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    kuma_url = db.Column(db.String(256), nullable=False)
    kuma_username = db.Column(db.String(80), nullable=False)
    # Note: Kuma password is stored in session, not database
    connected_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_activity = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self) -> str:
        return f'<KumaSession {self.kuma_url}>'


class SavedServer(db.Model):
    """
    Store saved Kuma server connections.
    Credentials are encrypted using the app's secret key.
    """
    
    __tablename__ = 'saved_servers'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)  # Display name for the server
    url = db.Column(db.String(256), nullable=False)
    username = db.Column(db.String(80), nullable=False)
    password_encrypted = db.Column(db.Text, nullable=False)  # Encrypted password
    use_2fa = db.Column(db.Boolean, default=False)
    totp_mode = db.Column(db.String(10), default='token')  # 'token' or 'secret'
    totp_secret_encrypted = db.Column(db.Text, nullable=True)  # Encrypted TOTP secret (if mode=secret)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_used = db.Column(db.DateTime, nullable=True)
    
    # Relationship
    user = db.relationship('User', backref=db.backref('saved_servers', lazy=True))
    
    @staticmethod
    def encrypt_value(value: str, secret_key: str) -> str:
        """Encrypt a value using Fernet symmetric encryption."""
        if not CRYPTO_AVAILABLE:
            raise RuntimeError("cryptography library not installed. Run: pip install cryptography")
        
        # Derive a Fernet-compatible key from the secret
        key = base64.urlsafe_b64encode(hashlib.sha256(secret_key.encode()).digest())
        f = Fernet(key)
        return f.encrypt(value.encode()).decode()
    
    @staticmethod
    def decrypt_value(encrypted_value: str, secret_key: str) -> str:
        """Decrypt a value using Fernet symmetric encryption."""
        if not CRYPTO_AVAILABLE:
            raise RuntimeError("cryptography library not installed. Run: pip install cryptography")
        
        key = base64.urlsafe_b64encode(hashlib.sha256(secret_key.encode()).digest())
        f = Fernet(key)
        return f.decrypt(encrypted_value.encode()).decode()
    
    def set_password(self, password: str, secret_key: str) -> None:
        """Encrypt and store the password."""
        self.password_encrypted = self.encrypt_value(password, secret_key)
    
    def get_password(self, secret_key: str) -> str:
        """Decrypt and return the password."""
        return self.decrypt_value(self.password_encrypted, secret_key)
    
    def set_totp_secret(self, totp_secret: str, secret_key: str) -> None:
        """Encrypt and store the TOTP secret."""
        if totp_secret:
            self.totp_secret_encrypted = self.encrypt_value(totp_secret, secret_key)
        else:
            self.totp_secret_encrypted = None
    
    def get_totp_secret(self, secret_key: str) -> str:
        """Decrypt and return the TOTP secret."""
        if self.totp_secret_encrypted:
            return self.decrypt_value(self.totp_secret_encrypted, secret_key)
        return ""
    
    def to_dict(self, include_secrets: bool = False, secret_key: str = None) -> dict:
        """Convert to dictionary for JSON response."""
        data = {
            'id': self.id,
            'name': self.name,
            'url': self.url,
            'username': self.username,
            'use_2fa': self.use_2fa,
            'totp_mode': self.totp_mode,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_used': self.last_used.isoformat() if self.last_used else None,
        }
        if include_secrets and secret_key:
            data['password'] = self.get_password(secret_key)
            if self.use_2fa and self.totp_mode == 'secret':
                data['totp_secret'] = self.get_totp_secret(secret_key)
        return data
    
    def __repr__(self) -> str:
        return f'<SavedServer {self.name} ({self.url})>'


class AppSettings(db.Model):
    """Application-wide settings stored in database."""
    
    __tablename__ = 'app_settings'
    
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(50), unique=True, nullable=False, index=True)
    value = db.Column(db.Text, nullable=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Default settings
    DEFAULTS = {
        'log_retention_days': '90',
    }
    
    @classmethod
    def get(cls, key: str, default: str = None) -> str:
        """Get a setting value by key."""
        setting = cls.query.filter_by(key=key).first()
        if setting:
            return setting.value
        return cls.DEFAULTS.get(key, default)
    
    @classmethod
    def set(cls, key: str, value: str) -> None:
        """Set a setting value."""
        setting = cls.query.filter_by(key=key).first()
        if setting:
            setting.value = value
        else:
            setting = cls(key=key, value=value)
            db.session.add(setting)
        db.session.commit()
    
    @classmethod
    def get_int(cls, key: str, default: int = 0) -> int:
        """Get a setting as an integer."""
        value = cls.get(key)
        try:
            return int(value) if value else default
        except ValueError:
            return default
    
    def __repr__(self) -> str:
        return f'<AppSettings {self.key}={self.value}>'
