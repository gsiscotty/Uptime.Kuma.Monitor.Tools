"""
Kuma Management Console - Secure Web Application
Main Flask application with routes and configuration.
"""

import os
import secrets
from datetime import timedelta

from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, Blueprint
from flask_wtf.csrf import CSRFProtect
from werkzeug.middleware.proxy_fix import ProxyFix

from .models import db, User, AuditLog, KumaSession, SavedServer, AppSettings
from .auth import (
    login_required, admin_required, kuma_connection_required,
    authenticate_user, create_user, setup_required, check_ip_allowed,
    generate_totp_secret, get_totp_uri, generate_qr_code, verify_totp,
    get_client_ip, get_user_agent, validate_password
)
from .security import limiter, add_security_headers, validate_url, sanitize_string, InputValidator
from .kuma_service import KumaService, KumaServiceError, KumaConnectionExpired


def _run_migrations(app):
    """Run database migrations for schema changes."""
    from sqlalchemy import inspect, text
    
    inspector = inspect(db.engine)
    
    # Check if 'users' table exists
    if 'users' in inspector.get_table_names():
        columns = [col['name'] for col in inspector.get_columns('users')]
        
        # Add recovery_codes_hash column if it doesn't exist
        if 'recovery_codes_hash' not in columns:
            app.logger.info("Adding recovery_codes_hash column to users table...")
            with db.engine.connect() as conn:
                conn.execute(text('ALTER TABLE users ADD COLUMN recovery_codes_hash TEXT'))
                conn.commit()
            app.logger.info("Migration complete: recovery_codes_hash column added.")


def create_app(config=None):
    """Application factory."""
    # Get the directory where this file is located
    base_dir = os.path.dirname(os.path.abspath(__file__))
    
    app = Flask(
        __name__,
        template_folder=os.path.join(base_dir, 'templates'),
        static_folder=os.path.join(base_dir, 'static'),
        static_url_path='/static'
    )
    
    # UNSAFE_MODE: Disable ALL security for external proxy setups
    unsafe_mode = os.environ.get('UNSAFE_MODE', 'false').lower() == 'true'
    
    # Configuration
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///data/users.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    # Session configuration
    if unsafe_mode:
        # Disable all cookie security for proxy compatibility
        app.config['SESSION_COOKIE_SECURE'] = False
        app.config['SESSION_COOKIE_HTTPONLY'] = False
        app.config['SESSION_COOKIE_SAMESITE'] = None
        app.config['WTF_CSRF_ENABLED'] = False
        # Also set these env vars for other components
        os.environ['DISABLE_SECURITY_HEADERS'] = 'true'
    else:
        app.config['SESSION_COOKIE_SECURE'] = os.environ.get('SESSION_COOKIE_SECURE', 'false').lower() == 'true'
        app.config['SESSION_COOKIE_HTTPONLY'] = True
        samesite = os.environ.get('SESSION_COOKIE_SAMESITE', 'Lax')
        app.config['SESSION_COOKIE_SAMESITE'] = samesite if samesite != 'None' else None
    
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(
        seconds=int(os.environ.get('SESSION_LIFETIME', 1800))
    )
    
    # Proxy configuration - trust X-Forwarded-* headers
    if unsafe_mode or os.environ.get('TRUST_PROXY', 'true').lower() == 'true':
        app.wsgi_app = ProxyFix(
            app.wsgi_app,
            x_for=2,       # Trust X-Forwarded-For (2 levels for chained proxies)
            x_proto=1,     # Trust X-Forwarded-Proto
            x_host=1,      # Trust X-Forwarded-Host
            x_port=1,      # Trust X-Forwarded-Port
            x_prefix=1     # Trust X-Forwarded-Prefix
        )
    
    # Security settings
    app.config['MAX_LOGIN_ATTEMPTS'] = int(os.environ.get('MAX_LOGIN_ATTEMPTS', 5))
    app.config['LOCKOUT_DURATION'] = int(os.environ.get('LOCKOUT_DURATION', 15))
    app.config['REQUIRE_2FA'] = os.environ.get('REQUIRE_2FA', 'false').lower() == 'true'
    app.config['ALLOWED_IPS'] = '' if unsafe_mode else os.environ.get('ALLOWED_IPS', '')
    app.config['ALLOW_LOCALHOST'] = os.environ.get('ALLOW_LOCALHOST', 'true').lower() == 'true'
    
    # Apply any passed config
    if config:
        app.config.update(config)
    
    # Initialize extensions
    db.init_app(app)
    
    # CSRF protection (disabled via config in unsafe mode, but must be initialized for templates)
    if unsafe_mode:
        app.config['WTF_CSRF_ENABLED'] = False
    CSRFProtect(app)
    
    limiter.init_app(app)
    
    # Create tables
    with app.app_context():
        # Ensure data directory exists
        db_path = app.config['SQLALCHEMY_DATABASE_URI']
        if db_path.startswith('sqlite:///'):
            db_dir = os.path.dirname(db_path.replace('sqlite:///', ''))
            if db_dir:
                os.makedirs(db_dir, exist_ok=True)
        db.create_all()
        
        # Run migrations for existing databases
        _run_migrations(app)
    
    # Security headers middleware
    @app.after_request
    def apply_security_headers(response):
        return add_security_headers(response)
    
    # IP allowlist check
    @app.before_request
    def check_ip():
        if not check_ip_allowed(get_client_ip()):
            return render_template('error.html', 
                error="Access Denied", 
                message="Your IP address is not allowed."), 403
    
    # Inject current year and version into all templates
    @app.context_processor
    def inject_globals():
        from datetime import datetime
        from . import __version__
        return {
            'current_year': datetime.now().year,
            'app_version': __version__
        }
    
    # Register blueprints
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(kuma_bp, url_prefix='/kuma')
    app.register_blueprint(main_bp)
    
    return app


# ============================================================================
# Auth Blueprint - Login, Setup, User Management
# ============================================================================
auth_bp = Blueprint('auth', __name__)


@auth_bp.route('/setup', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def setup():
    """Initial setup - create admin account."""
    if not setup_required():
        return redirect(url_for('auth.login'))
    
    if request.method == 'POST':
        username = sanitize_string(request.form.get('username', ''))
        password = request.form.get('password', '')
        confirm = request.form.get('confirm_password', '')
        
        # Validate
        valid, error = InputValidator.username(username)
        if not valid:
            flash(error, 'error')
            return render_template('setup.html')
        
        if password != confirm:
            flash('Passwords do not match.', 'error')
            return render_template('setup.html')
        
        valid, error = InputValidator.password(password)
        if not valid:
            flash(error, 'error')
            return render_template('setup.html')
        
        # Create admin user
        user, error = create_user(username, password, is_admin=True)
        if not user:
            flash(error, 'error')
            return render_template('setup.html')
        
        flash('Admin account created. Please log in.', 'success')
        return redirect(url_for('auth.login'))
    
    return render_template('setup.html')


@auth_bp.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    """User login."""
    # Redirect to setup if needed
    if setup_required():
        return redirect(url_for('auth.setup'))
    
    # Already logged in?
    if 'user_id' in session:
        return redirect(url_for('main.index'))
    
    if request.method == 'POST':
        username = sanitize_string(request.form.get('username', ''))
        password = request.form.get('password', '')
        totp_token = request.form.get('totp_token', '').strip()
        
        user, error = authenticate_user(username, password, totp_token)
        
        if error == "2FA_REQUIRED":
            # Show 2FA form
            return render_template('login.html', 
                show_2fa=True, 
                username=username,
                password=password)  # Hidden fields
        
        if not user:
            flash(error, 'error')
            return render_template('login.html')
        
        # Set session
        session.clear()
        session['user_id'] = user.id
        session['username'] = user.username
        session['is_admin'] = user.is_admin
        session.permanent = True
        
        # Redirect to next or index
        next_url = request.args.get('next')
        if next_url and next_url.startswith('/'):
            return redirect(next_url)
        return redirect(url_for('main.index'))
    
    return render_template('login.html')


@auth_bp.route('/recovery', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def recovery():
    """2FA recovery using recovery codes."""
    if setup_required():
        return redirect(url_for('auth.setup'))
    
    if 'user_id' in session:
        return redirect(url_for('main.index'))
    
    if request.method == 'POST':
        username = sanitize_string(request.form.get('username', ''))
        password = request.form.get('password', '')
        recovery_code = request.form.get('recovery_code', '').strip()
        
        # Verify username and password first
        user = User.query.filter_by(username=username, is_active=True).first()
        
        if not user or not user.check_password(password):
            flash('Invalid username or password.', 'error')
            return render_template('recovery.html')
        
        if user.is_locked():
            flash('Account is locked due to too many failed attempts.', 'error')
            return render_template('recovery.html')
        
        if not user.totp_enabled:
            flash('2FA is not enabled for this account.', 'error')
            return render_template('recovery.html')
        
        # Verify recovery code
        if user.verify_recovery_code(recovery_code):
            # Disable 2FA
            user.totp_secret = None
            user.totp_enabled = False
            user.recovery_codes_hash = None
            db.session.commit()
            
            AuditLog.log(
                '2fa_recovered',
                user_id=user.id,
                username=user.username,
                details="2FA disabled via recovery code",
                ip_address=get_client_ip(),
                user_agent=get_user_agent()
            )
            
            # Log the user in
            session.clear()
            session['user_id'] = user.id
            session['username'] = user.username
            session['is_admin'] = user.is_admin
            session.permanent = True
            
            flash('2FA has been disabled. Please set it up again for better security.', 'warning')
            return redirect(url_for('auth.settings'))
        else:
            user.record_failed_login(
                max_attempts=5,
                lockout_minutes=15
            )
            db.session.commit()
            
            AuditLog.log(
                'recovery_failed',
                user_id=user.id,
                username=user.username,
                details="Invalid recovery code",
                ip_address=get_client_ip(),
                user_agent=get_user_agent()
            )
            
            flash('Invalid recovery code.', 'error')
            return render_template('recovery.html', username=username)
    
    # GET request - pre-fill username if coming from login
    username = request.args.get('username', '')
    return render_template('recovery.html', username=username)


@auth_bp.route('/logout')
def logout():
    """User logout."""
    if 'user_id' in session:
        AuditLog.log(
            AuditLog.EVENT_LOGOUT,
            user_id=session.get('user_id'),
            username=session.get('username'),
            ip_address=get_client_ip(),
            user_agent=get_user_agent()
        )
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))


@auth_bp.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    """User settings - change password, 2FA."""
    user = User.query.get(session['user_id'])
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'change_password':
            current = request.form.get('current_password', '')
            new_pass = request.form.get('new_password', '')
            confirm = request.form.get('confirm_password', '')
            
            if not user.check_password(current):
                flash('Current password is incorrect.', 'error')
                return render_template('settings.html', user=user)
            
            if new_pass != confirm:
                flash('New passwords do not match.', 'error')
                return render_template('settings.html', user=user)
            
            valid, error = validate_password(new_pass)
            if not valid:
                flash(error, 'error')
                return render_template('settings.html', user=user)
            
            user.set_password(new_pass)
            db.session.commit()
            
            AuditLog.log(
                AuditLog.EVENT_PASSWORD_CHANGED,
                user_id=user.id,
                username=user.username,
                ip_address=get_client_ip(),
                user_agent=get_user_agent()
            )
            
            flash('Password changed successfully.', 'success')
        
        elif action == 'enable_2fa':
            # Generate new secret
            secret = generate_totp_secret()
            session['pending_2fa_secret'] = secret
            uri = get_totp_uri(secret, user.username)
            qr_code = generate_qr_code(uri)
            return render_template('settings.html', 
                user=user, 
                show_2fa_setup=True,
                qr_code=qr_code,
                secret=secret)
        
        elif action == 'verify_2fa':
            secret = session.get('pending_2fa_secret')
            token = request.form.get('totp_token', '').strip()
            
            if not secret:
                flash('2FA setup session expired. Please try again.', 'error')
                return render_template('settings.html', user=user)
            
            if verify_totp(secret, token):
                user.totp_secret = secret
                user.totp_enabled = True
                
                # Generate recovery codes
                recovery_codes = user.generate_recovery_codes(8)
                db.session.commit()
                session.pop('pending_2fa_secret', None)
                
                AuditLog.log(
                    AuditLog.EVENT_2FA_ENABLED,
                    user_id=user.id,
                    username=user.username,
                    ip_address=get_client_ip(),
                    user_agent=get_user_agent()
                )
                
                # Show recovery codes to user
                return render_template('settings.html',
                    user=user,
                    show_recovery_codes=True,
                    recovery_codes=recovery_codes)
            else:
                flash('Invalid 2FA code. Please try again.', 'error')
                uri = get_totp_uri(secret, user.username)
                qr_code = generate_qr_code(uri)
                return render_template('settings.html',
                    user=user,
                    show_2fa_setup=True,
                    qr_code=qr_code,
                    secret=secret)
        
        elif action == 'disable_2fa':
            token = request.form.get('totp_token', '').strip()
            if verify_totp(user.totp_secret, token):
                user.totp_secret = None
                user.totp_enabled = False
                user.recovery_codes_hash = None
                db.session.commit()
                
                AuditLog.log(
                    AuditLog.EVENT_2FA_DISABLED,
                    user_id=user.id,
                    username=user.username,
                    ip_address=get_client_ip(),
                    user_agent=get_user_agent()
                )
                
                flash('Two-factor authentication disabled.', 'success')
            else:
                flash('Invalid 2FA code.', 'error')
        
        elif action == 'regenerate_recovery':
            # Regenerate recovery codes (requires current 2FA token)
            token = request.form.get('totp_token', '').strip()
            if user.totp_enabled and verify_totp(user.totp_secret, token):
                recovery_codes = user.generate_recovery_codes(8)
                db.session.commit()
                
                AuditLog.log(
                    'recovery_codes_regenerated',
                    user_id=user.id,
                    username=user.username,
                    ip_address=get_client_ip(),
                    user_agent=get_user_agent()
                )
                
                return render_template('settings.html',
                    user=user,
                    show_recovery_codes=True,
                    recovery_codes=recovery_codes)
            else:
                flash('Invalid 2FA code.', 'error')
        
        return render_template('settings.html', user=user)
    
    return render_template('settings.html', user=user)


@auth_bp.route('/activity')
@login_required
def activity_log():
    """View activity/audit logs."""
    from datetime import datetime, timedelta
    
    # Get filter parameters
    event_type = request.args.get('type', '')
    days = request.args.get('days', '7')
    page = request.args.get('page', 1, type=int)
    per_page = 50
    
    # Build query
    query = AuditLog.query
    
    # Filter by user (non-admins only see their own logs)
    user = User.query.get(session['user_id'])
    if not user.is_admin:
        query = query.filter_by(user_id=session['user_id'])
    
    # Filter by event type
    if event_type:
        query = query.filter_by(event_type=event_type)
    
    # Filter by date range
    try:
        days_int = int(days)
        if days_int > 0:
            cutoff = datetime.utcnow() - timedelta(days=days_int)
            query = query.filter(AuditLog.timestamp >= cutoff)
    except ValueError:
        pass
    
    # Order by most recent
    query = query.order_by(AuditLog.timestamp.desc())
    
    # Paginate
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    logs = pagination.items
    
    # Get unique event types for filter dropdown
    event_types = db.session.query(AuditLog.event_type).distinct().order_by(AuditLog.event_type).all()
    event_types = [et[0] for et in event_types]
    
    # Get retention settings
    retention_days = AppSettings.get_int('log_retention_days', 90)
    
    # Get total log count for display
    total_logs = AuditLog.query.count() if user.is_admin else AuditLog.query.filter_by(user_id=session['user_id']).count()
    
    return render_template('activity_log.html',
        logs=logs,
        pagination=pagination,
        event_types=event_types,
        current_type=event_type,
        current_days=days,
        is_admin=user.is_admin,
        retention_days=retention_days,
        total_logs=total_logs
    )


@auth_bp.route('/activity/export')
@login_required
def export_activity_log():
    """Export activity logs as JSON."""
    import json
    from datetime import datetime, timedelta
    
    # Get filter parameters
    event_type = request.args.get('type', '')
    days = request.args.get('days', '30')
    
    # Build query
    query = AuditLog.query
    
    # Filter by user (non-admins only see their own logs)
    user = User.query.get(session['user_id'])
    if not user.is_admin:
        query = query.filter_by(user_id=session['user_id'])
    
    # Filter by event type
    if event_type:
        query = query.filter_by(event_type=event_type)
    
    # Filter by date range
    try:
        days_int = int(days)
        if days_int > 0:
            cutoff = datetime.utcnow() - timedelta(days=days_int)
            query = query.filter(AuditLog.timestamp >= cutoff)
    except ValueError:
        pass
    
    # Order by most recent, limit to 10000
    logs = query.order_by(AuditLog.timestamp.desc()).limit(10000).all()
    
    export_data = {
        'exported_at': datetime.utcnow().isoformat() + 'Z',
        'total_entries': len(logs),
        'logs': []
    }
    
    for log in logs:
        export_data['logs'].append({
            'timestamp': log.timestamp.isoformat() + 'Z' if log.timestamp else None,
            'event_type': log.event_type,
            'username': log.username,
            'details': log.event_details,
            'ip_address': log.ip_address,
            'success': log.success
        })
    
    AuditLog.log(
        'activity_log_exported',
        user_id=session.get('user_id'),
        username=session.get('username'),
        details=f"Exported {len(logs)} log entries",
        ip_address=get_client_ip(),
        user_agent=get_user_agent()
    )
    
    response = app.response_class(
        response=json.dumps(export_data, indent=2),
        status=200,
        mimetype='application/json'
    )
    response.headers['Content-Disposition'] = f'attachment; filename=activity-log-{datetime.utcnow().strftime("%Y%m%d-%H%M%S")}.json'
    return response


@auth_bp.route('/activity/cleanup', methods=['POST'])
@login_required
def cleanup_activity_log():
    """Clean up old activity logs based on retention policy."""
    from datetime import datetime, timedelta
    
    user = User.query.get(session['user_id'])
    if not user.is_admin:
        flash('Only administrators can clean up logs.', 'error')
        return redirect(url_for('auth.activity_log'))
    
    retention_days = AppSettings.get_int('log_retention_days', 90)
    
    if retention_days <= 0:
        flash('Log retention is set to unlimited. No cleanup needed.', 'info')
        return redirect(url_for('auth.activity_log'))
    
    cutoff = datetime.utcnow() - timedelta(days=retention_days)
    
    # Count logs to be deleted
    old_logs = AuditLog.query.filter(AuditLog.timestamp < cutoff).all()
    count = len(old_logs)
    
    if count > 0:
        # Delete old logs
        AuditLog.query.filter(AuditLog.timestamp < cutoff).delete()
        db.session.commit()
        
        # Log the cleanup action
        AuditLog.log(
            'activity_log_cleanup',
            user_id=session.get('user_id'),
            username=session.get('username'),
            details=f"Cleaned up {count} log entries older than {retention_days} days",
            ip_address=get_client_ip(),
            user_agent=get_user_agent()
        )
        
        flash(f'Cleaned up {count} log entries older than {retention_days} days.', 'success')
    else:
        flash('No old log entries to clean up.', 'info')
    
    return redirect(url_for('auth.activity_log'))


@auth_bp.route('/activity/settings', methods=['POST'])
@login_required
def update_activity_settings():
    """Update activity log retention settings."""
    user = User.query.get(session['user_id'])
    if not user.is_admin:
        flash('Only administrators can change log settings.', 'error')
        return redirect(url_for('auth.activity_log'))
    
    try:
        retention_days = int(request.form.get('retention_days', 90))
        
        # Validate range (0 = unlimited, max 365 days)
        if retention_days < 0:
            retention_days = 0
        elif retention_days > 365:
            retention_days = 365
        
        old_value = AppSettings.get('log_retention_days', '90')
        AppSettings.set('log_retention_days', str(retention_days))
        
        AuditLog.log(
            'settings_changed',
            user_id=session.get('user_id'),
            username=session.get('username'),
            details=f"Changed log retention from {old_value} to {retention_days} days",
            ip_address=get_client_ip(),
            user_agent=get_user_agent()
        )
        
        if retention_days == 0:
            flash('Log retention set to unlimited.', 'success')
        else:
            flash(f'Log retention set to {retention_days} days.', 'success')
            
    except ValueError:
        flash('Invalid retention value.', 'error')
    
    return redirect(url_for('auth.activity_log'))


# ============================================================================
# Kuma Blueprint - Connection and API operations
# ============================================================================
kuma_bp = Blueprint('kuma', __name__)

# Store Kuma service instances per session (in-memory)
_kuma_services: dict = {}


def get_kuma_service() -> KumaService:
    """Get or create KumaService for current session."""
    import logging
    logger = logging.getLogger('gunicorn.error')
    
    # Use a stable session identifier stored in the session itself
    if 'kuma_session_id' not in session:
        session['kuma_session_id'] = secrets.token_hex(16)
        logger.info(f"[SERVICE] Created new kuma_session_id: {session['kuma_session_id'][:8]}...")
    
    session_id = session['kuma_session_id']
    
    if session_id not in _kuma_services:
        logger.info(f"[SERVICE] Creating new KumaService for session {session_id[:8]}...")
        _kuma_services[session_id] = KumaService()
    else:
        svc = _kuma_services[session_id]
        logger.debug(f"[SERVICE] Reusing KumaService for session {session_id[:8]}..., connected={svc.connected}")
    
    return _kuma_services[session_id]


@kuma_bp.route('/connect', methods=['GET', 'POST'])
@login_required
def connect():
    """Connect to Uptime Kuma."""
    if request.method == 'POST':
        url = request.form.get('kuma_url', '').strip()
        username = request.form.get('kuma_username', '').strip()
        password = request.form.get('kuma_password', '')
        use_2fa = request.form.get('use_2fa') == 'on'
        totp_mode = request.form.get('totp_mode', 'token')
        totp_value = request.form.get('totp_value', '').strip()
        
        # Validate URL
        valid, result = validate_url(url)
        if not valid:
            flash(result, 'error')
            return render_template('kuma_connect.html')
        url = result
        
        if not username:
            flash('Username is required.', 'error')
            return render_template('kuma_connect.html')
        
        if not password:
            flash('Password is required.', 'error')
            return render_template('kuma_connect.html')
        
        # Connect
        service = get_kuma_service()
        
        totp_token = ""
        totp_secret = ""
        if use_2fa:
            if totp_mode == 'secret':
                totp_secret = totp_value
            else:
                totp_token = totp_value
        
        success, error = service.connect(
            url=url,
            username=username,
            password=password,
            use_2fa=use_2fa,
            totp_token=totp_token,
            totp_secret=totp_secret
        )
        
        if not success:
            flash(f'Connection failed: {error}', 'error')
            return render_template('kuma_connect.html')
        
        # Store connection info in session
        session['kuma_connected'] = True
        session['kuma_url'] = url
        session['kuma_server_name'] = url.replace('https://', '').replace('http://', '').split('/')[0]
        session['kuma_username'] = username
        session['kuma_password'] = password  # Needed for re-auth
        session['kuma_use_2fa'] = use_2fa
        session['kuma_totp_mode'] = totp_mode
        session['kuma_totp_secret'] = totp_secret if totp_mode == 'secret' else ''
        
        AuditLog.log(
            AuditLog.EVENT_KUMA_CONNECT,
            user_id=session.get('user_id'),
            username=session.get('username'),
            details=f"Connected to {url}",
            ip_address=get_client_ip(),
            user_agent=get_user_agent()
        )
        
        flash('Connected to Uptime Kuma successfully!', 'success')
        return redirect(url_for('main.editor'))
    
    return render_template('kuma_connect.html')


@kuma_bp.route('/disconnect')
@login_required
def disconnect():
    """Disconnect from Uptime Kuma."""
    # Get server name before clearing session
    server_name = session.get('kuma_server_name') or session.get('kuma_url') or 'server'
    kuma_url = session.get('kuma_url', '')
    
    service = get_kuma_service()
    service.disconnect()
    
    # Remove service from memory
    session_id = session.get('kuma_session_id')
    if session_id and session_id in _kuma_services:
        del _kuma_services[session_id]
    
    # Clear all kuma session data
    session.pop('kuma_connected', None)
    session.pop('kuma_url', None)
    session.pop('kuma_server_name', None)
    session.pop('kuma_username', None)
    session.pop('kuma_password', None)
    session.pop('kuma_use_2fa', None)
    session.pop('kuma_totp_mode', None)
    session.pop('kuma_totp_secret', None)
    session.pop('kuma_session_id', None)
    
    AuditLog.log(
        AuditLog.EVENT_KUMA_DISCONNECT,
        user_id=session.get('user_id'),
        username=session.get('username'),
        details=f"Disconnected from {server_name} ({kuma_url})",
        ip_address=get_client_ip(),
        user_agent=get_user_agent()
    )
    
    flash(f'Disconnected from {server_name}.', 'info')
    return redirect(url_for('kuma.connect'))


@kuma_bp.route('/api/reconnect', methods=['POST'])
@login_required
@limiter.limit("5 per minute")
def api_reconnect():
    """Reconnect to Uptime Kuma - disconnect and reconnect for fresh data."""
    import logging
    logger = logging.getLogger('gunicorn.error')
    
    try:
        # Get stored connection info
        kuma_url = session.get('kuma_url')
        kuma_username = session.get('kuma_username')
        kuma_password = session.get('kuma_password')
        use_2fa = session.get('kuma_use_2fa', False)
        totp_secret = session.get('kuma_totp_secret', '')
        
        if not kuma_url or not kuma_username:
            return jsonify({'error': 'No connection info stored. Please reconnect manually.'}), 400
        
        logger.info(f"[RECONNECT] Starting reconnect to {kuma_url}")
        
        # Disconnect current connection
        old_service = get_kuma_service()
        old_service.disconnect()
        
        # Remove old service from memory
        session_id = session.get('kuma_session_id')
        if session_id and session_id in _kuma_services:
            del _kuma_services[session_id]
            logger.info(f"[RECONNECT] Removed old service for session {session_id}")
        
        # Generate new session ID
        import uuid
        new_session_id = str(uuid.uuid4())
        session['kuma_session_id'] = new_session_id
        
        # Create new service and connect
        service = KumaService()
        
        # Generate TOTP token if we have the secret
        totp_token = ''
        if use_2fa and totp_secret:
            import pyotp
            totp = pyotp.TOTP(totp_secret)
            totp_token = totp.now()
            logger.info("[RECONNECT] Generated TOTP token from stored secret")
        
        success, error = service.connect(
            url=kuma_url,
            username=kuma_username,
            password=kuma_password,
            use_2fa=use_2fa,
            totp_token=totp_token,
            totp_secret=totp_secret
        )
        
        if success:
            _kuma_services[new_session_id] = service
            session['kuma_connected'] = True
            logger.info(f"[RECONNECT] Successfully reconnected to {kuma_url}")
            
            AuditLog.log(
                AuditLog.EVENT_KUMA_RECONNECT,
                user_id=session.get('user_id'),
                username=session.get('username'),
                details=f"Reconnected to {session.get('kuma_server_name', kuma_url)} ({kuma_url})",
                ip_address=get_client_ip(),
                user_agent=get_user_agent()
            )
            
            return jsonify({
                'success': True,
                'message': 'Reconnected successfully. Fresh data will be loaded.'
            })
        else:
            logger.error(f"[RECONNECT] Failed to reconnect: {error}")
            
            # If reconnect failed due to 2FA token, indicate need for manual re-auth
            if '2fa' in error.lower() or 'token' in error.lower():
                return jsonify({
                    'error': 'Reconnection failed - 2FA token required',
                    'needs_token': True,
                    'session_expired': True
                }), 401
            
            return jsonify({'error': f'Reconnection failed: {error}'}), 500
            
    except Exception as e:
        logger.error(f"[RECONNECT] Exception: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return jsonify({'error': f'Reconnection failed: {str(e)}'}), 500


# ============================================================================
# Saved Servers API
# ============================================================================
@kuma_bp.route('/api/servers')
@login_required
def api_list_servers():
    """List all saved servers for the current user."""
    servers = SavedServer.query.filter_by(user_id=session['user_id']).order_by(SavedServer.name).all()
    return jsonify({
        'servers': [s.to_dict() for s in servers]
    })


@kuma_bp.route('/api/servers', methods=['POST'])
@login_required
@limiter.limit("20 per minute")
def api_save_server():
    """Save a new server connection."""
    from flask import current_app
    import logging
    logger = logging.getLogger('gunicorn.error')
    
    logger.info("[SAVE] api_save_server called")
    
    try:
        data = request.get_json()
        logger.info(f"[SAVE] Received data keys: {list(data.keys()) if data else 'None'}")
        
        if not data:
            logger.warning("[SAVE] No data received")
            return jsonify({'error': 'Invalid request'}), 400
        
        name = sanitize_string(data.get('name', '')).strip()
        url = data.get('url', '').strip()
        username = data.get('username', '').strip()
        password = data.get('password', '')
        use_2fa = data.get('use_2fa', False)
        totp_mode = data.get('totp_mode', 'token')
        totp_secret = data.get('totp_secret', '').strip()
        
        logger.info(f"[SAVE] Parsed: name={name}, url={url}, username={username}, use_2fa={use_2fa}")
        
        # Validate
        if not name or len(name) < 2:
            logger.warning("[SAVE] Validation failed: name too short")
            return jsonify({'error': 'Server name must be at least 2 characters'}), 400
        
        valid, result = validate_url(url)
        logger.info(f"[SAVE] URL validation: valid={valid}, result={result}")
        if not valid:
            return jsonify({'error': result}), 400
        url = result
        
        if not username:
            logger.warning("[SAVE] Validation failed: no username")
            return jsonify({'error': 'Username is required'}), 400
        
        if not password:
            logger.warning("[SAVE] Validation failed: no password")
            return jsonify({'error': 'Password is required'}), 400
        
        if use_2fa and totp_mode == 'secret' and not totp_secret:
            logger.warning("[SAVE] Validation failed: 2FA secret required")
            return jsonify({'error': 'TOTP secret is required when using secret mode'}), 400
        
        # Check for duplicate name
        logger.info(f"[SAVE] Checking for duplicate name for user_id={session['user_id']}")
        existing = SavedServer.query.filter_by(
            user_id=session['user_id'],
            name=name
        ).first()
        if existing:
            logger.warning("[SAVE] Duplicate name found")
            return jsonify({'error': 'A server with this name already exists'}), 400
        
        # Create server
        logger.info("[SAVE] Creating SavedServer object")
        secret_key = current_app.config['SECRET_KEY']
        server = SavedServer(
            user_id=session['user_id'],
            name=name,
            url=url,
            username=username,
            use_2fa=use_2fa,
            totp_mode=totp_mode if use_2fa else 'token'
        )
        
        logger.info("[SAVE] Encrypting password")
        try:
            server.set_password(password, secret_key)
            logger.info("[SAVE] Password encrypted successfully")
            if use_2fa and totp_mode == 'secret':
                logger.info("[SAVE] Encrypting TOTP secret")
                server.set_totp_secret(totp_secret, secret_key)
        except RuntimeError as e:
            logger.error(f"[SAVE] Encryption error: {e}")
            return jsonify({'error': str(e)}), 500
        
        logger.info("[SAVE] Adding to database")
        db.session.add(server)
        db.session.commit()
        logger.info("[SAVE] Database commit successful")
        
        AuditLog.log(
            AuditLog.EVENT_SERVER_SAVED,
            user_id=session.get('user_id'),
            username=session.get('username'),
            details=f"Saved server: {name} ({url})",
            ip_address=get_client_ip(),
            user_agent=get_user_agent()
        )
        
        logger.info("[SAVE] Returning success response")
        return jsonify({
            'success': True,
            'server': server.to_dict(),
            'message': 'Server saved successfully'
        })
        
    except Exception as e:
        import traceback
        logger.error(f"[SAVE] Exception: {e}")
        logger.error(traceback.format_exc())
        return jsonify({'error': f'Failed to save server: {str(e)}'}), 500


@kuma_bp.route('/api/servers/<int:server_id>', methods=['PUT'])
@login_required
@limiter.limit("20 per minute")
def api_update_server(server_id):
    """Update a saved server connection."""
    from flask import current_app
    
    server = SavedServer.query.filter_by(
        id=server_id,
        user_id=session['user_id']
    ).first()
    
    if not server:
        return jsonify({'error': 'Server not found'}), 404
    
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid request'}), 400
    
    secret_key = current_app.config['SECRET_KEY']
    
    # Update fields if provided
    if 'name' in data:
        name = sanitize_string(data['name']).strip()
        if len(name) < 2:
            return jsonify({'error': 'Server name must be at least 2 characters'}), 400
        # Check for duplicate
        existing = SavedServer.query.filter(
            SavedServer.user_id == session['user_id'],
            SavedServer.name == name,
            SavedServer.id != server_id
        ).first()
        if existing:
            return jsonify({'error': 'A server with this name already exists'}), 400
        server.name = name
    
    if 'url' in data:
        valid, result = validate_url(data['url'])
        if not valid:
            return jsonify({'error': result}), 400
        server.url = result
    
    if 'username' in data:
        if not data['username'].strip():
            return jsonify({'error': 'Username is required'}), 400
        server.username = data['username'].strip()
    
    if 'password' in data and data['password']:
        server.set_password(data['password'], secret_key)
    
    if 'use_2fa' in data:
        server.use_2fa = data['use_2fa']
        if not data['use_2fa']:
            server.totp_secret_encrypted = None
            server.totp_mode = 'token'
    
    if 'totp_mode' in data and server.use_2fa:
        server.totp_mode = data['totp_mode']
    
    if 'totp_secret' in data and server.use_2fa and server.totp_mode == 'secret':
        if data['totp_secret']:
            server.set_totp_secret(data['totp_secret'], secret_key)
    
    db.session.commit()
    
    AuditLog.log(
        AuditLog.EVENT_SERVER_UPDATED,
        user_id=session.get('user_id'),
        username=session.get('username'),
        details=f"Updated server: {server.name} ({server.url})",
        ip_address=get_client_ip(),
        user_agent=get_user_agent()
    )
    
    return jsonify({
        'success': True,
        'server': server.to_dict(),
        'message': 'Server updated successfully'
    })


@kuma_bp.route('/api/servers/<int:server_id>', methods=['DELETE'])
@login_required
def api_delete_server(server_id):
    """Delete a saved server connection."""
    server = SavedServer.query.filter_by(
        id=server_id,
        user_id=session['user_id']
    ).first()
    
    if not server:
        return jsonify({'error': 'Server not found'}), 404
    
    server_name = server.name
    db.session.delete(server)
    db.session.commit()
    
    AuditLog.log(
        AuditLog.EVENT_SERVER_DELETED,
        user_id=session.get('user_id'),
        username=session.get('username'),
        details=f"Deleted server: {server_name}",
        ip_address=get_client_ip(),
        user_agent=get_user_agent()
    )
    
    return jsonify({
        'success': True,
        'message': 'Server deleted successfully'
    })


@kuma_bp.route('/api/servers/<int:server_id>/connect', methods=['POST'])
@login_required
@limiter.limit("10 per minute")
def api_connect_to_server(server_id):
    """Connect to a saved server."""
    from flask import current_app
    import logging
    logger = logging.getLogger('gunicorn.error')
    
    logger.info(f"[CONNECT] Attempting to connect to server_id={server_id}")
    
    server = SavedServer.query.filter_by(
        id=server_id,
        user_id=session['user_id']
    ).first()
    
    if not server:
        logger.warning(f"[CONNECT] Server {server_id} not found")
        return jsonify({'error': 'Server not found'}), 404
    
    logger.info(f"[CONNECT] Found server: {server.name} at {server.url}, use_2fa={server.use_2fa}, totp_mode={server.totp_mode}")
    
    data = request.get_json() or {}
    totp_token = data.get('totp_token', '').strip()
    
    secret_key = current_app.config['SECRET_KEY']
    
    try:
        password = server.get_password(secret_key)
        logger.info("[CONNECT] Password decrypted successfully")
    except Exception as e:
        logger.error(f"[CONNECT] Failed to decrypt password: {e}")
        return jsonify({'error': 'Failed to decrypt credentials'}), 500
    
    totp_secret = ''
    if server.use_2fa and server.totp_mode == 'secret':
        try:
            totp_secret = server.get_totp_secret(secret_key)
            logger.info("[CONNECT] TOTP secret decrypted successfully")
        except Exception as e:
            logger.error(f"[CONNECT] Failed to decrypt TOTP secret: {e}")
            return jsonify({'error': 'Failed to decrypt TOTP secret'}), 500
    
    # If 2FA is enabled with token mode, require token
    if server.use_2fa and server.totp_mode == 'token' and not totp_token:
        logger.info("[CONNECT] 2FA token required but not provided")
        return jsonify({
            'error': 'TOTP token required',
            'needs_token': True,
            'server_name': server.name
        }), 400
    
    # Connect
    logger.info(f"[CONNECT] Connecting to {server.url} as {server.username}")
    service = get_kuma_service()
    success, error = service.connect(
        url=server.url,
        username=server.username,
        password=password,
        use_2fa=server.use_2fa,
        totp_token=totp_token,
        totp_secret=totp_secret
    )
    
    if not success:
        logger.error(f"[CONNECT] Connection failed: {error}")
        return jsonify({'error': f'Connection failed: {error}'}), 401
    
    logger.info("[CONNECT] Connection successful!")
    
    # Store connection info in session
    session['kuma_connected'] = True
    session['kuma_url'] = server.url
    session['kuma_server_name'] = server.name
    session['kuma_username'] = server.username
    session['kuma_password'] = password
    session['kuma_use_2fa'] = server.use_2fa
    session['kuma_totp_mode'] = server.totp_mode
    session['kuma_totp_secret'] = totp_secret
    
    # Update last used
    server.last_used = db.func.now()
    db.session.commit()
    
    AuditLog.log(
        AuditLog.EVENT_KUMA_CONNECT,
        user_id=session.get('user_id'),
        username=session.get('username'),
        details=f"Connected via saved server: {server.name} ({server.url})",
        ip_address=get_client_ip(),
        user_agent=get_user_agent()
    )
    
    return jsonify({
        'success': True,
        'message': f'Connected to {server.name}',
        'redirect': url_for('main.editor')
    })


@kuma_bp.route('/api/servers/export', methods=['GET'])
@login_required
def api_export_servers():
    """Export saved servers as JSON (without sensitive data by default)."""
    import json
    from datetime import datetime
    
    include_credentials = request.args.get('include_credentials', 'false').lower() == 'true'
    
    servers = SavedServer.query.filter_by(user_id=session['user_id']).order_by(SavedServer.name).all()
    
    export_data = {
        'version': '1.0',
        'exported_at': datetime.utcnow().isoformat() + 'Z',
        'include_credentials': include_credentials,
        'servers': []
    }
    
    for server in servers:
        server_data = {
            'name': server.name,
            'url': server.url,
            'username': server.username,
            'use_2fa': server.use_2fa,
            'totp_mode': server.totp_mode if server.use_2fa else None
        }
        
        if include_credentials:
            # Include encrypted credentials - user must know the app's secret key to decrypt
            # This is intentionally left as encrypted data to prevent exposure
            server_data['_warning'] = 'Credentials are included but encrypted. They require the same SECRET_KEY to be used on import.'
            server_data['password_encrypted'] = server.password_encrypted
            if server.totp_secret_encrypted:
                server_data['totp_secret_encrypted'] = server.totp_secret_encrypted
        
        export_data['servers'].append(server_data)
    
    AuditLog.log(
        'servers_exported',
        user_id=session.get('user_id'),
        username=session.get('username'),
        details=f"Exported {len(servers)} servers (credentials: {include_credentials})",
        ip_address=get_client_ip(),
        user_agent=get_user_agent()
    )
    
    response = app.response_class(
        response=json.dumps(export_data, indent=2),
        status=200,
        mimetype='application/json'
    )
    response.headers['Content-Disposition'] = f'attachment; filename=kuma-servers-export-{datetime.utcnow().strftime("%Y%m%d-%H%M%S")}.json'
    return response


@kuma_bp.route('/api/servers/import', methods=['POST'])
@login_required
@limiter.limit("10 per minute")
def api_import_servers():
    """Import servers from JSON export file."""
    import json
    from flask import current_app
    
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        # Validate format
        if 'servers' not in data or not isinstance(data['servers'], list):
            return jsonify({'error': 'Invalid export file format'}), 400
        
        imported_count = 0
        skipped_count = 0
        errors = []
        
        for i, server_data in enumerate(data['servers']):
            try:
                name = sanitize_string(server_data.get('name', '')).strip()
                url = server_data.get('url', '').strip()
                username = server_data.get('username', '').strip()
                
                if not name or not url or not username:
                    errors.append(f"Server {i+1}: Missing required fields (name, url, username)")
                    skipped_count += 1
                    continue
                
                # Check if server with same name already exists
                existing = SavedServer.query.filter_by(
                    user_id=session['user_id'],
                    name=name
                ).first()
                
                if existing:
                    errors.append(f"Server '{name}': Already exists (skipped)")
                    skipped_count += 1
                    continue
                
                # Check if credentials are included
                has_credentials = 'password_encrypted' in server_data
                
                if has_credentials:
                    # Import with existing encrypted credentials (requires same SECRET_KEY)
                    new_server = SavedServer(
                        user_id=session['user_id'],
                        name=name,
                        url=url,
                        username=username,
                        password_encrypted=server_data['password_encrypted'],
                        use_2fa=server_data.get('use_2fa', False),
                        totp_mode=server_data.get('totp_mode', 'token'),
                        totp_secret_encrypted=server_data.get('totp_secret_encrypted')
                    )
                else:
                    # Import without credentials - user will need to set password manually
                    # Use a placeholder that will fail on connect
                    placeholder_password = SavedServer.encrypt_value('__IMPORT_NEEDS_PASSWORD__', current_app.config['SECRET_KEY'])
                    
                    new_server = SavedServer(
                        user_id=session['user_id'],
                        name=name,
                        url=url,
                        username=username,
                        password_encrypted=placeholder_password,
                        use_2fa=server_data.get('use_2fa', False),
                        totp_mode=server_data.get('totp_mode', 'token'),
                        totp_secret_encrypted=None
                    )
                
                db.session.add(new_server)
                imported_count += 1
                
            except Exception as e:
                errors.append(f"Server {i+1}: {str(e)}")
                skipped_count += 1
        
        db.session.commit()
        
        AuditLog.log(
            'servers_imported',
            user_id=session.get('user_id'),
            username=session.get('username'),
            details=f"Imported {imported_count} servers, skipped {skipped_count}",
            ip_address=get_client_ip(),
            user_agent=get_user_agent()
        )
        
        message = f"Imported {imported_count} server(s)"
        if skipped_count > 0:
            message += f", skipped {skipped_count}"
        
        has_credentials = data.get('include_credentials', False)
        if not has_credentials and imported_count > 0:
            message += ". Note: Passwords were not included in the export. Please edit each server to set the password."
        
        return jsonify({
            'success': True,
            'message': message,
            'imported': imported_count,
            'skipped': skipped_count,
            'errors': errors if errors else None,
            'needs_passwords': not has_credentials and imported_count > 0
        })
        
    except json.JSONDecodeError:
        return jsonify({'error': 'Invalid JSON format'}), 400
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Import failed: {str(e)}'}), 500


@kuma_bp.route('/api/validate-connection', methods=['GET', 'POST'])
@kuma_connection_required
def api_validate_connection():
    """Validate that the Kuma connection is still active (JSON API)."""
    try:
        service = get_kuma_service()
        is_valid, error = service.validate_connection()
        
        if not is_valid:
            if error == "SESSION_EXPIRED":
                # Check if we need a new token (2FA with token mode)
                needs_token = session.get('kuma_use_2fa', False) and not session.get('kuma_totp_secret')
                return jsonify({
                    'valid': False,
                    'expired': True,
                    'needs_token': needs_token,
                    'message': 'Session expired. Re-authentication required.'
                }), 401
            return jsonify({
                'valid': False,
                'expired': False,
                'message': error
            }), 500
        
        return jsonify({
            'valid': True,
            'can_auto_refresh': service.can_auto_refresh()
        })
    except Exception as e:
        return jsonify({'valid': False, 'message': str(e)}), 500


@kuma_bp.route('/api/reauth', methods=['POST'])
@kuma_connection_required
@limiter.limit("10 per minute")
def api_reauth():
    """Re-authenticate with Kuma using a new TOTP token (JSON API)."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid request'}), 400
        
        totp_token = data.get('totp_token', '').strip()
        
        if not totp_token:
            return jsonify({'error': 'TOTP token is required'}), 400
        
        # Retrieve stored credentials
        url = session.get('kuma_url')
        username = session.get('kuma_username')
        password = session.get('kuma_password')
        
        if not all([url, username, password]):
            return jsonify({
                'error': 'Session credentials missing. Please reconnect.',
                'redirect': True
            }), 401
        
        # Re-connect with new token
        service = get_kuma_service()
        success, error = service.connect(
            url=url,
            username=username,
            password=password,
            use_2fa=True,
            totp_token=totp_token,
            totp_secret=session.get('kuma_totp_secret', '')
        )
        
        if not success:
            return jsonify({'error': f'Re-authentication failed: {error}'}), 401
        
        AuditLog.log(
            "KUMA_REAUTH",
            user_id=session.get('user_id'),
            username=session.get('username'),
            details=f"Re-authenticated to {url}",
            ip_address=get_client_ip(),
            user_agent=get_user_agent()
        )
        
        return jsonify({'success': True, 'message': 'Re-authentication successful'})
        
    except Exception as e:
        return jsonify({'error': f'Re-authentication failed: {str(e)}'}), 500


@kuma_bp.route('/api/monitors')
@kuma_connection_required
def api_monitors():
    """Get all monitors (JSON API)."""
    import logging
    logger = logging.getLogger('gunicorn.error')
    
    # Check if full refresh is requested
    force_refresh = request.args.get('refresh', 'false').lower() == 'true'
    
    try:
        logger.info(f"[MONITORS] Fetching monitors, session kuma_connected={session.get('kuma_connected')}, force_refresh={force_refresh}")
        service = get_kuma_service()
        logger.info(f"[MONITORS] Got service, connected={service.connected}, url={service.url}")
        
        # Clear all caches if full refresh requested - ensures fresh data pull
        if force_refresh:
            logger.info("[MONITORS] Full refresh requested - clearing all caches")
            service._clear_cache()
            # Also clear the tags and notifications caches
            service._notifications_cache = None
            service._tags_cache = None
            logger.info("[MONITORS] All caches cleared for full data pull")
        
        monitors = service.get_monitors(force_refresh=True)
        logger.info(f"[MONITORS] Fetched {len(monitors) if monitors else 0} monitors from Uptime Kuma")
        
        # Enrich with additional info
        groups = {g['id']: g['name'] for g in service.get_groups()}
        
        result = []
        for m in monitors:
            parent_id = m.get('parent')
            result.append({
                'id': m.get('id'),
                'name': m.get('name', ''),
                'type': str(m.get('type', '')),
                'url': m.get('url', ''),
                'active': m.get('active', True),
                'interval': m.get('interval'),
                'maxretries': m.get('maxretries'),
                'retryInterval': m.get('retryInterval'),
                'resendInterval': m.get('resendInterval'),
                'upsideDown': m.get('upsideDown', False),
                'tags': [t.get('name', '') for t in m.get('tags', []) if isinstance(t, dict)],
                'notifications': m.get('notificationIDList', []),
                'group': groups.get(parent_id, '') if isinstance(parent_id, int) else '',
                'groupId': parent_id if isinstance(parent_id, int) else None,
                'isGroup': service.is_group_monitor(m),
            })
        
        return jsonify({'monitors': result})
    except KumaServiceError as e:
        logger.error(f"[MONITORS] KumaServiceError: {e}")
        return jsonify({'error': str(e)}), 500
    except Exception as e:
        logger.error(f"[MONITORS] Exception: {e}")
        return jsonify({'error': f'Failed to fetch monitors: {str(e)}'}), 500


@kuma_bp.route('/api/notifications')
@kuma_connection_required
def api_notifications():
    """Get all notifications (JSON API)."""
    force_refresh = request.args.get('refresh', 'false').lower() == 'true'
    try:
        service = get_kuma_service()
        # Force refresh to ensure we get the latest notifications
        notifications = service.get_notifications(force_refresh=True)
        
        result = [{'id': n.get('id'), 'name': n.get('name', '')} for n in notifications]
        return jsonify({'notifications': result})
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': f'Failed to fetch notifications: {str(e)}'}), 500


@kuma_bp.route('/api/tags')
@kuma_connection_required
def api_tags():
    """Get all tags (JSON API)."""
    force_refresh = request.args.get('refresh', 'false').lower() == 'true'
    try:
        service = get_kuma_service()
        tags = service.get_tags(force_refresh=force_refresh)
        
        result = [{'id': t.get('id'), 'name': t.get('name', ''), 'color': t.get('color', '#4B5563')} for t in tags]
        return jsonify({'tags': result})
    except Exception as e:
        return jsonify({'error': 'Failed to fetch tags'}), 500


@kuma_bp.route('/api/groups')
@kuma_connection_required
def api_groups():
    """Get all groups (JSON API)."""
    force_refresh = request.args.get('refresh', 'false').lower() == 'true'
    try:
        service = get_kuma_service()
        # Groups come from monitors, so force refresh monitors first if requested
        if force_refresh:
            service.get_monitors(force_refresh=True)
        groups = service.get_groups()
        return jsonify({'groups': groups})
    except Exception as e:
        return jsonify({'error': 'Failed to fetch groups'}), 500


@kuma_bp.route('/api/bulk-edit', methods=['POST'])
@kuma_connection_required
@limiter.limit("10 per minute")
def api_bulk_edit():
    """Apply bulk edits to monitors (JSON API)."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid request'}), 400
        
        monitor_ids = data.get('monitor_ids', [])
        changes = data.get('changes', {})
        dry_run = data.get('dry_run', True)
        
        if not monitor_ids:
            return jsonify({'error': 'No monitors selected'}), 400
        
        if not changes:
            return jsonify({'error': 'No changes specified'}), 400
        
        service = get_kuma_service()
        
        if dry_run:
            # Return preview of changes
            monitors = service.get_monitors()
            preview = []
            for m in monitors:
                if m.get('id') in monitor_ids:
                    preview.append({
                        'id': m.get('id'),
                        'name': m.get('name'),
                        'changes': changes
                    })
            return jsonify({'preview': preview, 'count': len(preview)})
        
        # Apply changes
        success, errors, messages = service.bulk_edit(monitor_ids, changes.copy())
        
        # Log the operation
        AuditLog.log(
            AuditLog.EVENT_BULK_EDIT,
            user_id=session.get('user_id'),
            username=session.get('username'),
            details=f"Edited {success} monitors, {errors} errors. Changes: {changes}",
            ip_address=get_client_ip(),
            user_agent=get_user_agent(),
            success=(errors == 0)
        )
        
        return jsonify({
            'success': success,
            'errors': errors,
            'messages': messages
        })
    
    except KumaConnectionExpired as e:
        # Token/session expired - client needs to re-authenticate
        needs_token = session.get('kuma_use_2fa', False) and not session.get('kuma_totp_secret')
        return jsonify({
            'error': str(e),
            'session_expired': True,
            'needs_token': needs_token,
            'message': 'Your Kuma session has expired. Please re-authenticate with a new 2FA token.'
        }), 401
        
    except KumaServiceError as e:
        return jsonify({'error': str(e)}), 500
    except Exception as e:
        return jsonify({'error': f'Bulk edit failed: {str(e)}'}), 500


# ============================================================================
# System Management - Tags
# ============================================================================
@kuma_bp.route('/api/tags', methods=['POST'])
@kuma_connection_required
@limiter.limit("10 per minute")
def api_create_tag():
    """Create a new tag."""
    try:
        data = request.get_json()
        if not data or not data.get('name'):
            return jsonify({'error': 'Tag name is required'}), 400
        
        name = data.get('name').strip()
        color = data.get('color', '#4B5563')
        
        service = get_kuma_service()
        result = service.create_tag(name, color)
        
        AuditLog.log(
            AuditLog.EVENT_TAG_CREATED,
            user_id=session.get('user_id'),
            username=session.get('username'),
            details=f"Created tag: {name} (color: {color})",
            ip_address=get_client_ip(),
            user_agent=get_user_agent(),
            success=True
        )
        
        return jsonify({'success': True, 'tag': result})
    
    except KumaConnectionExpired as e:
        needs_token = session.get('kuma_use_2fa', False) and not session.get('kuma_totp_secret')
        return jsonify({
            'error': str(e),
            'session_expired': True,
            'needs_token': needs_token
        }), 401
    except KumaServiceError as e:
        return jsonify({'error': str(e)}), 500
    except Exception as e:
        return jsonify({'error': f'Failed to create tag: {str(e)}'}), 500


@kuma_bp.route('/api/tags/<int:tag_id>', methods=['DELETE'])
@kuma_connection_required
@limiter.limit("10 per minute")
def api_delete_tag(tag_id):
    """Delete a tag."""
    try:
        service = get_kuma_service()
        service.delete_tag(tag_id)
        
        AuditLog.log(
            AuditLog.EVENT_TAG_DELETED,
            user_id=session.get('user_id'),
            username=session.get('username'),
            details=f"Deleted tag ID: {tag_id}",
            ip_address=get_client_ip(),
            user_agent=get_user_agent(),
            success=True
        )
        
        return jsonify({'success': True})
    
    except KumaConnectionExpired as e:
        needs_token = session.get('kuma_use_2fa', False) and not session.get('kuma_totp_secret')
        return jsonify({
            'error': str(e),
            'session_expired': True,
            'needs_token': needs_token
        }), 401
    except KumaServiceError as e:
        return jsonify({'error': str(e)}), 500
    except Exception as e:
        return jsonify({'error': f'Failed to delete tag: {str(e)}'}), 500


# ============================================================================
# System Management - Groups
# ============================================================================
@kuma_bp.route('/api/groups', methods=['POST'])
@kuma_connection_required
@limiter.limit("10 per minute")
def api_create_group():
    """Create a new monitor group."""
    try:
        data = request.get_json()
        if not data or not data.get('name'):
            return jsonify({'error': 'Group name is required'}), 400
        
        name = data.get('name').strip()
        
        service = get_kuma_service()
        result = service.create_group(name)
        
        AuditLog.log(
            AuditLog.EVENT_GROUP_CREATED,
            user_id=session.get('user_id'),
            username=session.get('username'),
            details=f"Created group: {name}",
            ip_address=get_client_ip(),
            user_agent=get_user_agent(),
            success=True
        )
        
        return jsonify({'success': True, 'group': result})
    
    except KumaConnectionExpired as e:
        needs_token = session.get('kuma_use_2fa', False) and not session.get('kuma_totp_secret')
        return jsonify({
            'error': str(e),
            'session_expired': True,
            'needs_token': needs_token
        }), 401
    except KumaServiceError as e:
        return jsonify({'error': str(e)}), 500
    except Exception as e:
        return jsonify({'error': f'Failed to create group: {str(e)}'}), 500


@kuma_bp.route('/api/groups/<int:group_id>', methods=['DELETE'])
@kuma_connection_required
@limiter.limit("10 per minute")
def api_delete_group(group_id):
    """Delete a monitor group."""
    try:
        service = get_kuma_service()
        service.delete_group(group_id)
        
        AuditLog.log(
            AuditLog.EVENT_GROUP_DELETED,
            user_id=session.get('user_id'),
            username=session.get('username'),
            details=f"Deleted group ID: {group_id}",
            ip_address=get_client_ip(),
            user_agent=get_user_agent(),
            success=True
        )
        
        return jsonify({'success': True})
    
    except KumaConnectionExpired as e:
        needs_token = session.get('kuma_use_2fa', False) and not session.get('kuma_totp_secret')
        return jsonify({
            'error': str(e),
            'session_expired': True,
            'needs_token': needs_token
        }), 401
    except KumaServiceError as e:
        return jsonify({'error': str(e)}), 500
    except Exception as e:
        return jsonify({'error': f'Failed to delete group: {str(e)}'}), 500


# ============================================================================
# Bulk Operations
# ============================================================================
@kuma_bp.route('/api/delete-monitors', methods=['POST'])
@kuma_connection_required
@limiter.limit("5 per minute")
def api_delete_monitors():
    """Delete multiple monitors (JSON API)."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid request'}), 400
        
        monitor_ids = data.get('monitor_ids', [])
        
        if not monitor_ids:
            return jsonify({'error': 'No monitors selected'}), 400
        
        service = get_kuma_service()
        
        # Delete monitors one by one
        success = 0
        errors = 0
        messages = []
        
        for mid in monitor_ids:
            try:
                service.delete_monitor(mid)
                success += 1
            except Exception as e:
                errors += 1
                messages.append(f"Monitor {mid}: {str(e)}")
        
        # Log the operation
        AuditLog.log(
            AuditLog.EVENT_MONITORS_DELETED,
            user_id=session.get('user_id'),
            username=session.get('username'),
            details=f"Deleted {success} monitors, {errors} errors. IDs: {monitor_ids}",
            ip_address=get_client_ip(),
            user_agent=get_user_agent(),
            success=(errors == 0)
        )
        
        return jsonify({
            'success': success,
            'errors': errors,
            'messages': messages
        })
    
    except KumaConnectionExpired as e:
        # Token/session expired - client needs to re-authenticate
        needs_token = session.get('kuma_use_2fa', False) and not session.get('kuma_totp_secret')
        return jsonify({
            'error': str(e),
            'session_expired': True,
            'needs_token': needs_token,
            'message': 'Your Kuma session has expired. Please re-authenticate with a new 2FA token.'
        }), 401
        
    except KumaServiceError as e:
        return jsonify({'error': str(e)}), 500
    except Exception as e:
        return jsonify({'error': f'Delete failed: {str(e)}'}), 500


# ============================================================================
# Main Blueprint - Dashboard and Editor
# ============================================================================
main_bp = Blueprint('main', __name__)


@main_bp.route('/')
@login_required
def index():
    """Main dashboard / redirect."""
    if session.get('kuma_connected'):
        return redirect(url_for('main.editor'))
    return redirect(url_for('kuma.connect'))


@main_bp.route('/editor')
@kuma_connection_required
def editor():
    """Bulk editor interface."""
    return render_template('editor.html',
        kuma_url=session.get('kuma_url'),
        kuma_server_name=session.get('kuma_server_name'),
        kuma_username=session.get('kuma_username'))


# ============================================================================
# Error handlers
# ============================================================================
def register_error_handlers(app):
    """Register error handlers."""
    
    @app.errorhandler(404)
    def not_found(e):
        return render_template('error.html', 
            error="Page Not Found", 
            message="The page you're looking for doesn't exist."), 404
    
    @app.errorhandler(500)
    def server_error(e):
        return render_template('error.html',
            error="Server Error",
            message="Something went wrong. Please try again later."), 500
    
    @app.errorhandler(429)
    def rate_limited(e):
        return render_template('error.html',
            error="Too Many Requests",
            message="Please slow down and try again in a moment."), 429


# ============================================================================
# Run
# ============================================================================
app = create_app()
register_error_handlers(app)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
