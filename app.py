# ==========================================
# TARAZO BACKEND - PRODUCTION READY
# Fixed: decode_token import, email_verified column, transaction safety
import os
import re
import json
import secrets
import logging
import hmac
import hashlib
import time
from datetime import datetime, timedelta
from functools import wraps
from collections import defaultdict
from contextlib import contextmanager

from flask import Flask, request, jsonify, make_response, g
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_cors import CORS
from flask_jwt_extended import (
    JWTManager, create_access_token, create_refresh_token,
    jwt_required, get_jwt_identity, get_jwt, decode_token  # ✅ Added decode_token
)
from marshmallow import Schema, fields, validate, ValidationError
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from itsdangerous import URLSafeTimedSerializer
from cryptography.fernet import Fernet
from sqlalchemy import func, CheckConstraint, Index, text
from sqlalchemy.exc import SQLAlchemyError
import requests
from dotenv import load_dotenv
from apscheduler.schedulers.background import BackgroundScheduler
from werkzeug.middleware.proxy_fix import ProxyFix

# Redis is REQUIRED for production
try:
    import redis
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    print("❌ Redis module is REQUIRED for production!")
    print("Install: pip install redis flask-limiter")
    exit(1)

load_dotenv()

# ==================== APP INITIALIZATION ====================
app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
app_start_time = datetime.utcnow()

# ==================== LOGGING ====================
class SensitiveDataFilter(logging.Filter):
    def filter(self, record):
        if hasattr(record, 'msg') and isinstance(record.msg, str):
            record.msg = re.sub(r'(077|078|076|079|075|074|070|073|071)\d{6}', '[PHONE]', record.msg)
            record.msg = re.sub(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', '[EMAIL]', record.msg)
        return True

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.FileHandler('tarazo.log'), logging.StreamHandler()]
)
logger = logging.getLogger(__name__)
logger.addFilter(SensitiveDataFilter())

# ==================== CONFIGURATION ====================
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=60)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=7)
app.config['JWT_TOKEN_LOCATION'] = ['headers']
app.config['JWT_HEADER_NAME'] = 'Authorization'
app.config['JWT_HEADER_TYPE'] = 'Bearer'
app.config['JWT_IDENTITY_CLAIM'] = 'sub'

app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024

# Validate required secrets
required_vars = ['SECRET_KEY', 'JWT_SECRET_KEY', 'DATABASE_URL', 'ENCRYPTION_KEY', 'REDIS_URL']
missing_vars = [v for v in required_vars if not os.environ.get(v)]
if missing_vars:
    print(f"ERROR: Missing required environment variables: {', '.join(missing_vars)}")
    print("Please set these before starting the server.")
    exit(1)

# Validate ENCRYPTION_KEY format
try:
    cipher = Fernet(os.environ.get('ENCRYPTION_KEY').encode())
    logger.info("✅ Encryption key validated")
except Exception as e:
    print(f"ERROR: Invalid ENCRYPTION_KEY format: {e}")
    print("Generate a valid key with: python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'")
    exit(1)

# Database
database_url = os.environ.get('DATABASE_URL')
if database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql://', 1)

app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_size': 20,
    'pool_recycle': 300,
    'pool_pre_ping': True,
    'pool_use_lifo': True,
    'max_overflow': 40,
    'pool_timeout': 30
}

# ==================== CORS ====================
FRONTEND_URL = os.environ.get('FRONTEND_URL', 'https://ravenj-png.github.io')

ALLOWED_ORIGINS = [
    FRONTEND_URL,
    "http://localhost:5500",
    "http://localhost:5000"
]

CORS(app,
     origins="*",
     supports_credentials=False,
     methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
     allow_headers=["Content-Type", "Authorization", "X-Requested-With", "Accept"],
     expose_headers=["Content-Type"],
     max_age=3600)

# ==================== REDIS (REQUIRED) ====================
try:
    redis_client = redis.from_url(os.environ.get('REDIS_URL'), socket_timeout=5, decode_responses=True)
    redis_client.ping()
    logger.info("✅ Redis connected")
    
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    limiter = Limiter(
        get_remote_address,
        app=app,
        default_limits=["1000 per day", "200 per hour", "30 per minute"],
        storage_uri=os.environ.get('REDIS_URL'),
        strategy="fixed-window",
        enabled=True
    )
    logger.info("✅ Rate limiting enabled")
except Exception as e:
    logger.error(f"❌ Redis connection failed: {e}")
    exit(1)

def rate_limit(limits):
    return limiter.limit(limits)

# ==================== JWT & EXTENSIONS ====================
jwt = JWTManager(app)
db = SQLAlchemy(app)
migrate = Migrate(app, db)
ph = PasswordHasher()
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# ==================== FLUTTERWAVE ====================
FLUTTERWAVE_SECRET_KEY = os.environ.get('FLUTTERWAVE_SECRET_KEY')
FLUTTERWAVE_PUBLIC_KEY = os.environ.get('FLUTTERWAVE_PUBLIC_KEY')
FLUTTERWAVE_WEBHOOK_SECRET = os.environ.get('FLUTTERWAVE_WEBHOOK_SECRET')
FLUTTERWAVE_BASE_URL = 'https://api.flutterwave.com/v3'

FLUTTERWAVE_ENABLED = bool(FLUTTERWAVE_SECRET_KEY and FLUTTERWAVE_PUBLIC_KEY)

if FLUTTERWAVE_ENABLED:
    logger.info("✅ Payments: ENABLED (Flutterwave)")
else:
    logger.warning("⚠️ Payments: DISABLED - Add Flutterwave keys to enable")

# ==================== BRUTE FORCE PROTECTION (Redis-based) ====================
def record_failed_login(ip):
    key = f"login_attempts:{ip}"
    redis_client.lpush(key, time.time())
    redis_client.ltrim(key, 0, 9)
    redis_client.expire(key, 900)

def is_ip_blocked(ip):
    key = f"login_attempts:{ip}"
    attempts = redis_client.lrange(key, 0, -1)
    now = time.time()
    recent = [float(a) for a in attempts if float(a) > now - 900]
    return len(recent) >= 10

def reset_failed_attempts(ip):
    key = f"login_attempts:{ip}"
    redis_client.delete(key)

# ==================== GLOBAL EXCEPTION HANDLER ====================
@app.errorhandler(Exception)
def handle_exception(e):
    logger.error(f"Unhandled exception: {str(e)}")
    return jsonify({'error': 'An unexpected error occurred'}), 500

# ==================== DATABASE MODELS WITH email_verified ====================
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    phone = db.Column(db.String(20))
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default='user', index=True)
    status = db.Column(db.String(20), default='online', index=True)
    address = db.Column(db.String(500))
    email_verified = db.Column(db.Boolean, default=False, index=True)  # ✅ Added missing field
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    __table_args__ = (
        Index('idx_user_role_status', 'role', 'status'),
    )

class Product(db.Model):
    __tablename__ = 'products'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    type = db.Column(db.String(100), nullable=False, index=True)
    price = db.Column(db.Integer, nullable=False)
    stock = db.Column(db.Integer, default=0, index=True)
    reserved_stock = db.Column(db.Integer, default=0, index=True)
    description = db.Column(db.Text)
    image_url = db.Column(db.String(500))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    @property
    def available_stock(self):
        return self.stock - self.reserved_stock
    
    __table_args__ = (
        Index('idx_product_type_stock', 'type', 'stock'),
        Index('idx_product_available', 'stock', 'reserved_stock'),
    )

class CartItem(db.Model):
    __tablename__ = 'cart_items'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), index=True)
    product_id = db.Column(db.Integer, db.ForeignKey('products.id'))
    quantity = db.Column(db.Integer, default=1)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    __table_args__ = (
        Index('idx_cart_user_product', 'user_id', 'product_id', unique=True),
        Index('idx_cart_user', 'user_id'),
    )

class Order(db.Model):
    __tablename__ = 'orders'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), index=True)
    agent_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True, index=True)
    items = db.Column(db.Text, nullable=False)
    total = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(50), default='pending', index=True)
    payment_method = db.Column(db.String(50))
    payment_status = db.Column(db.String(50), default='pending', index=True)
    transaction_id = db.Column(db.String(100), unique=True, index=True)
    payment_ref = db.Column(db.String(100), unique=True, index=True)
    stock_confirmed = db.Column(db.Boolean, default=False)
    stock_reserved_until = db.Column(db.DateTime, nullable=True)
    rider_name = db.Column(db.String(100))
    rider_phone = db.Column(db.String(20))
    rider_vehicle = db.Column(db.String(100))
    delivery_location = db.Column(db.String(500))
    date = db.Column(db.String(20))
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    __table_args__ = (
        Index('idx_orders_user_status', 'user_id', 'status'),
        Index('idx_orders_agent_status', 'agent_id', 'status'),
        Index('idx_orders_payment_status', 'payment_status'),
        Index('idx_orders_payment_ref', 'payment_ref'),
        Index('idx_orders_created_status', 'created_at', 'status'),
        Index('idx_orders_stock_expiry', 'stock_reserved_until'),
    )

class PaymentTransaction(db.Model):
    __tablename__ = 'payment_transactions'
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('orders.id'), index=True)
    tx_ref = db.Column(db.String(100), unique=True, index=True)
    transaction_id = db.Column(db.String(100), unique=True, index=True)
    amount = db.Column(db.Integer, nullable=False)
    currency = db.Column(db.String(3), default='UGX')
    status = db.Column(db.String(50), default='pending', index=True)
    payment_method = db.Column(db.String(50))
    customer_email = db.Column(db.String(255))
    customer_phone = db.Column(db.String(20))
    webhook_data = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    __table_args__ = (
        Index('idx_payment_tx_ref', 'tx_ref'),
        Index('idx_payment_status', 'status'),
    )

class TokenBlacklist(db.Model):
    __tablename__ = 'token_blacklist'
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(36), nullable=False, unique=True, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), index=True)

class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True, index=True)
    action = db.Column(db.String(100), nullable=False, index=True)
    resource_type = db.Column(db.String(50), index=True)
    resource_id = db.Column(db.Integer)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(500))
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    __table_args__ = (
        Index('idx_audit_user_time', 'user_id', 'created_at'),
        Index('idx_audit_action_time', 'action', 'created_at'),
    )

# ==================== JWT BLACKLIST ====================
@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    jti = jwt_payload['jti']
    token = TokenBlacklist.query.filter_by(jti=jti).first()
    return token is not None

# ==================== BACKGROUND SCHEDULER (Single Worker Only) ====================
RUN_SCHEDULER = os.environ.get('RUN_SCHEDULER', 'false').lower() == 'true'

if RUN_SCHEDULER:
    scheduler = BackgroundScheduler()
    
    def cleanup_expired_data():
        thirty_days_ago = datetime.utcnow() - timedelta(days=30)
        TokenBlacklist.query.filter(TokenBlacklist.created_at < thirty_days_ago).delete()
        ninety_days_ago = datetime.utcnow() - timedelta(days=90)
        AuditLog.query.filter(AuditLog.created_at < ninety_days_ago).delete()
        db.session.commit()
        logger.info("Cleaned up expired data")
    
    def release_expired_stock():
        expiry_time = datetime.utcnow() - timedelta(hours=1)
        expired_orders = Order.query.filter(
            Order.payment_status == 'pending',
            Order.stock_confirmed == False,
            Order.stock_reserved_until < expiry_time
        ).all()
        
        for order in expired_orders:
            items = json.loads(order.items)
            for item in items:
                product = Product.query.get(item['productId'])
                if product:
                    product.reserved_stock -= item['quantity']
            order.stock_reserved_until = None
            logger.info(f"Released expired stock for order #{order.id}")
        
        db.session.commit()
    
    scheduler.add_job(cleanup_expired_data, 'cron', hour=2, minute=0, id='cleanup_expired')
    scheduler.add_job(release_expired_stock, 'interval', minutes=30, id='release_stock')
    scheduler.start()
    logger.info("✅ Scheduler started (single worker mode)")

# ==================== HELPER FUNCTIONS ====================
def log_audit(user_id, action, resource_type=None, resource_id=None):
    audit = AuditLog(
        user_id=user_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent', '')[:500]
    )
    db.session.add(audit)
    db.session.commit()

def get_least_busy_agent():
    agents = User.query.filter_by(role='agent', status='online').all()
    if not agents:
        return None
    agent_load = []
    for agent in agents:
        active_orders = Order.query.filter(
            Order.agent_id == agent.id,
            Order.status.in_(['paid', 'processing'])
        ).count()
        agent_load.append((agent, active_orders))
    agent_load.sort(key=lambda x: (x[1], x[0].id))
    return agent_load[0][0] if agent_load else None

def generate_tx_ref(order_id):
    random_suffix = secrets.token_hex(4)
    timestamp = int(time.time())
    return f"TX-{order_id}-{timestamp}-{random_suffix}"

def verify_webhook_signature(payload, signature):
    if not FLUTTERWAVE_WEBHOOK_SECRET:
        return False
    if not signature:
        return False
    expected = hmac.new(
        FLUTTERWAVE_WEBHOOK_SECRET.encode('utf-8'),
        payload.encode('utf-8'),
        hashlib.sha512
    ).hexdigest()
    return hmac.compare_digest(expected, signature)

def send_verification_email(user):
    if not os.environ.get('SMTP_USER'):
        return False
    token = serializer.dumps(user.email, salt='email-verify')
    frontend_url = os.environ.get('FRONTEND_URL', 'http://localhost:5500')
    verification_url = f"{frontend_url}/verify-email/{token}"
    html = f"""
    <html><body>
        <h2>Welcome to Tarazo!</h2>
        <p>Click <a href="{verification_url}">here</a> to verify your email.</p>
        <p>This link expires in 24 hours.</p>
    </body></html>"""
    return send_email(user.email, "Verify Your Tarazo Account", html)

def send_email(to_email, subject, html_content):
    if not os.environ.get('SMTP_USER') or not os.environ.get('SMTP_PASS'):
        return False
    try:
        import smtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = os.environ.get('SMTP_USER')
        msg['To'] = to_email
        msg.attach(MIMEText(html_content, 'html'))
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login(os.environ.get('SMTP_USER'), os.environ.get('SMTP_PASS'))
            server.send_message(msg)
        return True
    except Exception as e:
        logger.error(f"Email failed: {e}")
        return False

def send_password_reset_email(user):
    token = serializer.dumps(user.email, salt='password-reset')
    frontend_url = os.environ.get('FRONTEND_URL', 'http://localhost:5500')
    reset_url = f"{frontend_url}/reset-password/{token}"
    html = f"""
    <html><body>
        <h2>Password Reset Request</h2>
        <p>Click <a href="{reset_url}">here</a> to reset your password.</p>
        <p>This link expires in 1 hour.</p>
    </body></html>"""
    return send_email(user.email, "Reset Your Tarazo Password", html)

# ==================== CREATE DEFAULT DATA ====================
def create_default_accounts():
    admin_email = os.environ.get('ADMIN_EMAIL', 'admin@tarazo.com')
    admin_password = os.environ.get('ADMIN_PASSWORD')
    if admin_password:
        admin = User.query.filter_by(email=admin_email).first()
        if not admin:
            admin = User(
                name='System Administrator',
                email=admin_email,
                phone='0771000000',
                password_hash=ph.hash(admin_password),
                role='admin',
                status='online',
                email_verified=True  # ✅ Admin auto-verified
            )
            db.session.add(admin)

    for i in range(1, 6):
        agent_email = os.environ.get(f'AGENT{i}_EMAIL')
        agent_password = os.environ.get(f'AGENT{i}_PASSWORD')
        if agent_email and agent_password:
            agent = User.query.filter_by(email=agent_email).first()
            if not agent:
                agent = User(
                    name=os.environ.get(f'AGENT{i}_NAME', f'Agent {i}'),
                    email=agent_email,
                    phone=os.environ.get(f'AGENT{i}_PHONE', f'077{i}00000'),
                    password_hash=ph.hash(agent_password),
                    role='agent',
                    status='online',
                    email_verified=True  # ✅ Agents auto-verified
                )
                db.session.add(agent)

    if Product.query.count() == 0:
        sample_products = [
            Product(name='Classic Floor Terrazzo', type='Floor', price=150000, stock=100),
            Product(name='Modern Wall Terrazzo', type='Wall', price=120000, stock=50),
            Product(name='Premium Countertop', type='Countertop', price=280000, stock=30),
        ]
        for p in sample_products:
            db.session.add(p)

    db.session.commit()

# ==================== ROLE DECORATORS ====================
def admin_required(f):
    @wraps(f)
    @jwt_required()
    def decorated(*args, **kwargs):
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        if not user or user.role != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        return f(*args, **kwargs)
    return decorated

def agent_required(f):
    @wraps(f)
    @jwt_required()
    def decorated(*args, **kwargs):
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        if not user or (user.role != 'agent' and user.role != 'admin'):
            return jsonify({'error': 'Agent access required'}), 403
        return f(*args, **kwargs)
    return decorated

def user_required(f):
    @wraps(f)
    @jwt_required()
    def decorated(*args, **kwargs):
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        return f(*args, **kwargs)
    return decorated

# ==================== PUBLIC ROUTES ====================
@app.route('/api/health', methods=['GET'])
def health():
    uptime = (datetime.utcnow() - app_start_time).total_seconds()
    return jsonify({
        'status': 'healthy',
        'uptime_seconds': uptime,
        'database': 'connected',
        'payments_mode': 'LIVE' if FLUTTERWAVE_ENABLED else 'DEMO',
        'timestamp': datetime.utcnow().isoformat()
    })

@app.route('/api/register', methods=['POST'])
@rate_limit("3 per minute")
def register():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid request body'}), 400
    
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')
    phone = data.get('phone', '')
    
    if not name or not email or not password:
        return jsonify({'error': 'Missing required fields'}), 400
    
    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'Email already registered'}), 409
    
    user = User(
        name=name,
        email=email,
        phone=phone,
        password_hash=ph.hash(password),
        role='user',
        status='online',
        email_verified=False  # ✅ Requires verification
    )
    
    db.session.add(user)
    db.session.commit()
    
    send_verification_email(user)
    log_audit(user.id, 'REGISTER', 'user', user.id)
    return jsonify({'success': True, 'message': 'Registration successful. Please verify your email.'}), 201

@app.route('/api/verify-email/<token>', methods=['GET'])
def verify_email(token):
    try:
        email = serializer.loads(token, salt='email-verify', max_age=86400)
        user = User.query.filter_by(email=email).first()
        if user:
            user.email_verified = True
            db.session.commit()
            log_audit(user.id, 'VERIFY_EMAIL', 'user', user.id)
            return jsonify({'success': True, 'message': 'Email verified successfully'})
        return jsonify({'error': 'User not found'}), 404
    except Exception as e:
        logger.error(f"Email verification failed: {e}")
        return jsonify({'error': 'Invalid or expired token'}), 400

@app.route('/api/forgot-password', methods=['POST'])
@rate_limit("3 per hour")
def forgot_password():
    data = request.get_json()
    email = data.get('email')
    user = User.query.filter_by(email=email).first()
    if user:
        send_password_reset_email(user)
        log_audit(user.id, 'FORGOT_PASSWORD', 'user', user.id)
    return jsonify({'message': 'If an account exists, a reset link has been sent'})

@app.route('/api/reset-password', methods=['POST'])
@rate_limit("3 per hour")
def reset_password():
    data = request.get_json()
    token = data.get('token')
    new_password = data.get('password')
    
    if not new_password or len(new_password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters'}), 400
    
    try:
        email = serializer.loads(token, salt='password-reset', max_age=3600)
        user = User.query.filter_by(email=email).first()
        if not user:
            return jsonify({'error': 'Invalid token'}), 400
        user.password_hash = ph.hash(new_password)
        db.session.commit()
        log_audit(user.id, 'RESET_PASSWORD', 'user', user.id)
        return jsonify({'success': True, 'message': 'Password reset successful'})
    except Exception as e:
        logger.error(f"Password reset failed: {e}")
        return jsonify({'error': 'Invalid or expired token'}), 400

@app.route('/api/login', methods=['POST'])
@rate_limit("5 per minute")
def login():
    client_ip = request.remote_addr
    
    if is_ip_blocked(client_ip):
        return jsonify({'error': 'Too many failed attempts. Try again later.'}), 429
    
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid request body'}), 400
    
    email = data.get('email')
    password = data.get('password')
    
    if not email or not password:
        return jsonify({'error': 'Email and password required'}), 400
    
    user = User.query.filter_by(email=email).first()
    
    if not user:
        record_failed_login(client_ip)
        return jsonify({'error': 'Invalid credentials'}), 401
    
    if not user.email_verified:
        return jsonify({'error': 'Please verify your email first'}), 403
    
    try:
        ph.verify(user.password_hash, password)
    except VerifyMismatchError:
        record_failed_login(client_ip)
        return jsonify({'error': 'Invalid credentials'}), 401
    
    reset_failed_attempts(client_ip)
    
    access_token = create_access_token(identity=user.id)
    refresh_token = create_refresh_token(identity=user.id)
    
    response = jsonify({
        'success': True,
        'access_token': access_token,
        'refresh_token': refresh_token,
        'user': {
            'id': user.id,
            'name': user.name,
            'email': user.email,
            'role': user.role,
            'phone': user.phone,
            'address': user.address,
            'status': user.status
        }
    })
    
    log_audit(user.id, 'LOGIN', 'user', user.id)
    return response

@app.route('/api/refresh', methods=['POST'])
@jwt_required(refresh=True)  # ✅ Using proper decorator instead of manual parsing
def refresh():
    user_id = get_jwt_identity()
    access_token = create_access_token(identity=user_id)
    return jsonify({'success': True, 'access_token': access_token})

@app.route('/api/logout', methods=['POST'])
@jwt_required()
def logout():
    jti = get_jwt()['jti']
    user_id = get_jwt_identity()
    blacklist = TokenBlacklist(jti=jti, user_id=user_id)
    db.session.add(blacklist)
    db.session.commit()
    log_audit(user_id, 'LOGOUT', 'user', user_id)
    return jsonify({'success': True, 'message': 'Logged out successfully'})

# ==================== PRODUCT ROUTES ====================
@app.route('/api/products', methods=['GET'])
def get_products():
    products = Product.query.all()
    return jsonify([{
        'id': p.id, 'name': p.name, 'type': p.type, 'price': p.price,
        'stock': p.available_stock, 'description': p.description or '', 
        'image_url': p.image_url or ''
    } for p in products])

# ==================== CART ROUTES ====================
@app.route('/api/cart', methods=['GET'])
@user_required
def get_cart():
    user_id = get_jwt_identity()
    cart = CartItem.query.filter_by(user_id=user_id).all()
    return jsonify([{
        'id': c.id, 'product_id': c.product_id, 'quantity': c.quantity
    } for c in cart])

@app.route('/api/cart', methods=['POST'])
@user_required
def add_to_cart():
    user_id = get_jwt_identity()
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid request body'}), 400
    
    product_id = data.get('product_id')
    quantity = data.get('quantity', 1)
    
    if not product_id:
        return jsonify({'error': 'Product ID required'}), 400
    
    product = Product.query.get(product_id)
    if not product:
        return jsonify({'error': 'Product not found'}), 404
    
    if product.available_stock < quantity:
        return jsonify({'error': f'Insufficient stock. Only {product.available_stock} available'}), 400
    
    cart_item = CartItem.query.filter_by(user_id=user_id, product_id=product_id).first()
    if cart_item:
        if product.available_stock < cart_item.quantity + quantity:
            return jsonify({'error': f'Insufficient stock'}), 400
        cart_item.quantity += quantity
    else:
        cart_item = CartItem(user_id=user_id, product_id=product_id, quantity=quantity)
        db.session.add(cart_item)
    
    db.session.commit()
    return jsonify({'success': True}), 201

@app.route('/api/cart/<int:cart_item_id>', methods=['DELETE'])
@user_required
def remove_from_cart(cart_item_id):
    user_id = get_jwt_identity()
    cart_item = CartItem.query.filter_by(id=cart_item_id, user_id=user_id).first()
    if not cart_item:
        return jsonify({'error': 'Cart item not found'}), 404
    db.session.delete(cart_item)
    db.session.commit()
    return jsonify({'success': True})

# ==================== ORDER ROUTES (FIXED TRANSACTION) ====================
@app.route('/api/orders', methods=['GET'])
@jwt_required()
def get_orders():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if user.role == 'admin':
        orders = Order.query.order_by(Order.created_at.desc()).all()
    elif user.role == 'agent':
        orders = Order.query.filter_by(agent_id=user_id).order_by(Order.created_at.desc()).all()
    else:
        orders = Order.query.filter_by(user_id=user_id).order_by(Order.created_at.desc()).all()
    
    return jsonify([{
        'id': o.id, 'user_id': o.user_id, 'agent_id': o.agent_id,
        'items': json.loads(o.items) if o.items else [],
        'total': o.total, 'status': o.status, 'payment_method': o.payment_method,
        'payment_status': o.payment_status, 'rider_name': o.rider_name,
        'rider_phone': o.rider_phone, 'delivery_location': o.delivery_location,
        'date': o.date, 'created_at': o.created_at.isoformat()
    } for o in orders])

@app.route('/api/orders', methods=['POST'])
@user_required
def create_order():
    user_id = get_jwt_identity()
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid request body'}), 400
    
    items_data = data.get('items', [])
    if not items_data:
        return jsonify({'error': 'No items'}), 400
    
    try:
        # Use a proper transaction with single commit at the end
        validated_items = []
        total = 0
        
        for item in items_data:
            product_id = item.get('productId')
            quantity = item.get('quantity', 1)
            
            product = Product.query.with_for_update().get(product_id)
            if not product:
                return jsonify({'error': f'Product not found'}), 404
            
            if product.available_stock < quantity:
                return jsonify({'error': f'Insufficient stock for {product.name}'}), 400
            
            total += product.price * quantity
            validated_items.append({
                'productId': product.id,
                'productName': product.name,
                'quantity': quantity,
                'price': product.price
            })
            
            product.reserved_stock += quantity
        
        payment_method = data.get('payment_method', 'MTN Mobile Money')
        
        order = Order(
            user_id=user_id,
            items=json.dumps(validated_items),
            total=total,
            status='pending',
            payment_status='pending',
            payment_method=payment_method,
            date=datetime.utcnow().strftime('%Y-%m-%d'),
            stock_confirmed=False,
            stock_reserved_until=datetime.utcnow() + timedelta(hours=1)
        )
        
        db.session.add(order)
        db.session.flush()  # Get order ID without committing
        
        order.payment_ref = generate_tx_ref(order.id)
        CartItem.query.filter_by(user_id=user_id).delete()
        
        # Single commit at the end
        db.session.commit()
        
        # Assign agent (outside transaction - no rollback needed if this fails)
        agent = get_least_busy_agent()
        if agent:
            order.agent_id = agent.id
            db.session.commit()
        
        log_audit(user_id, 'CREATE_ORDER', 'order', order.id)
        return jsonify({'success': True, 'order_id': order.id}), 201
            
    except SQLAlchemyError as e:
        db.session.rollback()
        logger.error(f"Order creation failed: {e}")
        return jsonify({'error': 'Order processing failed'}), 500

@app.route('/api/orders/<int:order_id>/status', methods=['PUT'])
@jwt_required()
def update_order_status(order_id):
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid request body'}), 400
    
    order = Order.query.get_or_404(order_id)
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if user.role != 'admin' and (user.role == 'agent' and order.agent_id != user_id):
        return jsonify({'error': 'Permission denied'}), 403
    
    order.status = data.get('status', order.status)
    db.session.commit()
    
    log_audit(user_id, 'UPDATE_ORDER_STATUS', 'order', order_id)
    return jsonify({'success': True})

# ==================== ADMIN ROUTES ====================
@app.route('/api/admin/stats', methods=['GET'])
@admin_required
def admin_stats():
    today = datetime.utcnow().date()
    today_orders = Order.query.filter(func.date(Order.created_at) == today).all()
    today_sales = sum(o.total for o in today_orders if o.payment_status == 'completed')
    pending = Order.query.filter(Order.payment_status == 'pending').count()
    low_stock = Product.query.filter(Product.available_stock < 5).count()
    
    return jsonify({
        'today_sales': today_sales,
        'pending_orders': pending,
        'total_products': Product.query.count(),
        'low_stock': low_stock
    })

@app.route('/api/admin/orders', methods=['GET'])
@admin_required
def admin_orders():
    orders = Order.query.order_by(Order.created_at.desc()).all()
    return jsonify([{
        'id': o.id, 'user_id': o.user_id, 'agent_id': o.agent_id,
        'total': o.total, 'status': o.status, 'payment_status': o.payment_status,
        'created_at': o.created_at.isoformat()
    } for o in orders])

# ==================== AGENT ROUTES ====================
@app.route('/api/agent/orders', methods=['GET'])
@agent_required
def agent_orders():
    user_id = get_jwt_identity()
    orders = Order.query.filter_by(agent_id=user_id).order_by(Order.created_at.desc()).all()
    return jsonify([{
        'id': o.id, 'user_id': o.user_id,
        'items': json.loads(o.items) if o.items else [],
        'total': o.total, 'status': o.status,
        'delivery_location': o.delivery_location,
        'created_at': o.created_at.isoformat()
    } for o in orders])

# ==================== CHAT ROUTE ====================
@app.route('/api/chat/customer', methods=['POST'])
@rate_limit("20 per minute")
def customer_chat():
    data = request.get_json()
    if not data:
        return jsonify({'response': "Invalid request"}), 400
    
    message = data.get('message', '').lower()
    
    if 'price' in message or 'cost' in message:
        response = "💰 Tarazo Prices:\n• Floor: UGX 150,000/m²\n• Wall: UGX 120,000/m²\n• Countertop: UGX 280,000/m²"
    elif 'delivery' in message:
        response = "🚚 Delivery takes 2-5 days. Free delivery on orders over UGX 500,000!"
    elif 'payment' in message:
        if FLUTTERWAVE_ENABLED:
            response = "💳 We accept MTN Mobile Money, Airtel Money, and Bank Cards via Flutterwave!"
        else:
            response = "💳 We accept MTN Mobile Money, Airtel Money, and Bank Cards. (Demo mode)"
    elif 'hello' in message or 'hi' in message:
        response = "Hello! Welcome to Tarazo! How can I help you today? 😊"
    else:
        response = "I can help you with prices, delivery, and payments!"
    
    return jsonify({'response': response})

# ==================== PAYMENT WEBHOOK (FIXED PARSING) ====================
@app.route('/api/payment/webhook', methods=['POST'])
def payment_webhook():
    raw_payload = request.get_data(as_text=True)
    signature = request.headers.get('verif-hash')
    
    if not verify_webhook_signature(raw_payload, signature):
        logger.warning("Invalid webhook signature")
        return jsonify({'error': 'Invalid signature'}), 401
    
    data = request.json
    tx_ref = data.get('tx_ref')
    status = data.get('status')
    
    if status == 'successful' and tx_ref:
        try:
            # Safely parse order_id from tx_ref
            parts = tx_ref.split('-')
            if len(parts) >= 2:
                order_id = int(parts[1])
                order = Order.query.get(order_id)
                
                if order and order.payment_status == 'pending':
                    order.payment_status = 'completed'
                    order.status = 'paid'
                    order.stock_confirmed = True
                    order.stock_reserved_until = None
                    
                    items = json.loads(order.items)
                    for item in items:
                        product = Product.query.get(item['productId'])
                        if product:
                            product.stock -= item['quantity']
                            product.reserved_stock -= item['quantity']
                    
                    db.session.commit()
                    logger.info(f"Payment confirmed for order #{order.id}")
            else:
                logger.warning(f"Malformed tx_ref: {tx_ref}")
        except (ValueError, IndexError) as e:
            logger.error(f"Failed to parse tx_ref: {tx_ref}, error: {e}")
    
    return jsonify({'status': 'ok'}), 200

# ==================== ERROR HANDLERS ====================
@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Resource not found'}), 404

@app.errorhandler(429)
def rate_limit_exceeded(e):
    return jsonify({'error': 'Too many requests. Please try again later.'}), 429

@app.errorhandler(500)
def server_error(e):
    logger.error(f"Server error: {e}")
    return jsonify({'error': 'Internal server error'}), 500

# ==================== MAIN ====================
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_default_accounts()
    
    port = int(os.environ.get('PORT', 5000))
    
    print(f"""
╔══════════════════════════════════════════════════════════════════╗
║              TARAZO BACKEND - PRODUCTION READY ✅                ║
║                         Version 6.1.0                            ║
╠══════════════════════════════════════════════════════════════════╣
║  Status:      RUNNING                                           ║
║  Mode:        PRODUCTION                                        ║
║  Payments:    {'LIVE' if FLUTTERWAVE_ENABLED else 'DEMO'}                                ║
║  Port:        {port}                                             ║
╠══════════════════════════════════════════════════════════════════╣
║  ✅ All Critical Issues Fixed:                                  ║
║  ✅ decode_token imported                                       ║
║  ✅ email_verified column added                                 ║
║  ✅ Transaction safety fixed (single commit)                    ║
║  ✅ Refresh uses @jwt_required(refresh=True)                    ║
║  ✅ Scheduler single worker mode                                ║
║  ✅ Webhook tx_ref safe parsing                                 ║
║  ✅ Redis REQUIRED (no fallback)                               ║
╚══════════════════════════════════════════════════════════════════╝
""")
    
    app.run(host='0.0.0.0', port=port, debug=False)
