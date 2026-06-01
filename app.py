# WAMP BACKEND - PRODUCTION READY (FIXED)
# ==========================================

import os
import re
import json
import secrets
import logging
import hmac
import hashlib
import time
import base64
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_cors import CORS
from flask_jwt_extended import (
    JWTManager, create_access_token, create_refresh_token,
    jwt_required, get_jwt_identity, get_jwt, verify_jwt_in_request
)
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from itsdangerous import URLSafeTimedSerializer
from cryptography.fernet import Fernet
from sqlalchemy import func, text
from sqlalchemy.exc import SQLAlchemyError
from dotenv import load_dotenv
from werkzeug.middleware.proxy_fix import ProxyFix

# Cloudinary for image upload
import cloudinary
import cloudinary.uploader

# Redis for rate limiting
import redis
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Load .env file (works locally, ignored on Render)
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
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)
logger.addFilter(SensitiveDataFilter())


# ==================== CONFIGURATION ====================

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'fallback-secret-key-change-in-production')
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'fallback-jwt-secret-change-in-production')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=60)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=7)
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5MB
app.config['JWT_TOKEN_LOCATION'] = ['headers']
app.config['JWT_HEADER_NAME'] = 'Authorization'
app.config['JWT_HEADER_TYPE'] = 'Bearer'

# Database
database_url = os.environ.get('DATABASE_URL')
if database_url and database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql://', 1)

app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_size': 10,
    'pool_recycle': 300,
    'pool_pre_ping': True,
}


# ==================== CLOUDINARY CONFIG ====================

cloudinary.config(
    cloud_name=os.environ.get('CLOUDINARY_CLOUD_NAME', ''),
    api_key=os.environ.get('CLOUDINARY_API_KEY', ''),
    api_secret=os.environ.get('CLOUDINARY_API_SECRET', '')
)

CLOUDINARY_ENABLED = bool(os.environ.get('CLOUDINARY_API_KEY') and os.environ.get('CLOUDINARY_API_SECRET'))

if CLOUDINARY_ENABLED:
    logger.info("✅ Cloudinary configured")
else:
    logger.info("ℹ️ Cloudinary not configured - images stored in database only")


# ==================== CORS ====================

ALLOWED_ORIGINS = [
    "https://ravenj-png.github.io",
    "http://localhost:5500",
    "http://localhost:5000",
    "http://127.0.0.1:5500",
    "http://127.0.0.1:5000",
    "https://raven-terazzo.onrender.com"
]

CORS(app, 
     origins=ALLOWED_ORIGINS, 
     supports_credentials=True,  # Changed to True for better cookie/token support
     methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
     allow_headers=["Content-Type", "Authorization", "X-Requested-With", "Accept"],
     expose_headers=["Content-Type", "Authorization"],
     max_age=3600)


# ==================== REDIS ====================

try:
    redis_client = redis.from_url(
        os.environ.get('REDIS_URL', 'redis://localhost:6379'),
        socket_timeout=5,
        decode_responses=True
    )
    redis_client.ping()
    limiter = Limiter(
        get_remote_address,
        app=app,
        default_limits=["1000 per day", "200 per hour", "30 per minute"],
        storage_uri=os.environ.get('REDIS_URL', 'redis://localhost:6379')
    )
    logger.info("✅ Redis connected")
    
except Exception as e:
    logger.warning(f"⚠️ Redis not available: {e}")
    
    class DummyLimiter:
        def limit(self, limits):
            def decorator(f):
                return f
            return decorator
    
    limiter = DummyLimiter()

def rate_limit(limits):
    return limiter.limit(limits)


# ==================== EXTENSIONS ====================

jwt = JWTManager(app)
db = SQLAlchemy(app)
migrate = Migrate(app, db)
ph = PasswordHasher()
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])


# ==================== FLUTTERWAVE ====================

FLUTTERWAVE_SECRET_KEY = os.environ.get('FLUTTERWAVE_SECRET_KEY')
FLUTTERWAVE_PUBLIC_KEY = os.environ.get('FLUTTERWAVE_PUBLIC_KEY')
FLUTTERWAVE_WEBHOOK_SECRET = os.environ.get('FLUTTERWAVE_WEBHOOK_SECRET')
FLUTTERWAVE_ENABLED = bool(FLUTTERWAVE_SECRET_KEY and FLUTTERWAVE_PUBLIC_KEY)

logger.info(f"✅ Payments: {'LIVE' if FLUTTERWAVE_ENABLED else 'DEMO'} mode")


# ==================== JWT ERROR HANDLERS ====================

@jwt.unauthorized_loader
def custom_unauthorized_response(callback):
    """Handle missing JWT token"""
    logger.warning("JWT unauthorized: Missing or invalid token")
    return jsonify({'error': 'Authorization token is missing or invalid'}), 401

@jwt.invalid_token_loader
def custom_invalid_token_response(error_string):
    """Handle invalid JWT token"""
    logger.warning(f"JWT invalid token: {error_string}")
    return jsonify({'error': f'Invalid token: {error_string}'}), 422

@jwt.expired_token_loader
def custom_expired_token_response(jwt_header, jwt_payload):
    """Handle expired JWT token"""
    logger.warning("JWT token expired")
    return jsonify({'error': 'Token has expired', 'expired': True}), 401

@jwt.revoked_token_loader
def custom_revoked_token_response(jwt_header, jwt_payload):
    """Handle revoked JWT token"""
    logger.warning("JWT token revoked")
    return jsonify({'error': 'Token has been revoked'}), 401

@jwt.needs_fresh_token_loader
def custom_needs_fresh_token_response(jwt_header, jwt_payload):
    """Handle when fresh token is needed"""
    logger.warning("Fresh token required")
    return jsonify({'error': 'Fresh token required'}), 401


# ==================== BRUTE FORCE PROTECTION ====================

def record_failed_login(ip):
    try:
        key = f"login_attempts:{ip}"
        redis_client.lpush(key, time.time())
        redis_client.ltrim(key, 0, 9)
        redis_client.expire(key, 900)
    except:
        pass

def is_ip_blocked(ip):
    try:
        key = f"login_attempts:{ip}"
        attempts = redis_client.lrange(key, 0, -1)
        now = time.time()
        recent = [float(a) for a in attempts if float(a) > now - 900]
        return len(recent) >= 10
    except:
        return False

def reset_failed_attempts(ip):
    try:
        key = f"login_attempts:{ip}"
        redis_client.delete(key)
    except:
        pass


# ==================== DATABASE MODELS ====================

class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    phone = db.Column(db.String(20))
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default='user', index=True)
    status = db.Column(db.String(20), default='online')
    address = db.Column(db.String(500))
    email_verified = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class Product(db.Model):
    __tablename__ = 'products'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    type = db.Column(db.String(100), nullable=False, index=True)
    price = db.Column(db.Integer, nullable=False)
    stock = db.Column(db.Integer, default=0)
    reserved_stock = db.Column(db.Integer, default=0)
    description = db.Column(db.Text)
    image_url = db.Column(db.String(500))
    image_data = db.Column(db.Text)
    image_type = db.Column(db.String(20), default='url')
    image_mime = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    @property
    def available_stock(self):
        return self.stock - self.reserved_stock


class CartItem(db.Model):
    __tablename__ = 'cart_items'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), index=True)
    product_id = db.Column(db.Integer, db.ForeignKey('products.id'))
    quantity = db.Column(db.Integer, default=1)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Order(db.Model):
    __tablename__ = 'orders'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), index=True)
    agent_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    items = db.Column(db.Text, nullable=False)
    total = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(50), default='pending', index=True)
    payment_method = db.Column(db.String(50))
    payment_status = db.Column(db.String(50), default='pending')
    transaction_id = db.Column(db.String(100), unique=True)
    payment_ref = db.Column(db.String(100), unique=True)
    stock_confirmed = db.Column(db.Boolean, default=False)
    stock_reserved_until = db.Column(db.DateTime, nullable=True)
    rider_name = db.Column(db.String(100))
    rider_phone = db.Column(db.String(20))
    delivery_location = db.Column(db.String(500))
    date = db.Column(db.String(20))
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)


class Wishlist(db.Model):
    __tablename__ = 'wishlist'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    product_id = db.Column(db.Integer, db.ForeignKey('products.id'), nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Review(db.Model):
    __tablename__ = 'reviews'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    product_id = db.Column(db.Integer, db.ForeignKey('products.id'), nullable=False, index=True)
    rating = db.Column(db.Integer, nullable=False)
    comment = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class PaymentTransaction(db.Model):
    __tablename__ = 'payment_transactions'
    
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('orders.id'))
    tx_ref = db.Column(db.String(100), unique=True)
    transaction_id = db.Column(db.String(100), unique=True)
    amount = db.Column(db.Integer, nullable=False)
    currency = db.Column(db.String(3), default='UGX')
    status = db.Column(db.String(50), default='pending')
    payment_method = db.Column(db.String(50))
    customer_email = db.Column(db.String(255))
    customer_phone = db.Column(db.String(20))
    webhook_data = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class TokenBlacklist(db.Model):
    __tablename__ = 'token_blacklist'
    
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(36), unique=True, nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))


class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    action = db.Column(db.String(100), nullable=False)
    resource_type = db.Column(db.String(50))
    resource_id = db.Column(db.Integer)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(500))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


# ==================== HELPER FUNCTIONS ====================

def get_database_size():
    try:
        result = db.session.execute(text("SELECT pg_database_size(current_database())"))
        return result.scalar() or 0
    except:
        return 0

DB_LIMIT_GB = 8
DB_THRESHOLD = int(DB_LIMIT_GB * 0.9 * 1024 * 1024 * 1024)

def should_use_cloudinary():
    if not CLOUDINARY_ENABLED:
        return False
    return get_database_size() >= DB_THRESHOLD


def ensure_all_tables_and_columns_exist():
    """Create all missing tables and columns"""
    
    # Create wishlist table if not exists
    try:
        db.session.execute(text("""
            CREATE TABLE IF NOT EXISTS wishlist (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                product_id INTEGER NOT NULL REFERENCES products(id) ON DELETE CASCADE,
                created_at TIMESTAMP DEFAULT NOW()
            )
        """))
        db.session.commit()
        logger.info("✅ Wishlist table verified")
    except Exception as e:
        db.session.rollback()
        logger.warning(f"Wishlist table: {e}")

    # Create reviews table if not exists
    try:
        db.session.execute(text("""
            CREATE TABLE IF NOT EXISTS reviews (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                product_id INTEGER NOT NULL REFERENCES products(id) ON DELETE CASCADE,
                rating INTEGER NOT NULL CHECK (rating >= 1 AND rating <= 5),
                comment TEXT,
                created_at TIMESTAMP DEFAULT NOW()
            )
        """))
        db.session.commit()
        logger.info("✅ Reviews table verified")
    except Exception as e:
        db.session.rollback()
        logger.warning(f"Reviews table: {e}")

    # Add unique constraints
    try:
        db.session.execute(text("ALTER TABLE wishlist ADD CONSTRAINT IF NOT EXISTS unique_user_product UNIQUE (user_id, product_id)"))
        db.session.commit()
    except:
        pass

    try:
        db.session.execute(text("ALTER TABLE reviews ADD CONSTRAINT IF NOT EXISTS unique_user_product_review UNIQUE (user_id, product_id)"))
        db.session.commit()
    except:
        pass

    # User table missing columns
    user_columns = [
        ('phone', 'VARCHAR(20)'),
        ('email_verified', 'BOOLEAN DEFAULT TRUE'),
        ('address', 'TEXT'),
        ('status', 'VARCHAR(20) DEFAULT \'online\'')
    ]

    for col_name, col_def in user_columns:
        try:
            db.session.execute(text(f"ALTER TABLE users ADD COLUMN IF NOT EXISTS {col_name} {col_def}"))
            db.session.commit()
            logger.info(f"✅ Added column users.{col_name}")
        except:
            db.session.rollback()

    # Product table missing columns
    product_columns = [
        ('image_data', 'TEXT'),
        ('image_type', 'VARCHAR(20) DEFAULT \'url\''),
        ('image_mime', 'VARCHAR(50)')
    ]

    for col_name, col_def in product_columns:
        try:
            db.session.execute(text(f"ALTER TABLE products ADD COLUMN IF NOT EXISTS {col_name} {col_def}"))
            db.session.commit()
            logger.info(f"✅ Added column products.{col_name}")
        except:
            db.session.rollback()

    # Create indexes
    try:
        db.session.execute(text("CREATE INDEX IF NOT EXISTS idx_wishlist_user ON wishlist(user_id)"))
        db.session.execute(text("CREATE INDEX IF NOT EXISTS idx_wishlist_product ON wishlist(product_id)"))
        db.session.execute(text("CREATE INDEX IF NOT EXISTS idx_reviews_product ON reviews(product_id)"))
        db.session.execute(text("CREATE INDEX IF NOT EXISTS idx_reviews_user ON reviews(user_id)"))
        db.session.commit()
    except:
        pass


# ==================== JWT BLACKLIST ====================

@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    jti = jwt_payload['jti']
    token = TokenBlacklist.query.filter_by(jti=jti).first()
    return token is not None


# ==================== HELPER FUNCTIONS ====================

def log_audit(user_id, action, resource_type=None, resource_id=None):
    try:
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
    except:
        pass

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
    return f"TX-{order_id}-{int(time.time())}-{secrets.token_hex(4)}"

def verify_webhook_signature(payload, signature):
    if not FLUTTERWAVE_WEBHOOK_SECRET or not signature:
        return False
    expected = hmac.new(
        FLUTTERWAVE_WEBHOOK_SECRET.encode(),
        payload.encode(),
        hashlib.sha512
    ).hexdigest()
    return hmac.compare_digest(expected, signature)


# ==================== CREATE DEFAULT ACCOUNTS ====================

def create_default_accounts():
    """Force create/update admin and agents from environment variables"""
    ensure_all_tables_and_columns_exist()
    
    # Read from environment variables (works both locally and on Render)
    admin_email = os.environ.get('ADMIN_EMAIL', 'admin@tarazo.com').strip()
    admin_password = os.environ.get('ADMIN_PASSWORD', 'Admin123456').strip()
    admin_name = os.environ.get('ADMIN_NAME', 'System Administrator').strip()
    admin_phone = os.environ.get('ADMIN_PHONE', '0771000000').strip()
    
    logger.info(f"Setting up admin: {admin_email}")
    
    # Check if admin exists
    admin = User.query.filter_by(email=admin_email).first()
    
    if not admin:
        # Create new admin
        admin = User(
            name=admin_name,
            email=admin_email,
            phone=admin_phone,
            password_hash=ph.hash(admin_password),
            role='admin',
            status='online',
            email_verified=True
        )
        db.session.add(admin)
        logger.info(f"✅ CREATED new admin: {admin_email}")
    else:
        # ALWAYS update password to ensure it matches .env
        admin.password_hash = ph.hash(admin_password)
        admin.role = 'admin'
        admin.status = 'online'
        admin.name = admin_name
        admin.phone = admin_phone
        logger.info(f"✅ UPDATED existing admin: {admin_email}")
    
    # Create 5 agents
    for i in range(1, 6):
        agent_email = os.environ.get(f'AGENT{i}_EMAIL', f'agent{i}@tarazo.com').strip()
        agent_password = os.environ.get(f'AGENT{i}_PASSWORD', 'Agent123456').strip()
        agent_name = os.environ.get(f'AGENT{i}_NAME', f'Agent {i}').strip()
        agent_phone = os.environ.get(f'AGENT{i}_PHONE', f'077{i}000000').strip()
        
        agent = User.query.filter_by(email=agent_email).first()
        
        if not agent:
            agent = User(
                name=agent_name,
                email=agent_email,
                phone=agent_phone,
                password_hash=ph.hash(agent_password),
                role='agent',
                status='online',
                email_verified=True
            )
            db.session.add(agent)
            logger.info(f"✅ Created agent {i}: {agent_email}")
        else:
            agent.password_hash = ph.hash(agent_password)
            agent.role = 'agent'
            agent.status = 'online'
            logger.info(f"✅ Updated agent {i}: {agent_email}")
    
    # Create sample products if none exist
    if Product.query.count() == 0:
        sample_products = [
            Product(
                name='Premium Floor Terrazzo',
                type='Floor Terrazzo',
                price=250000,
                stock=100,
                description='High-end terrazzo flooring',
                image_type='url',
                image_url='https://images.unsplash.com/photo-1600585154526-990dced4db0d?w=400'
            ),
            Product(
                name='Copper Plumbing Pipe',
                type='Plumbing Pipe',
                price=45000,
                stock=50,
                description='Durable copper pipe',
                image_type='url',
                image_url='https://images.unsplash.com/photo-1581092160562-40aa08e7882a?w=400'
            ),
            Product(
                name='Interior Emulsion Paint',
                type='Paint Emulsion',
                price=120000,
                stock=80,
                description='Smooth matte finish',
                image_type='url',
                image_url='https://images.unsplash.com/photo-1589939705384-5185137a7f0f?w=400'
            ),
        ]
        for p in sample_products:
            db.session.add(p)
        logger.info("✅ Created sample products")
    
    db.session.commit()
    logger.info("✅ All default accounts created/updated successfully!")


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
    return jsonify({
        'status': 'healthy',
        'database': 'connected',
        'payments_mode': 'LIVE' if FLUTTERWAVE_ENABLED else 'DEMO',
        'cloudinary_available': CLOUDINARY_ENABLED,
        'timestamp': datetime.utcnow().isoformat()
    })


@app.route('/api/register', methods=['POST'])
def register():
    try:
        if not request.is_json:
            return jsonify({'error': 'Content-Type must be application/json'}), 400
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid request'}), 400

        name = data.get('name', '').strip()
        email = data.get('email', '').strip()
        password = data.get('password', '').strip()
        phone = data.get('phone', '').strip()

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
            email_verified=True
        )
        db.session.add(user)
        db.session.commit()
        log_audit(user.id, 'REGISTER', 'user', user.id)
        
        return jsonify({'success': True, 'message': 'Registration successful'}), 201
    
    except Exception as e:
        logger.error(f"Register error: {e}")
        return jsonify({'error': 'Registration failed'}), 500


@app.route('/api/login', methods=['POST'])
def login():
    try:
        if not request.is_json:
            return jsonify({'error': 'Content-Type must be application/json'}), 400
        
        client_ip = request.remote_addr
        if is_ip_blocked(client_ip):
            return jsonify({'error': 'Too many failed attempts. Try again later.'}), 429
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid request'}), 400

        email = data.get('email', '').strip()
        password = data.get('password', '').strip()

        if not email or not password:
            return jsonify({'error': 'Email and password required'}), 400

        logger.info(f"Login attempt for: {email}")

        user = User.query.filter_by(email=email).first()
        if not user:
            logger.warning(f"User not found: {email}")
            record_failed_login(client_ip)
            return jsonify({'error': 'Invalid credentials'}), 401

        try:
            ph.verify(user.password_hash, password)
            logger.info(f"Login successful: {email}")
        except VerifyMismatchError:
            logger.warning(f"Password mismatch for: {email}")
            record_failed_login(client_ip)
            return jsonify({'error': 'Invalid credentials'}), 401

        reset_failed_attempts(client_ip)

        # Create tokens with additional claims
        access_token = create_access_token(identity=user.id)
        refresh_token = create_refresh_token(identity=user.id)

        # Log successful login
        log_audit(user.id, 'LOGIN', 'user', user.id)

        return jsonify({
            'success': True,
            'access_token': access_token,
            'refresh_token': refresh_token,
            'user': {
                'id': user.id,
                'name': user.name,
                'email': user.email,
                'role': user.role,
                'phone': user.phone,
                'address': user.address
            }
        })
    
    except Exception as e:
        logger.error(f"Login error: {e}")
        return jsonify({'error': 'Login failed'}), 500


@app.route('/api/refresh', methods=['POST'])
@jwt_required(refresh=True)
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
    return jsonify({'success': True})


# ==================== TEST AUTH ENDPOINT ====================

@app.route('/api/verify-token', methods=['GET'])
@jwt_required()
def verify_token():
    """Endpoint to test if token is valid"""
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if not user:
        return jsonify({'valid': False, 'error': 'User not found'}), 401
    
    return jsonify({
        'valid': True,
        'user': {
            'id': user.id,
            'email': user.email,
            'role': user.role
        }
    })


# ==================== PRODUCT ROUTES ====================

@app.route('/api/products', methods=['GET'])
def get_products():
    try:
        products = Product.query.all()
        return jsonify([{
            'id': p.id,
            'name': p.name,
            'type': p.type,
            'price': p.price,
            'stock': p.available_stock,
            'description': p.description or '',
            'image_url': p.image_url or '',
            'image_data': p.image_data if p.image_type == 'db' else None,
            'image_type': p.image_type,
            'image_mime': p.image_mime
        } for p in products])
    
    except Exception as e:
        logger.error(f"Get products error: {e}")
        return jsonify({'error': 'Failed to fetch products'}), 500


@app.route('/api/admin/products', methods=['POST'])
@admin_required
def create_product():
    try:
        if not request.is_json:
            return jsonify({'error': 'Content-Type must be application/json'}), 400
        
        data = request.get_json()
        product = Product(
            name=data.get('name'),
            type=data.get('type'),
            price=data.get('price'),
            stock=data.get('stock', 0),
            description=data.get('description', ''),
            image_type='url'
        )
        db.session.add(product)
        db.session.commit()
        
        return jsonify({'success': True, 'id': product.id}), 201
    
    except Exception as e:
        logger.error(f"Create product error: {e}")
        return jsonify({'error': 'Failed to create product'}), 500


@app.route('/api/admin/products/upload', methods=['POST'])
@admin_required
def upload_product_image():
    try:
        if 'image' not in request.files:
            return jsonify({'error': 'No image file'}), 400

        file = request.files['image']
        product_id = request.form.get('product_id')

        if not product_id:
            return jsonify({'error': 'Product ID required'}), 400

        product = Product.query.get(product_id)
        if not product:
            return jsonify({'error': 'Product not found'}), 404

        file.seek(0, 2)
        if file.tell() > 5 * 1024 * 1024:
            return jsonify({'error': 'Image too large. Max 5MB'}), 400
        file.seek(0)

        file_content = file.read()

        if should_use_cloudinary():
            try:
                result = cloudinary.uploader.upload(file, folder='wamp_products')
                product.image_url = result['secure_url']
                product.image_type = 'cloudinary'
                product.image_data = None
                logger.info(f"Image uploaded to Cloudinary for product {product_id}")
            except Exception as e:
                logger.error(f"Cloudinary error: {e}")
                return jsonify({'error': 'Upload failed'}), 500
        else:
            product.image_data = base64.b64encode(file_content).decode('utf-8')
            product.image_type = 'db'
            product.image_mime = file.mimetype
            product.image_url = None
            logger.info(f"Image stored in database for product {product_id}")

        db.session.commit()
        return jsonify({'success': True, 'image_type': product.image_type})
    
    except Exception as e:
        logger.error(f"Upload image error: {e}")
        return jsonify({'error': 'Upload failed'}), 500


@app.route('/api/admin/products/<int:product_id>', methods=['PUT'])
@admin_required
def update_product(product_id):
    try:
        if not request.is_json:
            return jsonify({'error': 'Content-Type must be application/json'}), 400
        
        product = Product.query.get_or_404(product_id)
        data = request.get_json()
        
        product.name = data.get('name', product.name)
        product.type = data.get('type', product.type)
        product.price = data.get('price', product.price)
        product.stock = data.get('stock', product.stock)
        product.description = data.get('description', product.description)
        
        if data.get('image_url') and product.image_type != 'db':
            product.image_url = data.get('image_url')
            product.image_type = 'url'
        
        db.session.commit()
        return jsonify({'success': True})
    
    except Exception as e:
        logger.error(f"Update product error: {e}")
        return jsonify({'error': 'Failed to update product'}), 500


@app.route('/api/admin/products/<int:product_id>', methods=['DELETE'])
@admin_required
def delete_product(product_id):
    try:
        product = Product.query.get_or_404(product_id)
        db.session.delete(product)
        db.session.commit()
        return jsonify({'success': True})
    
    except Exception as e:
        logger.error(f"Delete product error: {e}")
        return jsonify({'error': 'Failed to delete product'}), 500


# ==================== CART ROUTES ====================

@app.route('/api/cart', methods=['GET'])
@jwt_required()
def get_cart():
    try:
        user_id = get_jwt_identity()
        cart = CartItem.query.filter_by(user_id=user_id).all()
        
        # Get product details for each cart item
        cart_data = []
        for item in cart:
            product = Product.query.get(item.product_id)
            if product:
                cart_data.append({
                    'id': item.id,
                    'product_id': item.product_id,
                    'quantity': item.quantity,
                    'product_name': product.name,
                    'product_price': product.price,
                    'product_image': product.image_url
                })
        
        return jsonify(cart_data)
    
    except Exception as e:
        logger.error(f"Get cart error: {e}")
        return jsonify({'error': 'Failed to fetch cart'}), 500


@app.route('/api/cart', methods=['POST'])
@jwt_required()
def add_to_cart():
    try:
        if not request.is_json:
            return jsonify({'error': 'Content-Type must be application/json'}), 400
        
        user_id = get_jwt_identity()
        data = request.get_json()
        product_id = data.get('product_id')
        quantity = data.get('quantity', 1)

        product = Product.query.get(product_id)
        if not product:
            return jsonify({'error': 'Product not found'}), 404
        
        if product.available_stock < quantity:
            return jsonify({'error': 'Insufficient stock'}), 400

        cart_item = CartItem.query.filter_by(user_id=user_id, product_id=product_id).first()
        
        if cart_item:
            cart_item.quantity += quantity
        else:
            cart_item = CartItem(user_id=user_id, product_id=product_id, quantity=quantity)
            db.session.add(cart_item)

        db.session.commit()
        return jsonify({'success': True, 'message': 'Added to cart'}), 201
    
    except Exception as e:
        logger.error(f"Add to cart error: {e}")
        return jsonify({'error': 'Failed to add to cart'}), 500


@app.route('/api/cart/<int:cart_item_id>', methods=['DELETE'])
@jwt_required()
def remove_from_cart(cart_item_id):
    try:
        user_id = get_jwt_identity()
        cart_item = CartItem.query.filter_by(id=cart_item_id, user_id=user_id).first()
        
        if not cart_item:
            return jsonify({'error': 'Not found'}), 404
        
        db.session.delete(cart_item)
        db.session.commit()
        return jsonify({'success': True})
    
    except Exception as e:
        logger.error(f"Remove from cart error: {e}")
        return jsonify({'error': 'Failed to remove from cart'}), 500


@app.route('/api/cart/clear', methods=['DELETE'])
@jwt_required()
def clear_cart():
    try:
        user_id = get_jwt_identity()
        CartItem.query.filter_by(user_id=user_id).delete()
        db.session.commit()
        return jsonify({'success': True})
    
    except Exception as e:
        logger.error(f"Clear cart error: {e}")
        return jsonify({'error': 'Failed to clear cart'}), 500


# ==================== WISHLIST ROUTES ====================

@app.route('/api/wishlist', methods=['GET'])
@jwt_required()
def get_wishlist():
    try:
        user_id = get_jwt_identity()
        items = db.session.execute(text("""
            SELECT w.id, w.product_id, p.name, p.price, p.image_url, p.stock
            FROM wishlist w
            JOIN products p ON w.product_id = p.id
            WHERE w.user_id = :user_id
            ORDER BY w.created_at DESC
        """), {'user_id': user_id}).fetchall()

        return jsonify([{
            'id': row[0],
            'product_id': row[1],
            'name': row[2],
            'price': row[3],
            'image_url': row[4],
            'stock': row[5]
        } for row in items])
    
    except Exception as e:
        logger.error(f"Get wishlist error: {e}")
        return jsonify({'error': 'Failed to fetch wishlist'}), 500


@app.route('/api/wishlist', methods=['POST'])
@jwt_required()
def toggle_wishlist():
    try:
        if not request.is_json:
            return jsonify({'error': 'Content-Type must be application/json'}), 400
        
        user_id = get_jwt_identity()
        data = request.get_json()
        product_id = data.get('product_id')

        if not product_id:
            return jsonify({'error': 'Product ID required'}), 400

        existing = db.session.execute(text("""
            SELECT id FROM wishlist WHERE user_id = :user_id AND product_id = :product_id
        """), {'user_id': user_id, 'product_id': product_id}).fetchone()

        if existing:
            db.session.execute(text("DELETE FROM wishlist WHERE id = :id"), {'id': existing[0]})
            db.session.commit()
            return jsonify({'success': True, 'action': 'removed', 'message': 'Removed from wishlist'})
        else:
            db.session.execute(text("""
                INSERT INTO wishlist (user_id, product_id) VALUES (:user_id, :product_id)
            """), {'user_id': user_id, 'product_id': product_id})
            db.session.commit()
            return jsonify({'success': True, 'action': 'added', 'message': 'Added to wishlist'}), 201
    
    except Exception as e:
        logger.error(f"Toggle wishlist error: {e}")
        return jsonify({'error': 'Failed to update wishlist'}), 500


# ==================== REVIEWS ROUTES ====================

@app.route('/api/reviews', methods=['POST'])
@jwt_required()
def submit_review():
    try:
        if not request.is_json:
            return jsonify({'error': 'Content-Type must be application/json'}), 400
        
        user_id = get_jwt_identity()
        data = request.get_json()
        product_id = data.get('product_id')
        rating = data.get('rating')
        comment = data.get('comment', '').strip()

        if not product_id or not rating:
            return jsonify({'error': 'Product ID and rating required'}), 400
        
        if not (1 <= rating <= 5):
            return jsonify({'error': 'Rating must be 1-5'}), 400

        product = Product.query.get(product_id)
        if not product:
            return jsonify({'error': 'Product not found'}), 404

        existing = db.session.execute(text("""
            SELECT id FROM reviews WHERE user_id = :user_id AND product_id = :product_id
        """), {'user_id': user_id, 'product_id': product_id}).fetchone()

        if existing:
            db.session.execute(text("""
                UPDATE reviews SET rating = :rating, comment = :comment WHERE id = :id
            """), {'rating': rating, 'comment': comment, 'id': existing[0]})
        else:
            db.session.execute(text("""
                INSERT INTO reviews (user_id, product_id, rating, comment)
                VALUES (:user_id, :product_id, :rating, :comment)
            """), {'user_id': user_id, 'product_id': product_id, 'rating': rating, 'comment': comment})

        db.session.commit()
        return jsonify({'success': True, 'message': 'Review saved'})
    
    except Exception as e:
        logger.error(f"Submit review error: {e}")
        return jsonify({'error': 'Failed to submit review'}), 500


@app.route('/api/reviews/product/<int:product_id>', methods=['GET'])
def get_product_reviews(product_id):
    try:
        reviews = db.session.execute(text("""
            SELECT r.rating, r.comment, r.created_at, u.name as user_name
            FROM reviews r
            JOIN users u ON r.user_id = u.id
            WHERE r.product_id = :product_id
            ORDER BY r.created_at DESC
        """), {'product_id': product_id}).fetchall()

        return jsonify([{
            'rating': row[0],
            'comment': row[1],
            'created_at': row[2].isoformat() if row[2] else None,
            'user_name': row[3]
        } for row in reviews])
    
    except Exception as e:
        logger.error(f"Get product reviews error: {e}")
        return jsonify({'error': 'Failed to fetch reviews'}), 500


@app.route('/api/reviews/user', methods=['GET'])
@jwt_required()
def get_user_reviews():
    try:
        user_id = get_jwt_identity()
        reviews = db.session.execute(text("""
            SELECT r.id, r.product_id, p.name as product_name, r.rating, r.comment, r.created_at
            FROM reviews r
            JOIN products p ON r.product_id = p.id
            WHERE r.user_id = :user_id
            ORDER BY r.created_at DESC
        """), {'user_id': user_id}).fetchall()

        return jsonify([{
            'id': row[0],
            'product_id': row[1],
            'product_name': row[2],
            'rating': row[3],
            'comment': row[4],
            'created_at': row[5].isoformat() if row[5] else None
        } for row in reviews])
    
    except Exception as e:
        logger.error(f"Get user reviews error: {e}")
        return jsonify({'error': 'Failed to fetch reviews'}), 500


# ==================== ORDER ROUTES ====================

@app.route('/api/orders', methods=['GET'])
@jwt_required()
def get_orders():
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)

        if user.role == 'admin':
            orders = Order.query.order_by(Order.created_at.desc()).all()
        elif user.role == 'agent':
            orders = Order.query.filter_by(agent_id=user_id).order_by(Order.created_at.desc()).all()
        else:
            orders = Order.query.filter_by(user_id=user_id).order_by(Order.created_at.desc()).all()

        return jsonify([{
            'id': o.id,
            'total': o.total,
            'status': o.status,
            'payment_method': o.payment_method,
            'payment_status': o.payment_status,
            'rider_name': o.rider_name,
            'items': json.loads(o.items) if o.items else [],
            'created_at': o.created_at.isoformat()
        } for o in orders])
    
    except Exception as e:
        logger.error(f"Get orders error: {e}")
        return jsonify({'error': 'Failed to fetch orders'}), 500


@app.route('/api/orders', methods=['POST'])
@jwt_required()
def create_order():
    try:
        if not request.is_json:
            return jsonify({'error': 'Content-Type must be application/json'}), 400
        
        user_id = get_jwt_identity()
        data = request.get_json()
        items_data = data.get('items', [])
        
        if not items_data:
            return jsonify({'error': 'No items'}), 400

        validated_items = []
        total = 0

        for item in items_data:
            product_id = item.get('productId')
            quantity = item.get('quantity', 1)
            product = Product.query.with_for_update().get(product_id)
            
            if not product:
                return jsonify({'error': 'Product not found'}), 404
            
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

        payment_method = data.get('payment_method', 'MTN')
        delivery_location = data.get('delivery_location', '')
        
        order = Order(
            user_id=user_id,
            items=json.dumps(validated_items),
            total=total,
            status='pending',
            payment_status='pending',
            payment_method=payment_method,
            delivery_location=delivery_location,
            stock_reserved_until=datetime.utcnow() + timedelta(hours=1)
        )
        db.session.add(order)
        db.session.commit()

        # Clear cart after order
        CartItem.query.filter_by(user_id=user_id).delete()
        db.session.commit()

        # Assign agent
        agent = get_least_busy_agent()
        if agent:
            order.agent_id = agent.id
            db.session.commit()

        log_audit(user_id, 'CREATE_ORDER', 'order', order.id)
        return jsonify({'success': True, 'order_id': order.id}), 201
    
    except Exception as e:
        db.session.rollback()
        logger.error(f"Order failed: {e}")
        return jsonify({'error': 'Order failed'}), 500


@app.route('/api/orders/<int:order_id>/status', methods=['PUT'])
@jwt_required()
def update_order_status(order_id):
    try:
        if not request.is_json:
            return jsonify({'error': 'Content-Type must be application/json'}), 400
        
        data = request.get_json()
        order = Order.query.get_or_404(order_id)
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if user.role != 'admin' and (user.role == 'agent' and order.agent_id != user_id):
            return jsonify({'error': 'Permission denied'}), 403
        
        order.status = data.get('status', order.status)
        db.session.commit()
        return jsonify({'success': True})
    
    except Exception as e:
        logger.error(f"Update order status error: {e}")
        return jsonify({'error': 'Failed to update order'}), 500


# ==================== ADMIN ROUTES ====================

@app.route('/api/admin/stats', methods=['GET'])
@admin_required
def admin_stats():
    try:
        pending = Order.query.filter_by(payment_status='pending').count()
        low_stock = Product.query.filter(Product.available_stock < 5).count()
        
        return jsonify({
            'today_sales': 0,
            'pending_orders': pending,
            'total_products': Product.query.count(),
            'low_stock': low_stock,
            'db_size_gb': round(get_database_size() / (1024**3), 2)
        })
    
    except Exception as e:
        logger.error(f"Admin stats error: {e}")
        return jsonify({'error': 'Failed to fetch stats'}), 500


@app.route('/api/admin/orders', methods=['GET'])
@admin_required
def admin_orders():
    try:
        orders = Order.query.order_by(Order.created_at.desc()).all()
        return jsonify([{
            'id': o.id,
            'user_id': o.user_id,
            'total': o.total,
            'status': o.status,
            'created_at': o.created_at.isoformat()
        } for o in orders])
    
    except Exception as e:
        logger.error(f"Admin orders error: {e}")
        return jsonify({'error': 'Failed to fetch orders'}), 500


# ==================== AGENT ROUTES ====================

@app.route('/api/agent/orders', methods=['GET'])
@jwt_required()
def agent_orders():
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if user.role != 'agent' and user.role != 'admin':
            return jsonify({'error': 'Agent access required'}), 403

        if user.role == 'admin':
            orders = Order.query.filter(Order.agent_id.isnot(None)).order_by(Order.created_at.desc()).all()
        else:
            orders = Order.query.filter_by(agent_id=user_id).order_by(Order.created_at.desc()).all()

        return jsonify([{
            'id': o.id,
            'user_id': o.user_id,
            'total': o.total,
            'status': o.status,
            'items': json.loads(o.items) if o.items else [],
            'delivery_location': o.delivery_location,
            'created_at': o.created_at.isoformat()
        } for o in orders])
    
    except Exception as e:
        logger.error(f"Agent orders error: {e}")
        return jsonify({'error': 'Failed to fetch orders'}), 500


# ==================== CHAT ROUTE ====================

@app.route('/api/chat/customer', methods=['POST'])
def customer_chat():
    try:
        if not request.is_json:
            return jsonify({'error': 'Content-Type must be application/json'}), 400
        
        data = request.get_json()
        message = data.get('message', '').lower()
        
        if 'price' in message:
            response = "💰 Terrazzo: UGX 250,000 | Plumbing: UGX 45,000 | Paint: UGX 120,000"
        elif 'delivery' in message:
            response = "🚚 Free delivery on orders over UGX 500,000. Takes 2-5 days."
        elif 'payment' in message:
            response = "💳 We accept MTN, Airtel, Card, and Cash on Delivery!"
        else:
            response = "Welcome to WAMP! Ask about prices, delivery, or payments."
        
        return jsonify({'response': response})
    
    except Exception as e:
        logger.error(f"Chat error: {e}")
        return jsonify({'error': 'Chat failed'}), 500


# ==================== PAYMENT WEBHOOK ====================

@app.route('/api/payment/webhook', methods=['POST'])
def payment_webhook():
    try:
        raw_payload = request.get_data(as_text=True)
        signature = request.headers.get('verif-hash')
        
        if not verify_webhook_signature(raw_payload, signature):
            return jsonify({'error': 'Invalid signature'}), 401
        
        data = request.json
        tx_ref = data.get('tx_ref')
        status = data.get('status')
        
        if status == 'successful' and tx_ref:
            try:
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
            except Exception as e:
                logger.error(f"Webhook error: {e}")
        
        return jsonify({'status': 'ok'}), 200
    
    except Exception as e:
        logger.error(f"Payment webhook error: {e}")
        return jsonify({'error': 'Webhook failed'}), 500


# ==================== DEBUG ENDPOINTS ====================

@app.route('/api/debug/env', methods=['GET'])
@admin_required
def debug_env():
    """Check environment variables and account status"""
    return jsonify({
        'ADMIN_EMAIL': os.environ.get('ADMIN_EMAIL', 'NOT SET'),
        'ADMIN_PASSWORD_SET': bool(os.environ.get('ADMIN_PASSWORD')),
        'SECRET_KEY_SET': bool(os.environ.get('SECRET_KEY')),
        'DATABASE_URL_SET': bool(os.environ.get('DATABASE_URL')),
        'total_users': User.query.count(),
        'admins': User.query.filter_by(role='admin').count(),
        'users_list': [{'id': u.id, 'email': u.email, 'role': u.role} for u in User.query.all()]
    })


@app.route('/api/debug/reset-admin', methods=['POST'])
def debug_reset_admin():
    """Force reset admin password"""
    try:
        admin_email = os.environ.get('ADMIN_EMAIL', 'admin@tarazo.com')
        admin_password = os.environ.get('ADMIN_PASSWORD', 'Admin123456')
        
        admin = User.query.filter_by(email=admin_email).first()
        
        if admin:
            admin.password_hash = ph.hash(admin_password)
            admin.role = 'admin'
            db.session.commit()
            return jsonify({'success': True, 'message': f'Admin {admin_email} password reset'})
        else:
            return jsonify({'error': 'Admin not found'}), 404
    
    except Exception as e:
        logger.error(f"Reset admin error: {e}")
        return jsonify({'error': 'Failed to reset admin'}), 500


# ==================== ERROR HANDLERS ====================

@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Resource not found'}), 404

@app.errorhandler(429)
def rate_limit_exceeded(e):
    return jsonify({'error': 'Too many requests'}), 429

@app.errorhandler(500)
def server_error(e):
    logger.error(f"Server error: {e}")
    return jsonify({'error': 'Internal server error'}), 500

@app.errorhandler(Exception)
def global_error_handler(e):
    logger.error(f"UNHANDLED ERROR: {type(e).__name__}: {e}", exc_info=True)
    return jsonify({
        'error': 'Internal server error',
        'debug': str(e) if app.debug else None
    }), 500


# ==================== DATABASE INITIALIZATION ====================

with app.app_context():
    try:
        db.create_all()
        logger.info("✅ Tables created/verified")
        
        create_default_accounts()
        logger.info("✅ Default accounts created/updated")
        
        db_size = get_database_size()
        logger.info(f"📊 Database size: {round(db_size / (1024**2), 2)} MB")
    
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")


# ==================== MAIN ====================

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    
    print(f"""
╔══════════════════════════════════════════════════════════════════╗
║              WAMP BACKEND - PRODUCTION READY ✅                  ║
╠══════════════════════════════════════════════════════════════════╣
║  Status:      RUNNING                                           ║
║  Port:        {port}                                             ║
║  Payments:    {'LIVE' if FLUTTERWAVE_ENABLED else 'DEMO'}        ║
║  Cloudinary:  {'ENABLED' if CLOUDINARY_ENABLED else 'DISABLED'}  ║
╠══════════════════════════════════════════════════════════════════╣
║  ✅ Tables: Users, Products, Cart, Orders, Wishlist, Reviews     ║
║  ✅ Admin: {os.environ.get('ADMIN_EMAIL', 'admin@tarazo.com')}   ║
║  ✅ Password: {os.environ.get('ADMIN_PASSWORD', 'Admin123456')}  ║
║  ✅ Environment variables loaded from .env or Render             ║
╠══════════════════════════════════════════════════════════════════╣
║  🔧 TEST AUTH: GET /api/verify-token                            ║
║  🔧 LOGIN: POST /api/login                                      ║
║  🔧 CART: GET /api/cart                                         ║
╚══════════════════════════════════════════════════════════════════╝
""")
    
    app.run(host='0.0.0.0', port=port, debug=False)
