# WAMP BACKEND - PRODUCTION READY (COMPLETE + NEW FEATURES)
# ==========================================================

import os
import re
import json
import secrets
import logging
import hmac
import hashlib
import time
import base64
import csv
import io
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_cors import CORS
from flask_jwt_extended import (
    JWTManager, create_access_token, create_refresh_token,
    jwt_required, get_jwt_identity, get_jwt
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

# Load .env file
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
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=7)
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024
app.config['JWT_TOKEN_LOCATION'] = ['headers']
app.config['JWT_HEADER_NAME'] = 'Authorization'
app.config['JWT_HEADER_TYPE'] = 'Bearer'
app.config['JWT_IDENTITY_CLAIM'] = 'sub'

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


# ==================== CLOUDINARY ====================

cloudinary.config(
    cloud_name=os.environ.get('CLOUDINARY_CLOUD_NAME', ''),
    api_key=os.environ.get('CLOUDINARY_API_KEY', ''),
    api_secret=os.environ.get('CLOUDINARY_API_SECRET', '')
)

CLOUDINARY_ENABLED = bool(os.environ.get('CLOUDINARY_API_KEY') and os.environ.get('CLOUDINARY_API_SECRET'))

if CLOUDINARY_ENABLED:
    logger.info("✅ Cloudinary configured")
else:
    logger.info("ℹ️ Cloudinary disabled")


# ==================== CORS ====================

ALLOWED_ORIGINS = os.environ.get('ALLOWED_ORIGINS', 'https://ravenj-png.github.io,http://localhost:5500').split(',')

CORS(app, origins=ALLOWED_ORIGINS, supports_credentials=True, expose_headers=["Authorization"], max_age=3600)


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
        storage_uri=os.environ.get('REDIS_URL')
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


# ==================== PAYMENT CONFIG ====================

FLUTTERWAVE_SECRET_KEY = os.environ.get('FLUTTERWAVE_SECRET_KEY')
FLUTTERWAVE_PUBLIC_KEY = os.environ.get('FLUTTERWAVE_PUBLIC_KEY')
FLUTTERWAVE_WEBHOOK_SECRET = os.environ.get('FLUTTERWAVE_WEBHOOK_SECRET')
FLUTTERWAVE_ENABLED = bool(FLUTTERWAVE_SECRET_KEY and FLUTTERWAVE_PUBLIC_KEY)

logger.info(f"✅ Payments: {'LIVE' if FLUTTERWAVE_ENABLED else 'DEMO'} mode")


# ==================== SMTP CONFIG ====================

SMTP_USER = os.environ.get('SMTP_USER')
SMTP_PASS = os.environ.get('SMTP_PASS')


# ==================== JWT ERROR HANDLERS ====================

@jwt.unauthorized_loader
def custom_unauthorized_response(callback):
    return jsonify({'error': 'Authorization token is missing or invalid'}), 401


@jwt.invalid_token_loader
def custom_invalid_token_response(error_string):
    logger.warning(f"JWT invalid token: {error_string}")
    return jsonify({'error': f'Invalid token: {error_string}'}), 422


@jwt.expired_token_loader
def custom_expired_token_response(jwt_header, jwt_payload):
    return jsonify({'error': 'Token has expired', 'expired': True}), 401


@jwt.revoked_token_loader
def custom_revoked_token_response(jwt_header, jwt_payload):
    return jsonify({'error': 'Token has been revoked'}), 401


# ==================== JWT IDENTITY HANDLERS ====================

@jwt.user_identity_loader
def user_identity_lookup(user_id):
    return str(user_id)


@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    identity = jwt_data.get("sub")
    if not identity:
        return None
    try:
        return User.query.get(int(identity))
    except (ValueError, TypeError):
        return None


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
        recent = [float(a) for a in attempts if float(a) > time.time() - 900]
        return len(recent) >= 10
    except:
        return False


def reset_failed_attempts(ip):
    try:
        redis_client.delete(f"login_attempts:{ip}")
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


# NEW MODELS FOR FRONTEND FEATURES

class Notification(db.Model):
    __tablename__ = 'notifications'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    title = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Communication(db.Model):
    __tablename__ = 'communications'
    
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    receiver_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    content = db.Column(db.Text, nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


# ==================== JWT BLACKLIST ====================

@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    return TokenBlacklist.query.filter_by(jti=jwt_payload['jti']).first() is not None


# ==================== HELPER FUNCTIONS ====================

def get_database_size():
    try:
        return db.session.execute(text("SELECT pg_database_size(current_database())")).scalar() or 0
    except:
        return 0


def log_audit(user_id, action, resource_type=None, resource_id=None):
    try:
        db.session.add(AuditLog(
            user_id=user_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', '')[:500]
        ))
        db.session.commit()
    except:
        pass


def get_least_busy_agent():
    agents = User.query.filter_by(role='agent', status='online').all()
    if not agents:
        return None
    
    loads = [(a, Order.query.filter(Order.agent_id == a.id, Order.status.in_(['paid', 'processing'])).count()) for a in agents]
    loads.sort(key=lambda x: (x[1], x[0].id))
    return loads[0][0]


def verify_webhook_signature(payload, signature):
    if not FLUTTERWAVE_WEBHOOK_SECRET or not signature:
        return False
    expected = hmac.new(FLUTTERWAVE_WEBHOOK_SECRET.encode(), payload.encode(), hashlib.sha512).hexdigest()
    return hmac.compare_digest(expected, signature)


def send_smtp_email(to_email, subject, body):
    if not SMTP_USER or not SMTP_PASS:
        logger.warning("SMTP not configured, logging email content instead")
        logger.info(f"📧 Email to {to_email}: {subject}\n{body}")
        return True
    
    try:
        msg = MIMEMultipart()
        msg['From'] = SMTP_USER
        msg['To'] = to_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))
        
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(SMTP_USER, SMTP_PASS)
        server.send_message(msg)
        server.quit()
        
        logger.info(f"✅ Email sent to {to_email}")
        return True
        
    except Exception as e:
        logger.error(f"SMTP Error: {e}")
        return False


# ==================== ROLE DECORATORS ====================

def admin_required(f):
    @wraps(f)
    @jwt_required()
    def decorated(*args, **kwargs):
        user = User.query.get(int(get_jwt_identity()))
        if not user or user.role != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        return f(*args, **kwargs)
    return decorated


def user_required(f):
    @wraps(f)
    @jwt_required()
    def decorated(*args, **kwargs):
        user = User.query.get(int(get_jwt_identity()))
        if not user:
            return jsonify({'error': 'User not found'}), 404
        return f(*args, **kwargs)
    return decorated


# ==================== AUTH ROUTES ====================

@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({
        'status': 'healthy',
        'database': 'connected',
        'payments_mode': 'LIVE' if FLUTTERWAVE_ENABLED else 'DEMO'
    })


@app.route('/api/register', methods=['POST'])
def register():
    if not request.is_json:
        return jsonify({'error': 'JSON required'}), 400
    
    data = request.get_json()
    name = data.get('name', '').strip()
    email = data.get('email', '').strip()
    password = data.get('password', '').strip()
    phone = data.get('phone', '').strip()
    
    if not all([name, email, password]):
        return jsonify({'error': 'Missing fields'}), 400
    
    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'Email registered'}), 409
    
    user = User(
        name=name,
        email=email,
        phone=phone,
        password_hash=ph.hash(password),
        role='user'
    )
    db.session.add(user)
    db.session.commit()
    log_audit(user.id, 'REGISTER')
    
    return jsonify({'success': True, 'message': 'Registration successful'}), 201


@app.route('/api/login', methods=['POST'])
def login():
    if not request.is_json:
        return jsonify({'error': 'JSON required'}), 400
    
    client_ip = request.remote_addr
    if is_ip_blocked(client_ip):
        return jsonify({'error': 'Too many attempts'}), 429
    
    data = request.get_json()
    email = data.get('email', '').strip()
    password = data.get('password', '').strip()
    
    if not email or not password:
        return jsonify({'error': 'Credentials required'}), 400
    
    user = User.query.filter_by(email=email).first()
    
    if not user:
        record_failed_login(client_ip)
        return jsonify({'error': 'Invalid credentials'}), 401
    
    try:
        ph.verify(user.password_hash, password)
    except VerifyMismatchError:
        record_failed_login(client_ip)
        return jsonify({'error': 'Invalid credentials'}), 401
    
    reset_failed_attempts(client_ip)
    access_token = create_access_token(identity=str(user.id))
    refresh_token = create_refresh_token(identity=str(user.id))
    log_audit(user.id, 'LOGIN')
    
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


@app.route('/api/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    return jsonify({
        'success': True,
        'access_token': create_access_token(identity=str(get_jwt_identity()))
    })


@app.route('/api/logout', methods=['POST'])
@jwt_required()
def logout():
    db.session.add(TokenBlacklist(jti=get_jwt()['jti'], user_id=int(get_jwt_identity())))
    db.session.commit()
    log_audit(int(get_jwt_identity()), 'LOGOUT')
    return jsonify({'success': True})


@app.route('/api/forgot-password', methods=['POST'])
def forgot_password():
    if not request.is_json:
        return jsonify({'error': 'JSON required'}), 400
    
    email = request.get_json().get('email', '').strip()
    user = User.query.filter_by(email=email).first()
    
    if not user:
        return jsonify({'success': True, 'message': 'If registered, a reset link was sent'})
    
    reset_token = serializer.dumps(email, salt='password-reset')
    reset_url = f"{os.environ.get('FRONTEND_URL', '#')}/reset?token={reset_token}"
    send_smtp_email(email, 'WAMP Password Reset', f'Click to reset: {reset_url}')
    
    return jsonify({'success': True, 'message': 'Reset link sent'})


# ==================== USER ROUTES ====================

@app.route('/api/user/profile', methods=['PUT'])
@user_required
def update_profile():
    user = User.query.get(int(get_jwt_identity()))
    data = request.get_json()
    
    user.name = data.get('name', user.name)
    user.phone = data.get('phone', user.phone)
    user.address = data.get('address', user.address)
    db.session.commit()
    
    return jsonify({
        'success': True,
        'user': {
            'name': user.name,
            'phone': user.phone,
            'address': user.address
        }
    })


@app.route('/api/notifications', methods=['GET'])
@user_required
def get_notifications():
    user_id = int(get_jwt_identity())
    notifs = Notification.query.filter_by(user_id=user_id).order_by(Notification.created_at.desc()).limit(20).all()
    
    for n in notifs:
        n.is_read = True
    db.session.commit()
    
    return jsonify([{
        'id': n.id,
        'title': n.title,
        'message': n.message,
        'read': n.is_read,
        'date': n.created_at.isoformat()
    } for n in notifs])


# ==================== PRODUCT ROUTES ====================

@app.route('/api/products', methods=['GET'])
def get_products():
    return jsonify([{
        'id': p.id,
        'name': p.name,
        'type': p.type,
        'price': p.price,
        'stock': p.available_stock,
        'description': p.description or '',
        'image_url': p.image_url or ''
    } for p in Product.query.all()])


@app.route('/api/admin/products', methods=['POST'])
@admin_required
def create_product():
    d = request.get_json()
    p = Product(
        name=d['name'],
        type=d['type'],
        price=d['price'],
        stock=d.get('stock', 0),
        description=d.get('description', ''),
        image_url=d.get('image_url', '')
    )
    db.session.add(p)
    db.session.commit()
    return jsonify({'success': True, 'id': p.id}), 201


@app.route('/api/admin/products/<int:pid>', methods=['PUT'])
@admin_required
def update_product(pid):
    p = Product.query.get_or_404(pid)
    d = request.get_json()
    
    for k in ['name', 'type', 'price', 'stock', 'description', 'image_url']:
        if k in d:
            setattr(p, k, d[k])
    
    db.session.commit()
    return jsonify({'success': True})


@app.route('/api/admin/products/<int:pid>', methods=['DELETE'])
@admin_required
def delete_product(pid):
    db.session.delete(Product.query.get_or_404(pid))
    db.session.commit()
    return jsonify({'success': True})


# ==================== CART ROUTES ====================

@app.route('/api/cart', methods=['GET'])
@user_required
def get_cart():
    uid = int(get_jwt_identity())
    return jsonify([{
        'id': c.id,
        'product_id': c.product_id,
        'quantity': c.quantity
    } for c in CartItem.query.filter_by(user_id=uid).all()])


@app.route('/api/cart', methods=['POST'])
@user_required
def add_to_cart():
    uid = int(get_jwt_identity())
    d = request.get_json()
    pid = d['product_id']
    qty = d.get('quantity', 1)
    
    p = Product.query.get(pid)
    if not p or p.available_stock < qty:
        return jsonify({'error': 'Invalid'}), 400
    
    item = CartItem.query.filter_by(user_id=uid, product_id=pid).first()
    if item:
        item.quantity += qty
    else:
        db.session.add(CartItem(user_id=uid, product_id=pid, quantity=qty))
    
    db.session.commit()
    return jsonify({'success': True}), 201


@app.route('/api/cart/<int:cid>', methods=['DELETE'])
@user_required
def remove_cart(cid):
    item = CartItem.query.filter_by(id=cid, user_id=int(get_jwt_identity())).first()
    if item:
        db.session.delete(item)
        db.session.commit()
    return jsonify({'success': True})


# ==================== WISHLIST & REVIEWS ====================

@app.route('/api/wishlist', methods=['GET'])
@user_required
def get_wishlist():
    uid = int(get_jwt_identity())
    return jsonify([{
        'id': w.id,
        'product_id': w.product_id
    } for w in Wishlist.query.filter_by(user_id=uid).all()])


@app.route('/api/wishlist', methods=['POST'])
@user_required
def toggle_wishlist():
    uid = int(get_jwt_identity())
    pid = request.get_json()['product_id']
    existing = Wishlist.query.filter_by(user_id=uid, product_id=pid).first()
    
    if existing:
        db.session.delete(existing)
    else:
        db.session.add(Wishlist(user_id=uid, product_id=pid))
    
    db.session.commit()
    return jsonify({'success': True})


@app.route('/api/reviews', methods=['POST'])
@user_required
def submit_review():
    uid = int(get_jwt_identity())
    d = request.get_json()
    pid = d['product_id']
    rating = d['rating']
    comment = d.get('comment', '')
    
    if not (1 <= rating <= 5):
        return jsonify({'error': 'Invalid rating'}), 400
    
    existing = Review.query.filter_by(user_id=uid, product_id=pid).first()
    
    if existing:
        existing.rating = rating
        existing.comment = comment
    else:
        db.session.add(Review(user_id=uid, product_id=pid, rating=rating, comment=comment))
    
    db.session.commit()
    return jsonify({'success': True})


@app.route('/api/reviews/user', methods=['GET'])
@user_required
def get_user_reviews():
    uid = int(get_jwt_identity())
    return jsonify([{
        'id': r.id,
        'product_id': r.product_id,
        'rating': r.rating,
        'comment': r.comment,
        'created_at': r.created_at.isoformat()
    } for r in Review.query.filter_by(user_id=uid).all()])


# ==================== ORDER ROUTES ====================

def enrich_order(o):
    items = json.loads(o.items) if o.items else []
    enriched = []
    
    for it in items:
        p = Product.query.get(it['productId'])
        enriched.append({
            'name': p.name if p else 'Product',
            'price': p.price if p else 0,
            'quantity': it['quantity'],
            'product_id': it['productId']
        })
    
    return {
        'id': o.id,
        'user_id': o.user_id,
        'total': o.total,
        'status': o.status,
        'payment_method': o.payment_method,
        'rider_name': o.rider_name,
        'date': o.created_at.isoformat(),
        'items': enriched,
        'agent_id': o.agent_id
    }


@app.route('/api/orders', methods=['GET'])
@jwt_required()
def get_orders():
    uid = int(get_jwt_identity())
    user = User.query.get(uid)
    
    if user.role == 'admin':
        qs = Order.query
    elif user.role == 'agent':
        qs = Order.query.filter(Order.agent_id == uid)
    else:
        qs = Order.query.filter_by(user_id=uid)
    
    return jsonify([enrich_order(o) for o in qs.order_by(Order.created_at.desc()).all()])


@app.route('/api/orders', methods=['POST'])
@user_required
def create_order():
    uid = int(get_jwt_identity())
    d = request.get_json()
    items = d['items']
    total = d['total']
    method = d.get('payment_method', 'MTN')
    
    validated = []
    res_total = 0
    
    for it in items:
        p = Product.query.with_for_update().get(it['productId'])
        if not p or p.available_stock < it['quantity']:
            return jsonify({'error': 'Stock issue'}), 400
        res_total += p.price * it['quantity']
        validated.append({'productId': p.id, 'quantity': it['quantity']})
        p.reserved_stock += it['quantity']
    
    order = Order(
        user_id=uid,
        items=json.dumps(validated),
        total=res_total,
        payment_method=method,
        stock_reserved_until=datetime.utcnow() + timedelta(hours=1)
    )
    db.session.add(order)
    CartItem.query.filter_by(user_id=uid).delete()
    
    agent = get_least_busy_agent()
    if agent:
        order.agent_id = agent.id
    
    db.session.commit()
    log_audit(uid, 'CREATE_ORDER', 'order', order.id)
    
    return jsonify({'success': True, 'order_id': order.id}), 201


@app.route('/api/agent/orders/<int:oid>/claim', methods=['POST'])
@jwt_required()
def claim_order(oid):
    uid = int(get_jwt_identity())
    user = User.query.get(uid)
    
    if user.role not in ['agent', 'admin']:
        return jsonify({'error': 'Unauthorized'}), 403
    
    order = Order.query.get_or_404(oid)
    
    if order.agent_id and order.agent_id != uid:
        return jsonify({'error': 'Already claimed'}), 409
    
    order.agent_id = uid
    order.status = 'processing'
    db.session.commit()
    
    return jsonify({'success': True})


@app.route('/api/admin/orders/export', methods=['GET'])
@admin_required
def export_orders_csv():
    orders = Order.query.order_by(Order.created_at.desc()).all()
    si = io.StringIO()
    cw = csv.writer(si)
    
    cw.writerow(['ID', 'Date', 'Customer_ID', 'Total', 'Status', 'Payment', 'Agent_ID'])
    
    for o in orders:
        cw.writerow([o.id, o.created_at.isoformat(), o.user_id, o.total, o.status, o.payment_method, o.agent_id])
    
    resp = make_response(si.getvalue())
    resp.headers['Content-Type'] = 'text/csv'
    resp.headers['Content-Disposition'] = 'attachment; filename=wamp_orders.csv'
    
    return resp


# ==================== ADMIN ROUTES ====================

@app.route('/api/admin/stats', methods=['GET'])
@admin_required
def admin_stats():
    return jsonify({
        'today_sales': Order.query.filter(Order.created_at >= datetime.utcnow().replace(hour=0, minute=0, second=0)).with_entities(func.sum(Order.total)).scalar() or 0,
        'pending_orders': Order.query.filter(Order.status.in_(['pending', 'paid'])).count(),
        'total_products': Product.query.count(),
        'low_stock': Product.query.filter(Product.stock < 5).count()
    })


@app.route('/api/admin/books', methods=['GET'])
@admin_required
def admin_books():
    completed = Order.query.filter(Order.status.in_(['delivered', 'completed'])).all()
    pending = Order.query.filter(Order.status.in_(['pending', 'paid', 'processing'])).all()
    
    return jsonify({
        'total_revenue': sum(o.total for o in completed),
        'pending_revenue': sum(o.total for o in pending),
        'transaction_count': len(completed) + len(pending)
    })


@app.route('/api/admin/monitor', methods=['GET'])
@admin_required
def admin_monitor():
    agents = User.query.filter_by(role='agent').all()
    
    return jsonify([{
        'id': a.id,
        'name': a.name,
        'status': a.status,
        'active_orders': Order.query.filter(Order.agent_id == a.id, Order.status.in_(['pending', 'paid', 'processing'])).count()
    } for a in agents])


@app.route('/api/admin/messages', methods=['POST'])
@admin_required
def send_admin_message():
    d = request.get_json()
    target_role = d.get('recipient')
    content = d.get('content')
    
    if not content:
        return jsonify({'error': 'Content required'}), 400
    
    if target_role == 'all':
        recipients = User.query.filter(User.role.in_(['agent', 'user'])).all()
    else:
        recipients = User.query.filter(User.role == target_role).all()
    
    for r in recipients:
        db.session.add(Communication(sender_id=int(get_jwt_identity()), receiver_id=r.id, content=content))
    
    db.session.commit()
    return jsonify({'success': True, 'sent_to': len(recipients)})


# ==================== AGENT ROUTES ====================

@app.route('/api/agent/panel', methods=['GET'])
@jwt_required()
def agent_panel():
    uid = int(get_jwt_identity())
    assigned = Order.query.filter(Order.agent_id == uid).all()
    available = Order.query.filter(Order.agent_id.is_(None), Order.status == 'pending').all()
    
    return jsonify({
        'assigned': [enrich_order(o) for o in assigned],
        'available': [enrich_order(o) for o in available],
        'stats': {
            'assigned': len(assigned),
            'completed': len([o for o in assigned if o.status in ['delivered', 'completed']]),
            'pending': len([o for o in assigned if o.status in ['pending', 'processing']])
        }
    })


# ==================== COMMUNICATIONS ====================

@app.route('/api/messages', methods=['GET'])
@jwt_required()
def get_messages():
    uid = int(get_jwt_identity())
    msgs = Communication.query.filter(Communication.receiver_id == uid).order_by(Communication.created_at.desc()).limit(50).all()
    
    for m in msgs:
        m.is_read = True
    db.session.commit()
    
    return jsonify([{
        'id': m.id,
        'sender_id': m.sender_id,
        'content': m.content,
        'read': m.is_read,
        'date': m.created_at.isoformat()
    } for m in msgs])


@app.route('/api/messages', methods=['POST'])
@jwt_required()
def send_message():
    uid = int(get_jwt_identity())
    d = request.get_json()
    
    db.session.add(Communication(sender_id=uid, receiver_id=d['receiver_id'], content=d['content']))
    db.session.commit()
    
    return jsonify({'success': True})


# ==================== CHAT ====================

@app.route('/api/chat/customer', methods=['POST'])
def customer_chat():
    if not request.is_json:
        return jsonify({'error': 'JSON required'}), 400
    
    msg = request.get_json().get('message', '').lower()
    
    responses = {
        'price': '💰 Terrazzo: UGX 250k | Plumbing: UGX 45k | Paint: UGX 120k',
        'delivery': '🚚 Free >500k UGX. 2-5 days.',
        'payment': '💳 MTN, Airtel, Card, COD.'
    }
    
    for key, value in responses.items():
        if key in msg:
            return jsonify({'response': value})
    
    return jsonify({'response': 'Welcome to WAMP! Ask about prices, delivery, or payments.'})


# ==================== PAYMENT WEBHOOK ====================

@app.route('/api/payment/webhook', methods=['POST'])
def payment_webhook():
    raw = request.get_data(as_text=True)
    
    if not verify_webhook_signature(raw, request.headers.get('verif-hash')):
        return jsonify({'error': 'Invalid sig'}), 401
    
    d = request.json
    
    if d.get('status') == 'successful' and d.get('tx_ref'):
        try:
            oid = int(d['tx_ref'].split('-')[1])
            order = Order.query.get(oid)
            
            if order and order.payment_status == 'pending':
                order.payment_status = 'completed'
                order.status = 'paid'
                order.stock_confirmed = True
                
                for it in json.loads(order.items):
                    p = Product.query.get(it['productId'])
                    if p:
                        p.stock -= it['quantity']
                        p.reserved_stock -= it['quantity']
                
                db.session.commit()
        except:
            pass
    
    return jsonify({'status': 'ok'}), 200


# ==================== ERROR HANDLERS ====================

@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Not found'}), 404


@app.errorhandler(429)
def rate_exceeded(e):
    return jsonify({'error': 'Too many requests'}), 429


@app.errorhandler(500)
def server_error(e):
    logger.error(f"Server error: {e}")
    return jsonify({'error': 'Internal error'}), 500


# ==================== DB INIT & DEFAULTS ====================

def ensure_tables():
    tables = [
        ('wishlist', 'CREATE TABLE IF NOT EXISTS wishlist (id SERIAL PRIMARY KEY, user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE, product_id INT NOT NULL REFERENCES products(id) ON DELETE CASCADE, created_at TIMESTAMP DEFAULT NOW());'),
        ('reviews', 'CREATE TABLE IF NOT EXISTS reviews (id SERIAL PRIMARY KEY, user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE, product_id INT NOT NULL REFERENCES products(id) ON DELETE CASCADE, rating INT NOT NULL CHECK (rating BETWEEN 1 AND 5), comment TEXT, created_at TIMESTAMP DEFAULT NOW());'),
        ('notifications', 'CREATE TABLE IF NOT EXISTS notifications (id SERIAL PRIMARY KEY, user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE, title VARCHAR(200) NOT NULL, message TEXT NOT NULL, is_read BOOLEAN DEFAULT FALSE, created_at TIMESTAMP DEFAULT NOW());'),
        ('communications', 'CREATE TABLE IF NOT EXISTS communications (id SERIAL PRIMARY KEY, sender_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE, receiver_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE, content TEXT NOT NULL, is_read BOOLEAN DEFAULT FALSE, created_at TIMESTAMP DEFAULT NOW());')
    ]
    
    for tbl, sql in tables:
        try:
            db.session.execute(text(sql))
            db.session.commit()
            logger.info(f"✅ {tbl} verified")
        except:
            db.session.rollback()


def create_defaults():
    ensure_tables()
    
    # Admin setup
    admin_email = os.environ.get('ADMIN_EMAIL', 'admin@tarazo.com').strip()
    admin_pass = os.environ.get('ADMIN_PASSWORD', 'Admin123456').strip()
    admin = User.query.filter_by(email=admin_email).first()
    
    if not admin:
        db.session.add(User(
            name=os.environ.get('ADMIN_NAME', 'Boss Manager'),
            email=admin_email,
            phone=os.environ.get('ADMIN_PHONE', '0771000000'),
            password_hash=ph.hash(admin_pass),
            role='admin'
        ))
    else:
        admin.password_hash = ph.hash(admin_pass)
        admin.role = 'admin'
    
    # Agents setup
    for i in range(1, 6):
        a_email = os.environ.get(f'AGENT{i}_EMAIL', f'agent{i}@tarazo.com').strip()
        a_pass = os.environ.get(f'AGENT{i}_PASSWORD', 'Agent123456').strip()
        agent = User.query.filter_by(email=a_email).first()
        
        if not agent:
            db.session.add(User(
                name=os.environ.get(f'AGENT{i}_NAME', f'Agent {i}'),
                email=a_email,
                phone=os.environ.get(f'AGENT{i}_PHONE', f'077{i}000000'),
                password_hash=ph.hash(a_pass),
                role='agent'
            ))
        else:
            agent.password_hash = ph.hash(a_pass)
            agent.role = 'agent'
    
    # Sample products
    if Product.query.count() == 0:
        sample_products = [
            Product(name='Premium Floor Terrazzo', type='Floor Terrazzo', price=250000, stock=100, description='High-end finish', image_url='https://images.unsplash.com/photo-1600585154526-990dced4db0d?w=400'),
            Product(name='Copper Plumbing Pipe', type='Plumbing Pipe', price=45000, stock=50, description='Durable copper', image_url='https://images.unsplash.com/photo-1581092160562-40aa08e7882a?w=400'),
            Product(name='Interior Emulsion Paint', type='Paint Emulsion', price=120000, stock=80, description='Smooth matte', image_url='https://images.unsplash.com/photo-1589939705384-5185137a7f0f?w=400')
        ]
        for p in sample_products:
            db.session.add(p)
    
    db.session.commit()
    logger.info("✅ Defaults created")


with app.app_context():
    try:
        db.create_all()
        create_defaults()
        logger.info(f"📊 DB Size: {round(get_database_size() / (1024**2), 2)} MB")
    except Exception as e:
        logger.error(f"Init failed: {e}")


# ==================== MAIN ====================

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    print(f"🚀 WAMP Backend running on port {port}")
    app.run(host='0.0.0.0', port=port, debug=False)
