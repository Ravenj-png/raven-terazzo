# WAMP BACKEND - COMPLETE PRODUCTION (NO HARD-CODED CREDENTIALS)
# ================================================================

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
from sqlalchemy import func, text
from sqlalchemy.exc import SQLAlchemyError
from dotenv import load_dotenv
from werkzeug.middleware.proxy_fix import ProxyFix

# Cloudinary for image upload
import cloudinary
import cloudinary.uploader

# Redis for rate limiting
import redis

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
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=7)
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5MB
app.config['JWT_TOKEN_LOCATION'] = ['headers']
app.config['JWT_HEADER_NAME'] = 'Authorization'
app.config['JWT_HEADER_TYPE'] = 'Bearer'
app.config['JWT_IDENTITY_CLAIM'] = 'sub'

# Check required secrets
if not app.config['SECRET_KEY']:
    logger.error("❌ SECRET_KEY not set in environment variables!")
if not app.config['JWT_SECRET_KEY']:
    logger.error("❌ JWT_SECRET_KEY not set in environment variables!")

# Database
database_url = os.environ.get('DATABASE_URL')
if not database_url:
    logger.error("❌ DATABASE_URL not set in environment variables!")

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
    logger.info("ℹ️ Cloudinary not configured - images stored in database only")

# ==================== CORS ====================
ALLOWED_ORIGINS = os.environ.get('ALLOWED_ORIGINS', 'https://ravenj-png.github.io,http://localhost:5500,http://localhost:5000,https://raven-terazzo.onrender.com').split(',')

CORS(app, origins=ALLOWED_ORIGINS, supports_credentials=True,
     methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
     allow_headers=["Content-Type", "Authorization", "X-Requested-With", "Accept"],
     expose_headers=["Content-Type", "Authorization"],
     max_age=3600)

# ==================== REDIS (Rate Limiting) ====================
try:
    redis_url = os.environ.get('REDIS_URL')
    if redis_url:
        redis_client = redis.from_url(redis_url, socket_timeout=5, decode_responses=True)
        redis_client.ping()
        logger.info("✅ Redis connected")
    else:
        redis_client = None
        logger.info("ℹ️ Redis not configured - rate limiting disabled")
except Exception as e:
    redis_client = None
    logger.warning(f"⚠️ Redis connection failed: {e}")

# ==================== EXTENSIONS ====================
jwt = JWTManager(app)
db = SQLAlchemy(app)
migrate = Migrate(app, db)
ph = PasswordHasher()
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'] or 'fallback-for-serializer')

# ==================== BRUTE FORCE PROTECTION ====================
def record_failed_login(ip):
    if not redis_client:
        return
    try:
        key = f"login_attempts:{ip}"
        redis_client.lpush(key, time.time())
        redis_client.ltrim(key, 0, 9)
        redis_client.expire(key, 900)
    except:
        pass

def is_ip_blocked(ip):
    if not redis_client:
        return False
    try:
        key = f"login_attempts:{ip}"
        attempts = redis_client.lrange(key, 0, -1)
        now = time.time()
        recent = [float(a) for a in attempts if float(a) > now - 900]
        return len(recent) >= 10
    except:
        return False

def reset_failed_attempts(ip):
    if not redis_client:
        return
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
    category = db.Column(db.String(50), nullable=False, index=True)  # Terrazzo, Plumbing, General
    price = db.Column(db.Integer, nullable=False)
    stock = db.Column(db.Integer, default=0)
    reserved_stock = db.Column(db.Integer, default=0)
    description = db.Column(db.Text)
    image_url = db.Column(db.String(500))
    image_data = db.Column(db.Text)
    image_type = db.Column(db.String(20), default='url')  # 'url', 'db', 'cloudinary'
    image_mime = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
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

@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    return TokenBlacklist.query.filter_by(jti=jwt_payload['jti']).first() is not None

# ==================== JWT IDENTITY FIX ====================
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

def send_notification(user_id, title, message):
    try:
        notif = Notification(user_id=user_id, title=title, message=message)
        db.session.add(notif)
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

def release_expired_reservations():
    """Release stock reservations older than 1 hour"""
    expired_orders = Order.query.filter(
        Order.stock_reserved_until < datetime.utcnow(),
        Order.stock_confirmed == False
    ).all()
    
    for order in expired_orders:
        items = json.loads(order.items) if order.items else []
        for item in items:
            product = Product.query.get(item['productId'])
            if product:
                product.reserved_stock -= item['quantity']
        order.stock_reserved_until = None
    db.session.commit()

# ==================== DATABASE INITIALIZATION (NO HARD-CODED CREDENTIALS) ====================
def ensure_tables_and_defaults():
    """Create all tables and default data from ENV variables only - NO HARD-CODED VALUES"""
    
    # Create tables
    db.create_all()
    logger.info("✅ Tables created/verified")
    
    # Release expired reservations on startup
    release_expired_reservations()
    
    # ============================================
    # IMPORTANT: These values MUST come from .env
    # No hard-coded fallbacks!
    # ============================================
    
    admin_email = os.environ.get('ADMIN_EMAIL')
    admin_password = os.environ.get('ADMIN_PASSWORD')
    admin_name = os.environ.get('ADMIN_NAME', 'System Administrator')
    admin_phone = os.environ.get('ADMIN_PHONE', '0771000000')
    
    # Check if admin credentials are provided
    if not admin_email or not admin_password:
        logger.warning("⚠️ ADMIN_EMAIL or ADMIN_PASSWORD not set in environment variables!")
        logger.warning("⚠️ Admin account will NOT be created automatically!")
        logger.warning("⚠️ Please set ADMIN_EMAIL and ADMIN_PASSWORD in your .env file")
    else:
        admin = User.query.filter_by(email=admin_email).first()
        if not admin:
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
            logger.info(f"✅ Created admin from ENV: {admin_email}")
        else:
            admin.password_hash = ph.hash(admin_password)
            admin.role = 'admin'
            admin.status = 'online'
            logger.info(f"✅ Updated admin from ENV: {admin_email}")
    
    # Create agents from environment variables (only if provided)
    for i in range(1, 6):
        agent_email = os.environ.get(f'AGENT{i}_EMAIL')
        agent_password = os.environ.get(f'AGENT{i}_PASSWORD')
        agent_name = os.environ.get(f'AGENT{i}_NAME', f'Agent {i}')
        agent_phone = os.environ.get(f'AGENT{i}_PHONE', f'077{i}000000')
        
        # Only create agent if email and password are provided
        if agent_email and agent_password:
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
                logger.info(f"✅ Created agent from ENV: {agent_email}")
            else:
                agent.password_hash = ph.hash(agent_password)
                agent.role = 'agent'
                agent.status = 'online'
                logger.info(f"✅ Updated agent from ENV: {agent_email}")
        else:
            logger.info(f"ℹ️ AGENT{i}_EMAIL or PASSWORD not set - skipping agent {i}")
    
    # ============================================
    # NO HARD-CODED PRODUCTS!
    # Products should be added via Admin panel only
    # Categories are: Terrazzo, Plumbing, General
    # ============================================
    
    db.session.commit()
    logger.info("✅ Database initialization complete from ENV variables")

# ==================== AUTH ROUTES ====================
@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({
        'status': 'healthy',
        'database': 'connected' if database_url else 'not configured',
        'cloudinary': CLOUDINARY_ENABLED,
        'redis': redis_client is not None,
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

        access_token = create_access_token(identity=str(user.id))
        refresh_token = create_refresh_token(identity=str(user.id))

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
    access_token = create_access_token(identity=str(user_id))
    return jsonify({'success': True, 'access_token': access_token})

@app.route('/api/logout', methods=['POST'])
@jwt_required()
def logout():
    jti = get_jwt()['jti']
    user_id = get_jwt_identity()
    blacklist = TokenBlacklist(jti=jti, user_id=int(user_id))
    db.session.add(blacklist)
    db.session.commit()
    log_audit(int(user_id), 'LOGOUT', 'user', int(user_id))
    return jsonify({'success': True})

# ==================== USER ROUTES ====================
@app.route('/api/user/profile', methods=['PUT'])
@jwt_required()
def update_profile():
    user_id = int(get_jwt_identity())
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
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
@jwt_required()
def get_notifications():
    user_id = int(get_jwt_identity())
    notifs = Notification.query.filter_by(user_id=user_id, is_read=False).order_by(Notification.created_at.desc()).limit(20).all()
    
    for n in notifs:
        n.is_read = True
    db.session.commit()
    
    return jsonify([{
        'id': n.id,
        'title': n.title,
        'message': n.message,
        'date': n.created_at.isoformat()
    } for n in notifs])

# ==================== PRODUCT ROUTES ====================
@app.route('/api/products', methods=['GET'])
def get_products():
    try:
        release_expired_reservations()
        
        products = Product.query.all()
        result = []
        for p in products:
            product_data = {
                'id': p.id,
                'name': p.name,
                'category': p.category,
                'price': p.price,
                'stock': p.available_stock,
                'description': p.description or '',
                'image_type': p.image_type
            }
            
            # HYBRID STORAGE: Priority: Cloudinary URL > Database base64 > External URL
            if p.image_type == 'cloudinary' and p.image_url:
                product_data['image_url'] = p.image_url
            elif p.image_type == 'db' and p.image_data:
                product_data['image_data'] = p.image_data
                product_data['image_mime'] = p.image_mime
            else:
                product_data['image_url'] = p.image_url or ''
            
            result.append(product_data)
        
        return jsonify(result)
    
    except Exception as e:
        logger.error(f"Get products error: {e}")
        return jsonify({'error': 'Failed to fetch products'}), 500

@app.route('/api/products/search', methods=['GET'])
def search_products():
    try:
        query = request.args.get('q', '').strip()
        category = request.args.get('category', '').strip()
        
        products_query = Product.query
        
        if query:
            products_query = products_query.filter(
                Product.name.ilike(f'%{query}%') | 
                Product.description.ilike(f'%{query}%')
            )
        
        if category and category != 'all':
            products_query = products_query.filter(Product.category == category)
        
        products = products_query.all()
        
        result = []
        for p in products:
            product_data = {
                'id': p.id,
                'name': p.name,
                'category': p.category,
                'price': p.price,
                'stock': p.available_stock,
                'description': p.description or '',
                'image_type': p.image_type
            }
            
            if p.image_type == 'cloudinary' and p.image_url:
                product_data['image_url'] = p.image_url
            elif p.image_type == 'db' and p.image_data:
                product_data['image_data'] = p.image_data
            else:
                product_data['image_url'] = p.image_url or ''
            
            result.append(product_data)
        
        return jsonify(result)
    
    except Exception as e:
        logger.error(f"Search products error: {e}")
        return jsonify({'error': 'Search failed'}), 500

@app.route('/api/admin/products', methods=['POST'])
@jwt_required()
def create_product():
    try:
        user = User.query.get(int(get_jwt_identity()))
        if user.role != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        
        data = request.get_json()
        category = data.get('category', '').strip()
        
        # Validate category
        valid_categories = ['Terrazzo', 'Plumbing', 'General']
        if category not in valid_categories:
            return jsonify({'error': f'Invalid category. Must be one of: {", ".join(valid_categories)}'}), 400
        
        product = Product(
            name=data.get('name'),
            category=category,
            price=data.get('price'),
            stock=data.get('stock', 0),
            description=data.get('description', ''),
            image_url=data.get('image_url', ''),
            image_type='url'
        )
        db.session.add(product)
        db.session.commit()
        log_audit(user.id, 'CREATE_PRODUCT', 'product', product.id)
        
        return jsonify({'success': True, 'id': product.id}), 201
    
    except Exception as e:
        logger.error(f"Create product error: {e}")
        return jsonify({'error': 'Failed to create product'}), 500

@app.route('/api/admin/products/upload', methods=['POST'])
@jwt_required()
def upload_product_image():
    try:
        user = User.query.get(int(get_jwt_identity()))
        if user.role != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        
        if 'image' not in request.files:
            return jsonify({'error': 'No image file'}), 400

        file = request.files['image']
        product_id = request.form.get('product_id')

        if not product_id:
            return jsonify({'error': 'Product ID required'}), 400

        product = Product.query.get(product_id)
        if not product:
            return jsonify({'error': 'Product not found'}), 404

        # Check file size
        file.seek(0, 2)
        if file.tell() > 5 * 1024 * 1024:
            return jsonify({'error': 'Image too large. Max 5MB'}), 400
        file.seek(0)

        file_content = file.read()
        
        # STEP 1: ALWAYS store in database as backup (Hybrid Storage)
        product.image_data = base64.b64encode(file_content).decode('utf-8')
        product.image_mime = file.mimetype
        product.image_type = 'db'
        product.image_url = None
        
        cloudinary_success = False
        
        # STEP 2: Try Cloudinary for better performance (if configured)
        if CLOUDINARY_ENABLED:
            try:
                file.seek(0)  # Reset file pointer
                result = cloudinary.uploader.upload(file, folder='wamp_products')
                product.image_url = result['secure_url']
                product.image_type = 'cloudinary'  # Priority to Cloudinary
                cloudinary_success = True
                logger.info(f"✅ Image uploaded to Cloudinary for product {product_id}")
            except Exception as e:
                logger.error(f"Cloudinary upload failed: {e}")
                # Keep using DB storage (already set above)

        db.session.commit()
        log_audit(user.id, 'UPLOAD_IMAGE', 'product', product.id)
        
        return jsonify({
            'success': True,
            'image_type': product.image_type,
            'cloudinary_used': cloudinary_success,
            'message': 'Image stored in database' + (' and Cloudinary' if cloudinary_success else ' only')
        })
    
    except Exception as e:
        logger.error(f"Upload image error: {e}")
        return jsonify({'error': 'Upload failed'}), 500

@app.route('/api/admin/products/<int:product_id>', methods=['PUT'])
@jwt_required()
def update_product(product_id):
    try:
        user = User.query.get(int(get_jwt_identity()))
        if user.role != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        
        product = Product.query.get_or_404(product_id)
        data = request.get_json()
        
        product.name = data.get('name', product.name)
        
        category = data.get('category', '').strip()
        valid_categories = ['Terrazzo', 'Plumbing', 'General']
        if category and category in valid_categories:
            product.category = category
        
        product.price = data.get('price', product.price)
        product.stock = data.get('stock', product.stock)
        product.description = data.get('description', product.description)
        
        if data.get('image_url') and product.image_type != 'db':
            product.image_url = data.get('image_url')
            product.image_type = 'url'
        
        db.session.commit()
        log_audit(user.id, 'UPDATE_PRODUCT', 'product', product.id)
        
        return jsonify({'success': True})
    
    except Exception as e:
        logger.error(f"Update product error: {e}")
        return jsonify({'error': 'Failed to update product'}), 500

@app.route('/api/admin/products/<int:product_id>', methods=['DELETE'])
@jwt_required()
def delete_product(product_id):
    try:
        user = User.query.get(int(get_jwt_identity()))
        if user.role != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        
        product = Product.query.get_or_404(product_id)
        db.session.delete(product)
        db.session.commit()
        log_audit(user.id, 'DELETE_PRODUCT', 'product', product.id)
        
        return jsonify({'success': True})
    
    except Exception as e:
        logger.error(f"Delete product error: {e}")
        return jsonify({'error': 'Failed to delete product'}), 500

@app.route('/api/products/categories', methods=['GET'])
def get_categories():
    return jsonify(['Terrazzo', 'Plumbing', 'General'])

# ==================== CART ROUTES ====================
@app.route('/api/cart', methods=['GET'])
@jwt_required()
def get_cart():
    try:
        user_id = int(get_jwt_identity())
        cart_items = CartItem.query.filter_by(user_id=user_id).all()
        
        result = []
        for item in cart_items:
            product = Product.query.get(item.product_id)
            if product:
                result.append({
                    'id': item.id,
                    'product_id': item.product_id,
                    'quantity': item.quantity,
                    'product_name': product.name,
                    'product_price': product.price,
                    'product_image': product.image_url if product.image_type == 'cloudinary' else None
                })
        
        return jsonify(result)
    
    except Exception as e:
        logger.error(f"Get cart error: {e}")
        return jsonify({'error': 'Failed to fetch cart'}), 500

@app.route('/api/cart', methods=['POST'])
@jwt_required()
def add_to_cart():
    try:
        if not request.is_json:
            return jsonify({'error': 'Content-Type must be application/json'}), 400
        
        user_id = int(get_jwt_identity())
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
        user_id = int(get_jwt_identity())
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
        user_id = int(get_jwt_identity())
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
        user_id = int(get_jwt_identity())
        items = Wishlist.query.filter_by(user_id=user_id).all()
        
        result = []
        for item in items:
            product = Product.query.get(item.product_id)
            if product:
                result.append({
                    'id': item.id,
                    'product_id': item.product_id,
                    'name': product.name,
                    'price': product.price,
                    'image_url': product.image_url
                })
        
        return jsonify(result)
    
    except Exception as e:
        logger.error(f"Get wishlist error: {e}")
        return jsonify({'error': 'Failed to fetch wishlist'}), 500

@app.route('/api/wishlist', methods=['POST'])
@jwt_required()
def toggle_wishlist():
    try:
        if not request.is_json:
            return jsonify({'error': 'Content-Type must be application/json'}), 400
        
        user_id = int(get_jwt_identity())
        data = request.get_json()
        product_id = data.get('product_id')

        if not product_id:
            return jsonify({'error': 'Product ID required'}), 400

        existing = Wishlist.query.filter_by(user_id=user_id, product_id=product_id).first()
        
        if existing:
            db.session.delete(existing)
            db.session.commit()
            return jsonify({'success': True, 'action': 'removed', 'message': 'Removed from wishlist'})
        else:
            wishlist_item = Wishlist(user_id=user_id, product_id=product_id)
            db.session.add(wishlist_item)
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
        
        user_id = int(get_jwt_identity())
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

        existing = Review.query.filter_by(user_id=user_id, product_id=product_id).first()
        
        if existing:
            existing.rating = rating
            existing.comment = comment
        else:
            review = Review(user_id=user_id, product_id=product_id, rating=rating, comment=comment)
            db.session.add(review)

        db.session.commit()
        return jsonify({'success': True, 'message': 'Review saved'})
    
    except Exception as e:
        logger.error(f"Submit review error: {e}")
        return jsonify({'error': 'Failed to submit review'}), 500

@app.route('/api/reviews/user', methods=['GET'])
@jwt_required()
def get_user_reviews():
    try:
        user_id = int(get_jwt_identity())
        reviews = Review.query.filter_by(user_id=user_id).all()
        
        result = []
        for r in reviews:
            product = Product.query.get(r.product_id)
            result.append({
                'id': r.id,
                'product_id': r.product_id,
                'product_name': product.name if product else 'Unknown',
                'rating': r.rating,
                'comment': r.comment,
                'created_at': r.created_at.isoformat()
            })
        
        return jsonify(result)
    
    except Exception as e:
        logger.error(f"Get user reviews error: {e}")
        return jsonify({'error': 'Failed to fetch reviews'}), 500

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

# ==================== ORDER ROUTES ====================
def enrich_order(order):
    items = json.loads(order.items) if order.items else []
    enriched_items = []
    
    for item in items:
        product = Product.query.get(item.get('productId'))
        enriched_items.append({
            'name': product.name if product else 'Product',
            'price': product.price if product else 0,
            'quantity': item.get('quantity', 1),
            'product_id': item.get('productId')
        })
    
    return {
        'id': order.id,
        'user_id': order.user_id,
        'agent_id': order.agent_id,
        'total': order.total,
        'status': order.status,
        'payment_method': order.payment_method,
        'payment_status': order.payment_status,
        'rider_name': order.rider_name,
        'rider_phone': order.rider_phone,
        'delivery_location': order.delivery_location,
        'items': enriched_items,
        'created_at': order.created_at.isoformat()
    }

@app.route('/api/orders', methods=['GET'])
@jwt_required()
def get_orders():
    try:
        user_id = int(get_jwt_identity())
        user = User.query.get(user_id)

        if user.role == 'admin':
            orders = Order.query.order_by(Order.created_at.desc()).all()
        elif user.role == 'agent':
            orders = Order.query.filter_by(agent_id=user_id).order_by(Order.created_at.desc()).all()
        else:
            orders = Order.query.filter_by(user_id=user_id).order_by(Order.created_at.desc()).all()

        return jsonify([enrich_order(o) for o in orders])
    
    except Exception as e:
        logger.error(f"Get orders error: {e}")
        return jsonify({'error': 'Failed to fetch orders'}), 500

@app.route('/api/orders', methods=['POST'])
@jwt_required()
def create_order():
    try:
        if not request.is_json:
            return jsonify({'error': 'Content-Type must be application/json'}), 400
        
        user_id = int(get_jwt_identity())
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
                'quantity': quantity
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

        # Assign least busy agent
        agent = get_least_busy_agent()
        if agent:
            order.agent_id = agent.id
            db.session.commit()
            send_notification(agent.id, 'New Order Assigned', f'Order #{order.id} has been assigned to you')

        # Notify user
        send_notification(user_id, 'Order Created', f'Your order #{order.id} has been created successfully')

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
        user_id = int(get_jwt_identity())
        user = User.query.get(user_id)
        
        if user.role != 'admin' and (user.role == 'agent' and order.agent_id != user_id):
            return jsonify({'error': 'Permission denied'}), 403
        
        old_status = order.status
        order.status = data.get('status', order.status)
        db.session.commit()
        
        # Notify customer
        if old_status != order.status:
            send_notification(order.user_id, 'Order Status Updated', f'Your order #{order_id} is now {order.status}')
        
        return jsonify({'success': True})
    
    except Exception as e:
        logger.error(f"Update order status error: {e}")
        return jsonify({'error': 'Failed to update order'}), 500

# ==================== AGENT ROUTES ====================
@app.route('/api/agent/orders/<int:order_id>/claim', methods=['POST'])
@jwt_required()
def claim_order(order_id):
    try:
        user_id = int(get_jwt_identity())
        user = User.query.get(user_id)
        
        if user.role not in ['agent', 'admin']:
            return jsonify({'error': 'Agent access required'}), 403
        
        order = Order.query.get_or_404(order_id)
        
        if order.agent_id:
            return jsonify({'error': 'Order already claimed'}), 409
        
        order.agent_id = user_id
        order.status = 'processing'
        db.session.commit()
        
        send_notification(user_id, 'Order Claimed', f'You have claimed order #{order_id}')
        send_notification(order.user_id, 'Order Claimed', f'Your order #{order_id} is now being processed')
        
        return jsonify({'success': True})
    
    except Exception as e:
        logger.error(f"Claim order error: {e}")
        return jsonify({'error': 'Failed to claim order'}), 500

@app.route('/api/agent/panel', methods=['GET'])
@jwt_required()
def agent_panel():
    try:
        user_id = int(get_jwt_identity())
        user = User.query.get(user_id)
        
        if user.role not in ['agent', 'admin']:
            return jsonify({'error': 'Agent access required'}), 403
        
        if user.role == 'admin':
            assigned = Order.query.filter(Order.agent_id.isnot(None)).order_by(Order.created_at.desc()).all()
            available = Order.query.filter(Order.agent_id.is_(None), Order.status == 'pending').all()
        else:
            assigned = Order.query.filter_by(agent_id=user_id).order_by(Order.created_at.desc()).all()
            available = Order.query.filter(Order.agent_id.is_(None), Order.status == 'pending').all()
        
        return jsonify({
            'assigned': [enrich_order(o) for o in assigned],
            'available': [enrich_order(o) for o in available],
            'stats': {
                'assigned': len([o for o in assigned if o.status in ['pending', 'processing']]),
                'completed': len([o for o in assigned if o.status in ['delivered', 'completed']]),
                'pending': len([o for o in assigned if o.status == 'assigned'])
            }
        })
    
    except Exception as e:
        logger.error(f"Agent panel error: {e}")
        return jsonify({'error': 'Failed to load agent panel'}), 500

# ==================== RIDER ASSIGNMENT ====================
@app.route('/api/admin/orders/<int:order_id>/assign-rider', methods=['PUT'])
@jwt_required()
def assign_rider(order_id):
    try:
        user_id = int(get_jwt_identity())
        user = User.query.get(user_id)
        
        if user.role not in ['admin', 'agent']:
            return jsonify({'error': 'Permission denied'}), 403
        
        data = request.get_json()
        order = Order.query.get_or_404(order_id)
        
        order.rider_name = data.get('rider_name')
        order.rider_phone = data.get('rider_phone')
        order.status = 'shipped'
        db.session.commit()
        
        send_notification(order.user_id, 'Rider Assigned', f'A rider has been assigned to your order #{order_id}')
        
        return jsonify({'success': True})
    
    except Exception as e:
        logger.error(f"Assign rider error: {e}")
        return jsonify({'error': 'Failed to assign rider'}), 500

# ==================== ADMIN ROUTES ====================
@app.route('/api/admin/stats', methods=['GET'])
@jwt_required()
def admin_stats():
    try:
        user = User.query.get(int(get_jwt_identity()))
        if user.role != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        
        today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
        today_sales = db.session.query(func.sum(Order.total)).filter(
            Order.created_at >= today_start,
            Order.status.in_(['delivered', 'completed'])
        ).scalar() or 0
        
        pending_orders = Order.query.filter(Order.status.in_(['pending', 'paid'])).count()
        total_products = Product.query.count()
        low_stock = Product.query.filter(Product.stock < 5).count()
        
        return jsonify({
            'today_sales': today_sales,
            'pending_orders': pending_orders,
            'total_products': total_products,
            'low_stock': low_stock
        })
    
    except Exception as e:
        logger.error(f"Admin stats error: {e}")
        return jsonify({'error': 'Failed to fetch stats'}), 500

@app.route('/api/admin/orders/export', methods=['GET'])
@jwt_required()
def export_orders_csv():
    try:
        user = User.query.get(int(get_jwt_identity()))
        if user.role != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        
        orders = Order.query.order_by(Order.created_at.desc()).all()
        output = io.StringIO()
        writer = csv.writer(output)
        
        writer.writerow(['Order ID', 'User ID', 'Agent ID', 'Total', 'Status', 'Payment Method', 'Rider Name', 'Created At'])
        for o in orders:
            writer.writerow([o.id, o.user_id, o.agent_id or '', o.total, o.status, o.payment_method, o.rider_name or '', o.created_at.isoformat()])
        
        response = make_response(output.getvalue())
        response.headers['Content-Type'] = 'text/csv'
        response.headers['Content-Disposition'] = 'attachment; filename=orders_export.csv'
        
        return response
    
    except Exception as e:
        logger.error(f"Export orders error: {e}")
        return jsonify({'error': 'Failed to export orders'}), 500

# ==================== COMMUNICATIONS / CHAT ====================
@app.route('/api/communications', methods=['GET'])
@jwt_required()
def get_communications():
    try:
        user_id = int(get_jwt_identity())
        messages = Communication.query.filter(
            (Communication.sender_id == user_id) | (Communication.receiver_id == user_id)
        ).order_by(Communication.created_at.desc()).limit(50).all()
        
        result = []
        for m in messages:
            sender = User.query.get(m.sender_id)
            result.append({
                'id': m.id,
                'sender_id': m.sender_id,
                'sender_name': sender.name if sender else 'Unknown',
                'receiver_id': m.receiver_id,
                'content': m.content,
                'is_read': m.is_read,
                'created_at': m.created_at.isoformat()
            })
        
        return jsonify(result)
    
    except Exception as e:
        logger.error(f"Get communications error: {e}")
        return jsonify({'error': 'Failed to fetch messages'}), 500

@app.route('/api/communications', methods=['POST'])
@jwt_required()
def send_communication():
    try:
        if not request.is_json:
            return jsonify({'error': 'JSON required'}), 400
        
        user_id = int(get_jwt_identity())
        data = request.get_json()
        
        receiver_id = data.get('receiver_id')
        content = data.get('content')
        
        if not receiver_id or not content:
            return jsonify({'error': 'Receiver ID and content required'}), 400
        
        message = Communication(
            sender_id=user_id,
            receiver_id=receiver_id,
            content=content
        )
        db.session.add(message)
        db.session.commit()
        
        # Send notification to receiver
        sender = User.query.get(user_id)
        send_notification(receiver_id, 'New Message', f'New message from {sender.name}')
        
        return jsonify({'success': True, 'id': message.id}), 201
    
    except Exception as e:
        logger.error(f"Send communication error: {e}")
        return jsonify({'error': 'Failed to send message'}), 500

@app.route('/api/communications/<int:msg_id>/read', methods=['POST'])
@jwt_required()
def mark_communication_read(msg_id):
    try:
        user_id = int(get_jwt_identity())
        message = Communication.query.get_or_404(msg_id)
        
        if message.receiver_id != user_id:
            return jsonify({'error': 'Unauthorized'}), 403
        
        message.is_read = True
        db.session.commit()
        
        return jsonify({'success': True})
    
    except Exception as e:
        logger.error(f"Mark read error: {e}")
        return jsonify({'error': 'Failed to mark as read'}), 500

# ==================== CHAT BOT ====================
@app.route('/api/chat/customer', methods=['POST'])
def customer_chat():
    try:
        if not request.is_json:
            return jsonify({'error': 'JSON required'}), 400
        
        data = request.get_json()
        message = data.get('message', '').lower()
        
        if 'price' in message or 'cost' in message:
            response = "💰 Here are our prices:\n• Terrazzo: UGX 250,000 - 500,000\n• Plumbing: UGX 45,000 - 150,000\n• General Merchandise: UGX 10,000 - 200,000"
        elif 'delivery' in message or 'shipping' in message:
            response = "🚚 Free delivery on orders over UGX 500,000. Standard delivery takes 2-5 business days."
        elif 'payment' in message or 'pay' in message:
            response = "💳 We accept MTN Mobile Money, Airtel Money, Bank Cards, and Cash on Delivery!"
        elif 'terrazzo' in message:
            response = "🏛️ Our Terrazzo products include floor finishes, wall finishes, and custom designs. Prices start at UGX 250,000."
        elif 'plumbing' in message:
            response = "🔧 We offer copper pipes, PVC pipes, fittings, valves, and complete plumbing solutions."
        elif 'general' in message or 'merchandise' in message:
            response = "📦 Our General Merchandise includes paints, tools, hardware, and construction supplies."
        else:
            response = "Welcome to WAMP Enterprises! 🏗️\nWe specialize in:\n• Terrazzo Flooring\n• Plumbing Services\n• General Merchandise\n\nAsk me about prices, delivery, or payments!"
        
        return jsonify({'response': response})
    
    except Exception as e:
        logger.error(f"Chat error: {e}")
        return jsonify({'error': 'Chat failed'}), 500

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
    return jsonify({'error': 'Internal server error'}), 500

# ==================== DATABASE INITIALIZATION ====================
with app.app_context():
    try:
        ensure_tables_and_defaults()
        logger.info("✅ Database initialization complete")
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")

# ==================== MAIN ====================
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    
    print(f"""
╔═══════════════════════════════════════════════════════════════════════════════╗
║                    WAMP BACKEND - PRODUCTION READY ✅                         ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║  Port:        {port}                                                          ║
║  Cloudinary:  {'ENABLED' if CLOUDINARY_ENABLED else 'DISABLED'}                ║
║  Redis:       {'ENABLED' if redis_client else 'DISABLED'}                      ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║  ⚠️  IMPORTANT:                                                               ║
║  - Admin credentials come from .env file                                      ║
║  - Agent credentials come from .env file                                      ║
║  - Products are added via Admin panel only                                    ║
║  - Categories: Terrazzo | Plumbing | General                                  ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║  🖼️  Image Storage: HYBRID (Database + Cloudinary)                            ║
║  🔐 Security:     JWT | Rate Limiting | Brute Force Protection                ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║  🚀 Features:     Auth | Products | Cart | Orders | Wishlist | Reviews       ║
║                 Agent Panel | Rider Assignment | Chat | Notifications        ║
╚═══════════════════════════════════════════════════════════════════════════════╝
    """)
    
    app.run(host='0.0.0.0', port=port, debug=False)
