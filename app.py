# ==========================================
# TARAZO BACKEND - COMPLETE WORKING VERSION
# ==========================================

import os
import json
import secrets
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_jwt_extended import (
    JWTManager, create_access_token, create_refresh_token,
    jwt_required, get_jwt_identity, set_access_cookies,
    set_refresh_cookies, unset_jwt_cookies
)
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from flask_wtf.csrf import CSRFProtect, generate_csrf
from dotenv import load_dotenv

load_dotenv()

# ==========================================
# APP CONFIGURATION
# ==========================================
app = Flask(__name__)

# Security config
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', secrets.token_hex(32))
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=60)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=7)
app.config['JWT_TOKEN_LOCATION'] = ['cookies', 'headers']
app.config['JWT_COOKIE_SECURE'] = False  # Set to True in production with HTTPS
app.config['JWT_COOKIE_HTTPONLY'] = True
app.config['JWT_COOKIE_SAMESITE'] = 'Lax'

# Database
database_url = os.environ.get('DATABASE_URL', 'sqlite:///tarazo.db')
app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# CSRF Configuration
app.config['WTF_CSRF_ENABLED'] = True
app.config['WTF_CSRF_CHECK_DEFAULT'] = False
app.config['WTF_CSRF_HEADERS'] = ['X-CSRFToken']
app.config['WTF_CSRF_TIME_LIMIT'] = 3600
app.config['WTF_CSRF_SSL_STRICT'] = False

# CORS Configuration
CORS(app, 
     origins=[
         "http://localhost:5500", 
         "http://127.0.0.1:5500", 
         "https://ravenj-png.github.io",
         "https://raven-terazzo.onrender.com"
     ],
     supports_credentials=True,
     methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
     allow_headers=["Content-Type", "Authorization", "X-CSRFToken", "X-Requested-With"],
     expose_headers=["Content-Type", "X-CSRFToken"],
     resources={r"/*": {"origins": "*"}})

# Initialize extensions
db = SQLAlchemy(app)
jwt = JWTManager(app)
csrf = CSRFProtect()
csrf.init_app(app)

# Password hashing
ph = PasswordHasher()

# ==========================================
# DATABASE MODELS
# ==========================================

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    phone = db.Column(db.String(20))
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default='user')
    address = db.Column(db.String(500))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Product(db.Model):
    __tablename__ = 'products'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    type = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Integer, nullable=False)
    stock = db.Column(db.Integer, default=0)
    description = db.Column(db.Text)
    image_url = db.Column(db.String(500))
    install_images = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class CartItem(db.Model):
    __tablename__ = 'cart_items'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    product_id = db.Column(db.Integer, db.ForeignKey('products.id'))
    quantity = db.Column(db.Integer, default=1)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Order(db.Model):
    __tablename__ = 'orders'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    agent_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    items = db.Column(db.Text, nullable=False)
    total = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(50), default='paid')
    payment_method = db.Column(db.String(50))
    rider_name = db.Column(db.String(100))
    rider_phone = db.Column(db.String(20))
    rider_vehicle = db.Column(db.String(100))
    delivery_location = db.Column(db.String(500))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# ==========================================
# HELPER FUNCTIONS
# ==========================================

def create_default_data():
    """Create default admin and sample products"""
    try:
        # Create admin if not exists
        admin_email = os.environ.get('ADMIN_EMAIL', 'admin@tarazo.com')
        admin = User.query.filter_by(email=admin_email).first()
        
        if not admin:
            admin = User(
                name='Administrator',
                email=admin_email,
                phone='0771000000',
                password_hash=ph.hash(os.environ.get('ADMIN_PASSWORD', 'admin123')),
                role='admin'
            )
            db.session.add(admin)
            print(f"✅ Admin created: {admin_email}")
        
        # Create sample products if none exist
        if Product.query.count() == 0:
            sample_products = [
                {
                    'name': 'Classic Floor Terrazzo',
                    'type': 'Floor',
                    'price': 150000,
                    'stock': 100,
                    'description': 'Premium floor terrazzo, perfect for living rooms and offices. Durable, elegant, and easy to maintain.',
                    'image_url': 'https://placehold.co/600x400/1a5276/white?text=Floor+Terrazzo'
                },
                {
                    'name': 'Modern Wall Terrazzo',
                    'type': 'Wall',
                    'price': 120000,
                    'stock': 50,
                    'description': 'Beautiful wall terrazzo tiles. Add a touch of elegance to your walls.',
                    'image_url': 'https://placehold.co/600x400/27ae60/white?text=Wall+Terrazzo'
                },
                {
                    'name': 'Premium Countertop',
                    'type': 'Countertop',
                    'price': 280000,
                    'stock': 30,
                    'description': 'High-end countertop terrazzo. Heat and stain resistant, perfect for kitchens.',
                    'image_url': 'https://placehold.co/600x400/f39c12/white?text=Countertop'
                },
                {
                    'name': 'Outdoor Terrazzo',
                    'type': 'Floor',
                    'price': 180000,
                    'stock': 75,
                    'description': 'Weather-resistant outdoor terrazzo. Perfect for patios and walkways.',
                    'image_url': 'https://placehold.co/600x400/154360/white?text=Outdoor'
                }
            ]
            
            for p in sample_products:
                product = Product(**p)
                db.session.add(product)
            print(f"✅ {len(sample_products)} sample products created")
        
        db.session.commit()
    except Exception as e:
        print(f"Error creating default data: {e}")
        db.session.rollback()

# ==========================================
# API ROUTES
# ==========================================

@app.route('/api/csrf-token', methods=['GET', 'OPTIONS'])
def get_csrf_token():
    """Get CSRF token for frontend"""
    token = generate_csrf()
    response = make_response(jsonify({'csrf_token': token}))
    response.set_cookie('csrf_token', token, httponly=False, samesite='Lax')
    return response

@app.route('/api/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'version': '1.0.0'
    })

@app.route('/api/register', methods=['POST', 'OPTIONS'])
def register():
    """User registration"""
    try:
        data = request.get_json()
        
        # Validate input
        if not data.get('name') or not data.get('email') or not data.get('password'):
            return jsonify({'error': 'Missing required fields'}), 400
        
        # Check if user exists
        if User.query.filter_by(email=data['email']).first():
            return jsonify({'error': 'Email already registered'}), 409
        
        # Create user
        user = User(
            name=data['name'],
            email=data['email'],
            phone=data.get('phone', ''),
            password_hash=ph.hash(data['password']),
            role='user'
        )
        
        db.session.add(user)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Registration successful'}), 201
        
    except Exception as e:
        db.session.rollback()
        print(f"Registration error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/login', methods=['POST', 'OPTIONS'])
def login():
    """User login"""
    try:
        data = request.get_json()
        
        if not data.get('email') or not data.get('password'):
            return jsonify({'error': 'Email and password required'}), 400
        
        user = User.query.filter_by(email=data['email']).first()
        
        if not user:
            return jsonify({'error': 'Invalid credentials'}), 401
        
        try:
            ph.verify(user.password_hash, data['password'])
        except VerifyMismatchError:
            return jsonify({'error': 'Invalid credentials'}), 401
        
        # Create tokens
        access_token = create_access_token(identity=user.id)
        refresh_token = create_refresh_token(identity=user.id)
        
        response = jsonify({
            'success': True,
            'user': {
                'id': user.id,
                'name': user.name,
                'email': user.email,
                'role': user.role,
                'phone': user.phone,
                'address': user.address
            }
        })
        
        set_access_cookies(response, access_token)
        set_refresh_cookies(response, refresh_token)
        
        return response
        
    except Exception as e:
        print(f"Login error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/logout', methods=['POST', 'OPTIONS'])
@jwt_required()
def logout():
    """User logout"""
    response = jsonify({'success': True, 'message': 'Logged out successfully'})
    unset_jwt_cookies(response)
    return response

@app.route('/api/refresh', methods=['POST', 'OPTIONS'])
@jwt_required(refresh=True)
def refresh():
    """Refresh access token"""
    user_id = get_jwt_identity()
    access_token = create_access_token(identity=user_id)
    response = jsonify({'success': True})
    set_access_cookies(response, access_token)
    return response

@app.route('/api/products', methods=['GET', 'OPTIONS'])
def get_products():
    """Get all products"""
    products = Product.query.all()
    return jsonify([{
        'id': p.id,
        'name': p.name,
        'type': p.type,
        'price': p.price,
        'stock': p.stock,
        'description': p.description or '',
        'image_url': p.image_url or '',
        'install_images': p.install_images or '[]'
    } for p in products])

@app.route('/api/products/<int:product_id>', methods=['GET', 'OPTIONS'])
def get_product(product_id):
    """Get single product"""
    product = Product.query.get_or_404(product_id)
    return jsonify({
        'id': product.id,
        'name': product.name,
        'type': product.type,
        'price': product.price,
        'stock': product.stock,
        'description': product.description,
        'image_url': product.image_url,
        'install_images': product.install_images
    })

@app.route('/api/cart', methods=['GET', 'OPTIONS'])
@jwt_required()
def get_cart():
    """Get user's cart"""
    user_id = get_jwt_identity()
    cart_items = CartItem.query.filter_by(user_id=user_id).all()
    return jsonify([{
        'id': c.id,
        'product_id': c.product_id,
        'quantity': c.quantity
    } for c in cart_items])

@app.route('/api/cart', methods=['POST', 'OPTIONS'])
@jwt_required()
def add_to_cart():
    """Add item to cart"""
    user_id = get_jwt_identity()
    data = request.get_json()
    
    product_id = data.get('product_id')
    quantity = data.get('quantity', 1)
    
    # Check if item already in cart
    cart_item = CartItem.query.filter_by(user_id=user_id, product_id=product_id).first()
    
    if cart_item:
        cart_item.quantity += quantity
    else:
        cart_item = CartItem(user_id=user_id, product_id=product_id, quantity=quantity)
        db.session.add(cart_item)
    
    db.session.commit()
    return jsonify({'success': True, 'message': 'Added to cart'}), 201

@app.route('/api/cart/<int:product_id>', methods=['DELETE', 'OPTIONS'])
@jwt_required()
def remove_from_cart(product_id):
    """Remove item from cart"""
    user_id = get_jwt_identity()
    cart_item = CartItem.query.filter_by(user_id=user_id, product_id=product_id).first()
    
    if cart_item:
        db.session.delete(cart_item)
        db.session.commit()
    
    return jsonify({'success': True, 'message': 'Removed from cart'})

@app.route('/api/cart/clear', methods=['DELETE', 'OPTIONS'])
@jwt_required()
def clear_cart():
    """Clear user's cart"""
    user_id = get_jwt_identity()
    CartItem.query.filter_by(user_id=user_id).delete()
    db.session.commit()
    return jsonify({'success': True, 'message': 'Cart cleared'})

@app.route('/api/orders', methods=['GET', 'OPTIONS'])
@jwt_required()
def get_orders():
    """Get user's orders"""
    user_id = get_jwt_identity()
    orders = Order.query.filter_by(user_id=user_id).order_by(Order.created_at.desc()).all()
    
    return jsonify([{
        'id': o.id,
        'user_id': o.user_id,
        'items': json.loads(o.items) if o.items else [],
        'total': o.total,
        'status': o.status,
        'payment_method': o.payment_method,
        'rider_name': o.rider_name,
        'rider_phone': o.rider_phone,
        'rider_vehicle': o.rider_vehicle,
        'delivery_location': o.delivery_location,
        'created_at': o.created_at.isoformat()
    } for o in orders])

@app.route('/api/orders', methods=['POST', 'OPTIONS'])
@jwt_required()
def create_order():
    """Create new order"""
    user_id = get_jwt_identity()
    data = request.get_json()
    
    order = Order(
        user_id=user_id,
        items=json.dumps(data.get('items', [])),
        total=data.get('total', 0),
        payment_method=data.get('payment_method', 'MTN Mobile Money'),
        status='paid'
    )
    
    db.session.add(order)
    db.session.commit()
    
    # Clear cart after order
    CartItem.query.filter_by(user_id=user_id).delete()
    db.session.commit()
    
    return jsonify({'success': True, 'order_id': order.id, 'message': 'Order created successfully'}), 201

@app.route('/api/orders/<int:order_id>', methods=['GET', 'OPTIONS'])
@jwt_required()
def get_order(order_id):
    """Get single order"""
    user_id = get_jwt_identity()
    order = Order.query.get_or_404(order_id)
    
    # Check permission
    if order.user_id != user_id:
        user = User.query.get(user_id)
        if user.role not in ['admin', 'agent']:
            return jsonify({'error': 'Unauthorized'}), 403
    
    return jsonify({
        'id': order.id,
        'user_id': order.user_id,
        'items': json.loads(order.items) if order.items else [],
        'total': order.total,
        'status': order.status,
        'payment_method': order.payment_method,
        'rider_name': order.rider_name,
        'rider_phone': order.rider_phone,
        'rider_vehicle': order.rider_vehicle,
        'delivery_location': order.delivery_location,
        'created_at': order.created_at.isoformat()
    })

@app.route('/api/orders/<int:order_id>/status', methods=['PUT', 'OPTIONS'])
@jwt_required()
def update_order_status(order_id):
    """Update order status"""
    user_id = get_jwt_identity()
    data = request.get_json()
    order = Order.query.get_or_404(order_id)
    
    # Check permission
    user = User.query.get(user_id)
    if user.role not in ['admin', 'agent'] and order.user_id != user_id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    order.status = data.get('status', order.status)
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'Order status updated'})

@app.route('/api/orders/<int:order_id>/assign', methods=['PUT', 'OPTIONS'])
@jwt_required()
def assign_rider(order_id):
    """Assign rider to order"""
    user_id = get_jwt_identity()
    data = request.get_json()
    order = Order.query.get_or_404(order_id)
    
    # Check permission
    user = User.query.get(user_id)
    if user.role not in ['admin', 'agent']:
        return jsonify({'error': 'Unauthorized'}), 403
    
    order.rider_name = data.get('rider_name')
    order.rider_phone = data.get('rider_phone')
    order.rider_vehicle = data.get('rider_vehicle')
    order.delivery_location = data.get('delivery_location')
    
    if order.status == 'paid':
        order.status = 'processing'
    
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'Rider assigned successfully'})

@app.route('/api/chat/customer', methods=['POST', 'OPTIONS'])
def customer_chat():
    """AI chat endpoint for customers"""
    data = request.get_json()
    message = data.get('message', '').lower()
    
    # Simple response logic
    if any(word in message for word in ['price', 'cost', 'how much']):
        response = "💰 Tarazo Prices:\n• Floor Terrazzo: UGX 150,000/m²\n• Wall Terrazzo: UGX 120,000/m²\n• Countertop: UGX 280,000/m²\n• Outdoor: UGX 180,000/m²"
    elif any(word in message for word in ['delivery', 'shipping', 'delivered']):
        response = "🚚 Delivery takes 2-5 days. Free delivery on orders over UGX 500,000!"
    elif any(word in message for word in ['install', 'installation']):
        response = "🛠️ Professional installation recommended. Takes 3-7 days depending on area size."
    elif any(word in message for word in ['payment', 'pay', 'mtn', 'airtel']):
        response = "💳 We accept MTN Mobile Money, Airtel Money, and Bank Cards."
    elif any(word in message for word in ['hello', 'hi', 'hey', 'good morning', 'good afternoon']):
        response = "Hello! Welcome to Tarazo Premium Terrazzo! How can I help you today? 😊"
    elif any(word in message for word in ['thank', 'thanks']):
        response = "You're welcome! Feel free to ask if you need anything else! 🙏"
    else:
        response = "Thank you for contacting Tarazo! I can help you with:\n• Product prices\n• Delivery information\n• Installation process\n• Payment methods\n\nWhat would you like to know?"
    
    return jsonify({'response': response})

@app.route('/api/admin/stats', methods=['GET', 'OPTIONS'])
@jwt_required()
def admin_stats():
    """Get admin statistics"""
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    today = datetime.utcnow().date()
    today_orders = Order.query.filter(db.func.date(Order.created_at) == today).all()
    today_sales = sum(o.total for o in today_orders)
    
    pending_orders = Order.query.filter(Order.status.in_(['paid', 'processing'])).count()
    total_products = Product.query.count()
    low_stock = Product.query.filter(Product.stock < 10).count()
    total_users = User.query.count()
    total_orders = Order.query.count()
    total_sales = db.session.query(db.func.sum(Order.total)).scalar() or 0
    
    return jsonify({
        'today_sales': today_sales,
        'pending_orders': pending_orders,
        'total_products': total_products,
        'low_stock': low_stock,
        'total_users': total_users,
        'total_orders': total_orders,
        'total_sales': total_sales
    })

@app.route('/api/admin/orders', methods=['GET', 'OPTIONS'])
@jwt_required()
def admin_orders():
    """Get all orders for admin"""
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    orders = Order.query.order_by(Order.created_at.desc()).all()
    
    return jsonify([{
        'id': o.id,
        'user_id': o.user_id,
        'items': json.loads(o.items) if o.items else [],
        'total': o.total,
        'status': o.status,
        'payment_method': o.payment_method,
        'rider_name': o.rider_name,
        'rider_phone': o.rider_phone,
        'created_at': o.created_at.isoformat()
    } for o in orders])

@app.route('/api/admin/users', methods=['GET', 'OPTIONS'])
@jwt_required()
def admin_users():
    """Get all users for admin"""
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    users = User.query.all()
    
    return jsonify([{
        'id': u.id,
        'name': u.name,
        'email': u.email,
        'phone': u.phone,
        'role': u.role,
        'created_at': u.created_at.isoformat()
    } for u in users])

# ==========================================
# ERROR HANDLERS
# ==========================================

@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Resource not found'}), 404

@app.errorhandler(500)
def server_error(e):
    print(f"Server error: {e}")
    return jsonify({'error': 'Internal server error'}), 500

# ==========================================
# MAIN
# ==========================================

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_default_data()
        print("✅ Database initialized")
    
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV') == 'development'
    
    print(f"""
    ╔══════════════════════════════════════════════════════════╗
    ║                                                          ║
    ║              🏛️  TARAZO BACKEND API  🏛️                 ║
    ║                                                          ║
    ╠══════════════════════════════════════════════════════════╣
    ║  Server:    http://localhost:{port}                      ║
    ║  Debug:     {str(debug):<40} ║
    ║  Database:  {'SQLite' if 'sqlite' in database_url else 'PostgreSQL':<40} ║
    ║                                                          ║
    ║  📡 Endpoints:                                           ║
    ║  POST   /api/register     - Create account              ║
    ║  POST   /api/login        - Login                       ║
    ║  GET    /api/products     - Get all products            ║
    ║  GET    /api/cart         - View cart                   ║
    ║  POST   /api/orders       - Create order                ║
    ║  GET    /api/admin/stats  - Admin statistics            ║
    ║                                                          ║
    ╚══════════════════════════════════════════════════════════╝
    """)
    
    app.run(host='0.0.0.0', port=port, debug=debug)
