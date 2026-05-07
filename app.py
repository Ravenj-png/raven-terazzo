import os
import json
import secrets
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, create_refresh_token, jwt_required, get_jwt_identity, set_access_cookies, set_refresh_cookies, unset_jwt_cookies
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from flask_wtf.csrf import CSRFProtect, generate_csrf
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

# ==================== CONFIGURATION ====================
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', secrets.token_hex(32))
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=60)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=7)
app.config['JWT_TOKEN_LOCATION'] = ['cookies']
app.config['JWT_COOKIE_SECURE'] = os.environ.get('FLASK_ENV') == 'production'
app.config['JWT_COOKIE_HTTPONLY'] = True
app.config['JWT_COOKIE_SAMESITE'] = 'Lax'

# Database - Render will provide DATABASE_URL
database_url = os.environ.get('DATABASE_URL')
if not database_url:
    database_url = 'sqlite:///tarazo.db'
    print("⚠️ Using SQLite (development)")
else:
    print(f"✅ Using PostgreSQL: {database_url[:30]}...")

app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_size': 10,
    'pool_recycle': 300,
    'pool_pre_ping': True
}

# CSRF Configuration
app.config['WTF_CSRF_ENABLED'] = True
app.config['WTF_CSRF_CHECK_DEFAULT'] = False
app.config['WTF_CSRF_HEADERS'] = ['X-CSRFToken']
app.config['WTF_CSRF_TIME_LIMIT'] = 3600
app.config['WTF_CSRF_SSL_STRICT'] = False

# ==================== CORS ====================
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
     expose_headers=["Content-Type", "X-CSRFToken", "Set-Cookie"],
     max_age=3600)

# Initialize extensions
db = SQLAlchemy(app)
jwt = JWTManager(app)
csrf = CSRFProtect()
csrf.init_app(app)

# Password hashing
ph = PasswordHasher()

# ==================== MODELS ====================
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

# ==================== DATABASE INITIALIZATION (CRITICAL FOR RENDER) ====================
def init_database():
    """Initialize database tables and create default data"""
    try:
        # Create all tables
        db.create_all()
        print("✅ Database tables created successfully")
        
        # Create default admin and products
        create_default_data()
        
    except Exception as e:
        print(f"❌ Database initialization error: {e}")
        import traceback
        traceback.print_exc()

def create_default_data():
    """Create default admin and sample products"""
    try:
        # Create admin
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
                {'name': 'Classic Floor Terrazzo', 'type': 'Floor', 'price': 150000, 'stock': 100, 
                 'description': 'Premium floor terrazzo for living rooms and offices. Durable and elegant.',
                 'image_url': 'https://placehold.co/600x400/1a5276/white?text=Floor+Terrazzo'},
                {'name': 'Modern Wall Terrazzo', 'type': 'Wall', 'price': 120000, 'stock': 50,
                 'description': 'Beautiful wall terrazzo tiles for accent walls. Easy to install.',
                 'image_url': 'https://placehold.co/600x400/27ae60/white?text=Wall+Terrazzo'},
                {'name': 'Premium Countertop', 'type': 'Countertop', 'price': 280000, 'stock': 30,
                 'description': 'High-end countertop terrazzo for kitchens. Heat and stain resistant.',
                 'image_url': 'https://placehold.co/600x400/f39c12/white?text=Countertop'},
                {'name': 'Outdoor Terrazzo', 'type': 'Floor', 'price': 180000, 'stock': 75,
                 'description': 'Weather-resistant outdoor terrazzo. Perfect for patios.',
                 'image_url': 'https://placehold.co/600x400/154360/white?text=Outdoor'},
            ]
            for p in sample_products:
                product = Product(**p)
                db.session.add(product)
            print(f"✅ {len(sample_products)} sample products created")
        
        db.session.commit()
        print("✅ Default data created successfully")
        
    except Exception as e:
        print(f"Error creating default data: {e}")
        db.session.rollback()

# ==================== INITIALIZE DATABASE ON STARTUP ====================
# This runs when the app starts (important for Render/Gunicorn)
with app.app_context():
    init_database()

# ==================== PUBLIC ROUTES ====================
@app.route('/api/csrf-token', methods=['GET', 'OPTIONS'])
def get_csrf_token():
    if request.method == 'OPTIONS':
        return make_response('', 200)
    token = generate_csrf()
    response = make_response(jsonify({'csrf_token': token}))
    response.set_cookie('csrf_token', token, httponly=False, samesite='Lax')
    return response

@app.route('/api/health', methods=['GET', 'OPTIONS'])
def health():
    if request.method == 'OPTIONS':
        return make_response('', 200)
    # Check database connection
    try:
        db.session.execute('SELECT 1')
        db_status = 'connected'
    except:
        db_status = 'disconnected'
    
    return jsonify({
        'status': 'healthy',
        'database': db_status,
        'timestamp': datetime.utcnow().isoformat()
    })

@app.route('/api/register', methods=['POST', 'OPTIONS'])
def register():
    if request.method == 'OPTIONS':
        return make_response('', 200)
    
    try:
        data = request.get_json()
        
        if not data.get('name') or not data.get('email') or not data.get('password'):
            return jsonify({'error': 'Missing required fields'}), 400
        
        if User.query.filter_by(email=data['email']).first():
            return jsonify({'error': 'Email already registered'}), 409
        
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
    if request.method == 'OPTIONS':
        return make_response('', 200)
    
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
        
        # Convert ID to string for JWT identity
        access_token = create_access_token(identity=str(user.id))
        refresh_token = create_refresh_token(identity=str(user.id))
        
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

@app.route('/api/products', methods=['GET', 'OPTIONS'])
def get_products():
    if request.method == 'OPTIONS':
        return make_response('', 200)
    products = Product.query.all()
    return jsonify([{
        'id': p.id, 'name': p.name, 'type': p.type, 'price': p.price,
        'stock': p.stock, 'description': p.description or '',
        'image_url': p.image_url or '', 'install_images': p.install_images or '[]'
    } for p in products])

@app.route('/api/chat/customer', methods=['POST', 'OPTIONS'])
def customer_chat():
    if request.method == 'OPTIONS':
        return make_response('', 200)
    
    data = request.get_json()
    message = data.get('message', '').lower()
    
    if 'price' in message or 'cost' in message:
        response = "💰 Tarazo Prices:\n• Floor: UGX 150,000/m²\n• Wall: UGX 120,000/m²\n• Countertop: UGX 280,000/m²"
    elif 'delivery' in message:
        response = "🚚 Delivery takes 2-5 days. Free delivery on orders over UGX 500,000!"
    elif 'install' in message:
        response = "🛠️ Professional installation recommended. Takes 3-7 days depending on area."
    elif 'payment' in message:
        response = "💳 We accept MTN Mobile Money, Airtel Money, and Bank Cards."
    elif 'hello' in message or 'hi' in message:
        response = "Hello! Welcome to Tarazo Premium Terrazzo! How can I help you today? 😊"
    else:
        response = "I can help you with prices, delivery, installation, and payment methods. What would you like to know?"
    
    return jsonify({'response': response})

# ==================== PROTECTED ROUTES ====================
@app.route('/api/logout', methods=['POST', 'OPTIONS'])
@jwt_required()
def logout():
    if request.method == 'OPTIONS':
        return make_response('', 200)
    response = jsonify({'success': True, 'message': 'Logged out successfully'})
    unset_jwt_cookies(response)
    return response

@app.route('/api/cart', methods=['GET', 'POST', 'OPTIONS'])
@jwt_required()
def handle_cart():
    if request.method == 'OPTIONS':
        return make_response('', 200)
    
    user_id = int(get_jwt_identity())
    
    if request.method == 'GET':
        cart_items = CartItem.query.filter_by(user_id=user_id).all()
        return jsonify([{'id': c.id, 'product_id': c.product_id, 'quantity': c.quantity} for c in cart_items])
    
    elif request.method == 'POST':
        data = request.get_json()
        product_id = data.get('product_id')
        quantity = data.get('quantity', 1)
        
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
    if request.method == 'OPTIONS':
        return make_response('', 200)
    
    user_id = int(get_jwt_identity())
    cart_item = CartItem.query.filter_by(user_id=user_id, product_id=product_id).first()
    if cart_item:
        db.session.delete(cart_item)
        db.session.commit()
    
    return jsonify({'success': True, 'message': 'Removed from cart'})

@app.route('/api/orders', methods=['GET', 'POST', 'OPTIONS'])
@jwt_required()
def handle_orders():
    if request.method == 'OPTIONS':
        return make_response('', 200)
    
    user_id = int(get_jwt_identity())
    
    if request.method == 'GET':
        orders = Order.query.filter_by(user_id=user_id).order_by(Order.created_at.desc()).all()
        return jsonify([{
            'id': o.id, 'user_id': o.user_id, 'items': json.loads(o.items) if o.items else [],
            'total': o.total, 'status': o.status, 'payment_method': o.payment_method,
            'rider_name': o.rider_name, 'rider_phone': o.rider_phone,
            'rider_vehicle': o.rider_vehicle, 'delivery_location': o.delivery_location,
            'created_at': o.created_at.isoformat()
        } for o in orders])
    
    elif request.method == 'POST':
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
        
        CartItem.query.filter_by(user_id=user_id).delete()
        db.session.commit()
        
        return jsonify({'success': True, 'order_id': order.id}), 201

@app.route('/api/orders/<int:order_id>/status', methods=['PUT', 'OPTIONS'])
@jwt_required()
def update_order_status(order_id):
    if request.method == 'OPTIONS':
        return make_response('', 200)
    
    data = request.get_json()
    order = Order.query.get_or_404(order_id)
    order.status = data.get('status', order.status)
    db.session.commit()
    return jsonify({'success': True, 'message': 'Status updated'})

@app.route('/api/orders/<int:order_id>/assign', methods=['PUT', 'OPTIONS'])
@jwt_required()
def assign_rider(order_id):
    if request.method == 'OPTIONS':
        return make_response('', 200)
    
    data = request.get_json()
    order = Order.query.get_or_404(order_id)
    order.rider_name = data.get('rider_name')
    order.rider_phone = data.get('rider_phone')
    order.rider_vehicle = data.get('rider_vehicle')
    order.delivery_location = data.get('delivery_location')
    db.session.commit()
    return jsonify({'success': True, 'message': 'Rider assigned'})

# ==================== ADMIN ROUTES ====================
@app.route('/api/admin/stats', methods=['GET', 'OPTIONS'])
@jwt_required()
def admin_stats():
    if request.method == 'OPTIONS':
        return make_response('', 200)
    
    user_id = int(get_jwt_identity())
    user = User.query.get(user_id)
    
    if not user or user.role != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    
    today = datetime.utcnow().date()
    today_orders = Order.query.filter(db.func.date(Order.created_at) == today).all()
    today_sales = sum(o.total for o in today_orders)
    pending_orders = Order.query.filter(Order.status.in_(['paid', 'processing'])).count()
    total_products = Product.query.count()
    low_stock = Product.query.filter(Product.stock < 10).count()
    
    return jsonify({
        'today_sales': today_sales,
        'pending_orders': pending_orders,
        'total_products': total_products,
        'low_stock': low_stock
    })

@app.route('/api/admin/orders', methods=['GET', 'OPTIONS'])
@jwt_required()
def admin_orders():
    if request.method == 'OPTIONS':
        return make_response('', 200)
    
    user_id = int(get_jwt_identity())
    user = User.query.get(user_id)
    
    if not user or user.role != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    
    orders = Order.query.order_by(Order.created_at.desc()).all()
    return jsonify([{
        'id': o.id, 'user_id': o.user_id, 'total': o.total, 'status': o.status,
        'payment_method': o.payment_method, 'created_at': o.created_at.isoformat()
    } for o in orders])

@app.route('/api/admin/users', methods=['GET', 'OPTIONS'])
@jwt_required()
def admin_users():
    if request.method == 'OPTIONS':
        return make_response('', 200)
    
    user_id = int(get_jwt_identity())
    user = User.query.get(user_id)
    
    if not user or user.role != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    
    users = User.query.all()
    return jsonify([{
        'id': u.id, 'name': u.name, 'email': u.email,
        'phone': u.phone, 'role': u.role, 'created_at': u.created_at.isoformat()
    } for u in users])

# ==================== ERROR HANDLERS ====================
@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Resource not found'}), 404

@app.errorhandler(500)
def server_error(e):
    print(f"Server error: {e}")
    return jsonify({'error': 'Internal server error'}), 500

# ==================== MAIN ====================
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    is_production = os.environ.get('FLASK_ENV') == 'production'
    
    print(f"""
    ╔══════════════════════════════════════════════════════════╗
    ║              🏛️  TARAZO BACKEND API  🏛️                 ║
    ╠══════════════════════════════════════════════════════════╣
    ║  Environment: {'PRODUCTION' if is_production else 'DEVELOPMENT':<40} ║
    ║  Port: {port:<40} ║
    ║  Database: {'PostgreSQL' if database_url else 'SQLite':<40} ║
    ╚══════════════════════════════════════════════════════════╝
    """)
    
    app.run(host='0.0.0.0', port=port, debug=not is_production)
