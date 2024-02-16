from flask import Flask, request, jsonify, url_for, send_from_directory, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity, create_access_token
from apscheduler.schedulers.background import BackgroundScheduler
from flask_mail import Mail, Message
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
from datetime import timedelta, datetime
import pytz
import os
import uuid

load_dotenv()

app = Flask(__name__)

# Configure database, JWT, and mail settings
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///mydatabase.db'
app.config['JWT_SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default_secret_key')
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT'))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS') == 'true'
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER')

# Initialize extensions
from extensions import db, migrate, bcrypt, jwt
db.init_app(app)
migrate.init_app(app, db)
bcrypt.init_app(app)
jwt.init_app(app)
mail = Mail(app)

# Rate Limiter
limiter = Limiter(
    get_remote_address,
    app = app,
    default_limits=["200 per day", "50 per hour"]
)

# Configuration for file uploads
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'static/images')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Coupon Expiration Checker
def deactivate_expired_coupons():
    now = datetime.utcnow()
    expired_coupons = Coupon.query.filter(
        Coupon.is_active == True,
        Coupon.valid_to < now
    ).all()
    for coupon in expired_coupons:
        coupon.is_active = False
    db.session.commit()

scheduler = BackgroundScheduler()
scheduler.add_job(func=deactivate_expired_coupons, trigger="interval", hours=24)
scheduler.start()

# Import models
from models import User, Product, CartItem, Order, OrderDetail, Coupon, Review

def generate_reset_token(user_id):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(user_id, salt='password-reset-salt')

def send_reset_email(user_email, token):
    with app.app_context():
        msg = Message('Password Reset Request', recipients=[user_email])
        msg.body = f'''To reset your password, visit the following link:
{url_for('reset_password', token=token, _external=True)}

If you did not make this request, simply ignore this email and no changes will be made.
'''
        mail.send(msg)

# Registration Route
@app.route('/register', methods=['POST'])
@limiter.limit("10 per minute")
def register():
    data = request.json

    if User.query.filter_by(email=data['email']).first():
        return jsonify({"message": "Email already in use"}), 400

    new_user = User(username=data['username'], email=data['email'])
    new_user.password = data['password']
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "User registered successfully"}), 201

# Login Route
@app.route('/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    data = request.json
    user = User.query.filter_by(email=data['email']).first()

    if user and user.verify_password(data['password']):
        access_token = create_access_token(identity=user.id, expires_delta=timedelta(days=1))
        return jsonify(access_token=access_token), 200

    return jsonify({"message": "Invalid email or password"}), 401

# Update User Details Route
@app.route('/user/update', methods=['PATCH'])
@limiter.limit("10 per minute")
@jwt_required()
def update_user():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    if not user:
        return jsonify({"message": "User not found"}), 404

    data = request.json

    if 'email' in data:
        user.email = data['email']
    if 'username' in data:
        user.username = data['username']
    if 'password' in data:
        user.password = data['password']

    db.session.commit()
    return jsonify({"message": "User updated successfully"}), 200

# Delete User Route
@app.route('/user/delete', methods=['DELETE'])
@limiter.limit("10 per minute")
@jwt_required()
def delete_user():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    if not user:
        return jsonify({"message": "User not found"}), 404

    db.session.delete(user)
    db.session.commit()
    return jsonify({"message": "User deleted successfully"}), 200

# Reset Password Request Route
@app.route('/password-reset/request', methods=['POST'])
@limiter.limit("1 per minute")
def request_password_reset():
    data = request.json
    user = User.query.filter_by(email=data['email']).first()

    if user:
        reset_token = generate_reset_token(user.id)

        send_reset_email(user.email, reset_token)

        return jsonify({"message": "Password reset email sent"}), 200

    return jsonify({"message": "Email not found"}), 404

# Reset Password Confirmation Route
@app.route('/password-reset/confirm', methods=['POST'])
@limiter.limit("10 per minute")
def reset_password():
    data = request.json
    reset_token = data.get('token')
    new_password = data.get('password')

    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

    try:
        user_id = serializer.loads(
            reset_token, 
            salt='password-reset-salt', 
            max_age=3600
        )
    except (SignatureExpired, BadSignature):
        return jsonify({"message": "Invalid or expired token"}), 400

    user = User.query.get(user_id)
    if not user:
        return jsonify({"message": "Invalid token"}), 400

    user.password = new_password
    db.session.commit()

    return jsonify({"message": "Password has been reset"}), 200

# User Profile Route
@app.route('/user/profile', methods=['GET'])
@limiter.limit("10 per minute")
@jwt_required()
def user_profile():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    if not user:
        return jsonify({"message": "User not found"}), 404

    profile_data = {
        "username": user.username,
        "email": user.email
    }

    orders = Order.query.filter_by(user_id=user.id).all()
    profile_data['orders'] = [{"id": o.id, "status": o.status} for o in orders]

    return jsonify(profile_data), 200

# Add a New Product Route
@app.route('/admin/products/add', methods=['POST'])
@limiter.limit("25 per minute")
@jwt_required()
def add_product():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    if not user or not user.is_admin:
        return jsonify({"message": "Access denied"}), 403

    if 'image' not in request.files:
        return jsonify({"message": "No image part"}), 400

    file = request.files['image']

    if file.filename == '':
        return jsonify({"message": "No selected file"}), 400
    if not allowed_file(file.filename):
        return jsonify({"message": "File extension not allowed"}), 400

    filename = secure_filename(file.filename)
    ext = filename.rsplit('.', 1)[1]
    new_filename = f"{uuid.uuid4()}.{ext}"
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], new_filename)
    file.save(file_path)

    image_url = url_for('static', filename=f'images/{new_filename}', _external=True)

    name = request.form.get('name')
    description = request.form.get('description')
    price = request.form.get('price')
    weight = request.form.get('weight')
    category = request.form.get('category')
    is_featured = request.form.get('is_featured', type=bool, default=False)
    is_on_promotion = request.form.get('is_on_promotion', type=bool, default=False)
    promotional_price = request.form.get('promotional_price', type=float)

    new_product = Product(
        name=name,
        description=description,
        price=price,
        weight=weight,
        image_url=image_url,
        category=category,
        is_featured=is_featured,
        is_on_promotion=is_on_promotion,
        promotional_price=promotional_price if is_on_promotion else None
    )
    db.session.add(new_product)
    db.session.commit()

    return jsonify({"message": "Product added successfully", "product_id": new_product.id, "image_url": image_url}), 201

# Serve uploaded files
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# Update a Product Route
@app.route('/admin/products/update/<int:product_id>', methods=['PATCH'])
@limiter.limit("25 per minute")
@jwt_required()
def update_product(product_id):
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    if not user or not user.is_admin:
        return jsonify({"message": "Access denied"}), 403

    product = Product.query.get(product_id)
    if not product:
        return jsonify({"message": "Product not found"}), 404

    data = request.json
    product.name = data.get('name', product.name)
    product.description = data.get('description', product.description)
    product.price = data.get('price', product.price)
    product.weight = data.get('weight', product.weight)
    product.category = data.get('category', product.category)
    product.is_available = data.get('is_available', product.is_available)
    product.is_featured = data.get('is_featured', product.is_featured)
    product.is_on_promotion = data.get('is_on_promotion', product.is_on_promotion)
    if product.is_on_promotion:
        product.promotional_price = data.get('promotional_price', product.promotional_price)

    db.session.commit()
    return jsonify({"message": "Product updated successfully"}), 200

# Delete a Product Route
@app.route('/admin/products/delete/<int:product_id>', methods=['DELETE'])
@limiter.limit("25 per minute")
@jwt_required()
def delete_product(product_id):
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    if not user or not user.is_admin:
        return jsonify({"message": "Access denied"}), 403

    product = Product.query.get(product_id)
    if not product:
        return jsonify({"message": "Product not found"}), 404

    db.session.delete(product)
    db.session.commit()

    return jsonify({"message": "Product deleted successfully"}), 200

# List Users Route
@app.route('/admin/users', methods=['GET'])
@limiter.limit("25 per minute")
@jwt_required()
def list_users():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    if not user or not user.is_admin:
        return jsonify({"message": "Access denied"}), 403

    users = User.query.all()
    users_data = [{"id": u.id, "username": u.username, "email": u.email} for u in users]

    return jsonify(users_data), 200

# User Role Management Route
@app.route('/admin/users/role/<int:user_id>', methods=['PATCH'])
@limiter.limit("25 per minute")
@jwt_required()
def update_user_role_and_discount(user_id):
    current_user_id = get_jwt_identity()
    admin_user = User.query.get(current_user_id)

    if not admin_user or not admin_user.is_admin:
        return jsonify({"message": "Access denied"}), 403

    user = User.query.get(user_id)
    if not user:
        return jsonify({"message": "User not found"}), 404

    data = request.json
    update_made = False

    if 'is_admin' in data and isinstance(data['is_admin'], bool):
        user.is_admin = data['is_admin']
        update_made = True

    if 'discount' in data and isinstance(data['discount'], (int, float)):
        user.discount_rate = data['discount']
        update_made = True

    if update_made:
        db.session.commit()
        return jsonify({"message": "User updates made successfully"}), 200
    else:
        return jsonify({"message": "Invalid request"}), 400
    
# Route to add new coupons
@app.route('/admin/coupons/add', methods=['POST'])
@limiter.limit("25 per minute")
@jwt_required()
def add_coupon():
    current_user_id = get_jwt_identity()
    admin_user = User.query.get(current_user_id)

    if not admin_user or not admin_user.is_admin:
        return jsonify({"message": "Access denied"}), 403

    data = request.json

    try:
        valid_from = datetime.strptime(data['valid_from'], '%Y-%m-%d').replace(tzinfo=pytz.utc)
        valid_to = datetime.strptime(data['valid_to'], '%Y-%m-%d').replace(tzinfo=pytz.utc)
    except (ValueError, KeyError):
        return jsonify({"message": "Invalid date format"}), 400

    new_coupon = Coupon(
        code=data['code'],
        discount_percentage=data['discount_percentage'],
        valid_from=valid_from,
        valid_to=valid_to,
        is_active=data.get('is_active', True)
    )

    db.session.add(new_coupon)
    try:
        db.session.commit()
    except Exception as e:
        return jsonify({"message": str(e)}), 500

    return jsonify({"message": "Coupon added successfully", "coupon_id": new_coupon.id}), 201

# Activate / Deactivate Coupon Route
@app.route('/admin/coupons/update/<int:coupon_id>', methods=['PATCH'])
@limiter.limit("25 per minute")
@jwt_required()
def update_coupon(coupon_id):
    current_user_id = get_jwt_identity()
    admin_user = User.query.get(current_user_id)

    if not admin_user or not admin_user.is_admin:
        return jsonify({"message": "Access denied"}), 403

    coupon = Coupon.query.get(coupon_id)
    if not coupon:
        return jsonify({"message": "Coupon not found"}), 404

    data = request.json
    if 'is_active' in data:
        coupon.is_active = data['is_active']

    db.session.commit()
    return jsonify({"message": "Coupon updated successfully"}), 200

# View All Orders Route
@app.route('/admin/orders', methods=['GET'])
@limiter.limit("25 per minute")
@jwt_required()
def view_all_orders():
    current_user_id = get_jwt_identity()
    admin_user = User.query.get(current_user_id)

    if not admin_user or not admin_user.is_admin:
        return jsonify({"message": "Access denied"}), 403

    orders = Order.query.all()
    orders_data = [{"id": o.id, "user_id": o.user_id, "total_price": o.total_price, "status": o.status} for o in orders]

    return jsonify(orders_data), 200

# Update Order Status Route
@app.route('/admin/orders/update/<int:order_id>', methods=['PATCH'])
@limiter.limit("25 per minute")
@jwt_required()
def update_order_status(order_id):
    current_user_id = get_jwt_identity()
    admin_user = User.query.get(current_user_id)

    if not admin_user or not admin_user.is_admin:
        return jsonify({"message": "Access denied"}), 403

    order = Order.query.get(order_id)
    if not order:
        return jsonify({"message": "Order not found"}), 404

    data = request.json
    order.status = data.get('status', order.status)

    db.session.commit()

    return jsonify({"message": "Order status updated successfully"}), 200

# Adding to Cart Route
@app.route('/cart/add', methods=['POST'])
@limiter.limit("50 per minute")
@jwt_required()
def add_to_cart():
    user_id = get_jwt_identity()
    data = request.json

    product_id = data.get('product_id')
    quantity = data.get('quantity', 1)

    product = Product.query.get(product_id)
    if not product:
        return jsonify({"message": "Product not found"}), 404

    cart_item = CartItem.query.filter_by(user_id=user_id, product_id=product_id).first()
    if cart_item:
        cart_item.quantity += quantity
    else:
        cart_item = CartItem(user_id=user_id, product_id=product_id, quantity=quantity)
        db.session.add(cart_item)

    db.session.commit()
    return jsonify({"message": "Item added to cart"}), 201

# View Cart Route
@app.route('/cart', methods=['GET'])
@limiter.limit("25 per minute")
@jwt_required()
def view_cart():
    user_id = get_jwt_identity()
    cart_items = CartItem.query.filter_by(user_id=user_id).all()

    cart_data = [{
        "product_id": item.product_id,
        "quantity": item.quantity,
        "product_name": item.product.name,
        "price": item.product.promotional_price if item.product.is_on_promotion else item.product.price
    } for item in cart_items]

    return jsonify(cart_data), 200

# Checkout Route
@app.route('/checkout', methods=['POST'])
@limiter.limit("25 per minute")
@jwt_required()
def checkout():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    data = request.json
    coupon_code = data.get('coupon_code')

    cart_items = CartItem.query.filter_by(user_id=user_id).all()

    total_price = sum((item.product.promotional_price if item.product.is_on_promotion else item.product.price) * item.quantity for item in cart_items)

    total_price *= (1 - user.discount / 100)

    if coupon_code:
        coupon = Coupon.query.filter_by(code=coupon_code, is_active=True).first()
        if coupon and coupon.valid_from <= datetime.utcnow() <= coupon.valid_to:
            total_price *= (1 - coupon.discount_percentage / 100)

    order = Order(user_id=user_id, total_price=total_price, status='Pending')
    db.session.add(order)
    for item in cart_items:
        order_detail = OrderDetail(
            order_id=order.id, 
            product_id=item.product_id, 
            quantity=item.quantity, 
            price=(item.product.promotional_price if item.product.is_on_promotion else item.product.price)
        )
        db.session.add(order_detail)

    for item in cart_items:
        db.session.delete(item)

    db.session.commit()
    return jsonify({"message": "Checkout successful", "order_id": order.id}), 201

# Product Search Route
@app.route('/products', methods=['GET'])
@limiter.limit("50 per minute")
def browse_products():
    search_query = request.args.get('search', '')
    category = request.args.get('category', '')
    min_price = request.args.get('min_price', None, type=float)
    max_price = request.args.get('max_price', None, type=float)

    query = Product.query

    if search_query:
        query = query.filter(Product.name.ilike(f'%{search_query}%'))
    if category:
        query = query.filter_by(category=category)
    if min_price is not None:
        query = query.filter(Product.price >= min_price)
    if max_price is not None:
        query = query.filter(Product.price <= max_price)

    products = query.all()

    product_data = [{
        "id": product.id,
        "name": product.name,
        "description": product.description,
        "price": product.promotional_price if product.is_on_promotion else product.price,
        "average_rating": product.average_rating,
        "review_count": product.review_count,
        "category": product.category,
        "image_url": product.image_url,
        "is_featured": product.is_featured,
        "is_on_promotion": product.is_on_promotion
    } for product in products]

    return jsonify(product_data), 200

# Order History / Details Route
@app.route('/orders', methods=['GET'])
@limiter.limit("25 per minute")
@jwt_required()
def order_history():
    user_id = get_jwt_identity()
    orders = Order.query.filter_by(user_id=user_id).all()

    order_data = [{
        "id": order.id,
        "total_price": order.total_price,
        "status": order.status,
        "created_at": order.created_at.strftime("%Y-%m-%d %H:%M:%S")
    } for order in orders]

    return jsonify(order_data), 200

# Specific Order Details Route
@app.route('/orders', methods=['GET'])
@limiter.limit("25 per minute")
@jwt_required()
def order_details():
    user_id = get_jwt_identity()
    orders = Order.query.filter_by(user_id=user_id).all()

    order_data = [{
        "id": order.id,
        "total_price": order.total_price,
        "status": order.status,
        "created_at": order.created_at.strftime("%Y-%m-%d %H:%M:%S")
    } for order in orders]

    return jsonify(order_data), 200

# Re-add Old Orders to Cart Route
@app.route('/orders/add-to-cart/<int:order_id>', methods=['POST'])
@limiter.limit("25 per minute")
@jwt_required()
def add_order_to_cart(order_id):
    user_id = get_jwt_identity()
    old_order = Order.query.filter_by(id=order_id, user_id=user_id).first()

    if not old_order:
        return jsonify({"message": "Order not found"}), 404

    unavailable_products = []

    for detail in old_order.order_details:
        product = Product.query.get(detail.product_id)
        if product and product.is_available:
            current_price = product.promotional_price if product.is_on_promotion else product.price
            cart_item = CartItem.query.filter_by(user_id=user_id, product_id=product.id).first()
            if cart_item:
                cart_item.quantity += detail.quantity
            else:
                new_cart_item = CartItem(user_id=user_id, product_id=product.id, quantity=detail.quantity, price=current_price)
                db.session.add(new_cart_item)
        else:
            unavailable_products.append(product.name)

    db.session.commit()

    if unavailable_products:
        return jsonify({"message": "Some items were unavailable and not added to the cart", "unavailable_products": unavailable_products}), 200
    else:
        return jsonify({"message": "Items added to cart"}), 200
    
# Re-add Specific Items From Old Orders Route
@app.route('/orders/add-item-to-cart/<int:order_id>/<int:product_id>', methods=['POST'])
@limiter.limit("25 per minute")
@jwt_required()
def add_order_item_to_cart(order_id, product_id):
    user_id = get_jwt_identity()
    data = request.json
    quantity = data.get('quantity', 1)

    if quantity <= 0:
        return jsonify({"message": "Invalid quantity"}), 400

    order = Order.query.filter_by(id=order_id, user_id=user_id).first()
    if not order:
        return jsonify({"message": "Order not found"}), 404

    order_detail = next((detail for detail in order.order_details if detail.product_id == product_id), None)
    if not order_detail:
        return jsonify({"message": "Product not found in the order"}), 404

    product = Product.query.get(product_id)
    if not product or not product.is_available:
        return jsonify({"message": "Product is not available"}), 404

    current_price = product.promotional_price if product.is_on_promotion else product.price
    cart_item = CartItem.query.filter_by(user_id=user_id, product_id=product_id).first()
    if cart_item:
        cart_item.quantity += quantity
    else:
        new_cart_item = CartItem(user_id=user_id, product_id=product_id, quantity=quantity, price=current_price)
        db.session.add(new_cart_item)

    db.session.commit()
    return jsonify({"message": "Item added to cart"}), 200

# Add a Rating / Review Route
@app.route('/products/<int:product_id>/review', methods=['POST'])
@limiter.limit("10 per minute")
@jwt_required()
def add_or_update_review(product_id):
    user_id = get_jwt_identity()
    data = request.json
    rating = data.get('rating')
    comment = data.get('comment', '')

    if not (1 <= rating <= 5):
        return jsonify({"message": "Rating must be between 1 and 5"}), 400

    product = Product.query.get(product_id)
    if not product:
        return jsonify({"message": "Product not found"}), 404

    review = Review.query.filter_by(user_id=user_id, product_id=product_id).first()
    if review:
        review.rating = rating
        review.comment = comment
    else:
        review = Review(user_id=user_id, product_id=product_id, rating=rating, comment=comment)
        db.session.add(review)

    db.session.commit()

    update_product_rating(product)

    return jsonify({"message": "Review submitted successfully"}), 201

def update_product_rating(product):
    total_rating = sum(review.rating for review in product.reviews)
    product.review_count = len(product.reviews)
    product.average_rating = total_rating / product.review_count if product.review_count > 0 else 0
    db.session.commit()

############# TEMPORARY ADMIN CREATION ROUTE ###############
@app.route('/setup', methods=['POST'])
@limiter.limit("1 per minute")
def setup_admin():
    if User.query.filter_by(is_admin=True).first():
        return jsonify({"message": "Admin already exists"}), 400

    data = request.json
    admin_user = User(username=data['username'], email=data['email'])
    admin_user.password = data['password']
    admin_user.is_admin = True

    db.session.add(admin_user)
    db.session.commit()

    return jsonify({"message": "Admin user created successfully"}), 201

if __name__ == '__main__':
    app.run(debug=True)