from extensions import db, bcrypt
from sqlalchemy.orm import validates
from datetime import datetime
import re

def calculate_total_weight(order_details):
    total_weight = sum(detail.product.weight * detail.quantity for detail in order_details)
    return total_weight
    
def calculate_shipping_cost(total_weight):
    rate_per_unit_weight = 0.5
    return total_weight * rate_per_unit_weight

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200))
    is_admin = db.Column(db.Boolean, default=False)
    cart_items = db.relationship('CartItem', backref='user', lazy=True)
    orders = db.relationship('Order', backref='user', lazy=True)
    discount = db.Column(db.Float, default=0.0)

    @validates('discount')
    def validate_discount(self, key, discount_rate):
        if not 0 <= discount_rate <= 100:
            raise ValueError("Discount rate must be between 0 and 100")
        return discount_rate
    
    @validates('email')
    def validate_email(self, key, email):
        if not re.match("[^@]+@[^@]+\.[^@]+", email):
            raise ValueError("Invalid email format")
        return email

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def verify_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    price = db.Column(db.Float, nullable=False)
    promotional_price = db.Column(db.Float, nullable=True)
    weight = db.Column(db.Integer, nullable=False)
    cart_items = db.relationship('CartItem', backref='product', lazy=True)
    image_url = db.Column(db.String(255), nullable=True)
    category = db.Column(db.String(100), nullable=True)
    is_available = db.Column(db.Boolean, default=True)
    is_featured = db.Column(db.Boolean, default=False)
    is_on_promotion = db.Column(db.Boolean, default=False)
    average_rating = db.Column(db.Float, default=0.0)
    review_count = db.Column(db.Integer, default=0)
    reviews = db.relationship('Review', backref='product', lazy=True)

    @validates('price', 'promotional_price')
    def validate_price(self, key, price):
        if price is not None and price < 0:
            raise ValueError(f"{key} must be non-negative")
        return price
    
    @validates('weight')
    def validate_weight(self, key, weight):
        if weight < 0:
            raise ValueError("Weight must be non-negative")
        return weight

class CartItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, default=1)

    @validates('quantity')
    def validate_quantity(self, key, quantity):
        if quantity < 1:
            raise ValueError("Quantity must be at least 1")
        return quantity

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    total_price = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(50), default='Pending')
    shipping_address = db.Column(db.String(200), nullable=False)
    order_details = db.relationship('OrderDetail', backref='order', lazy=True)
    shipping_cost = db.Column(db.Float, nullable=True)
    discount = db.Column(db.Float, default=0.0)

    def validate_discount(self, key, discount_rate):
        assert 0 <= discount_rate <= 100, "Discount rate must be between 0 and 100"
        return discount_rate

class OrderDetail(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Float, nullable=False)

    @validates('price')
    def validate_price(self, key, price):
        if price < 0:
            raise ValueError("Price must be non-negative")
        return price

class Coupon(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(50), unique=True, nullable=False)
    discount_percentage = db.Column(db.Float, nullable=False)
    valid_from = db.Column(db.DateTime, nullable=False)
    valid_to = db.Column(db.DateTime, nullable=False)
    is_active = db.Column(db.Boolean, default=False)

    @validates('discount_percentage')
    def validate_discount_percentage(self, key, discount_percentage):
        if not 0 <= discount_percentage <= 100:
            raise ValueError("Discount percentage must be between 0 and 100")
        return discount_percentage
    
    @validates('valid_from', 'valid_to')
    def validate_dates(self, key, date):
        if key == 'valid_to' and self.valid_from and self.valid_from > date:
            raise ValueError("valid_to must be later than valid_from")
        return date

class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    comment = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    @validates('rating')
    def validate_rating(self, key, rating):
        if not 1 <= rating <= 5:
            raise ValueError("Rating must be between 1 and 5")
        return rating