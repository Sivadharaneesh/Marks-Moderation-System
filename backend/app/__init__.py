from flask import Flask
from flask_pymongo import PyMongo
from flask_jwt_extended import JWTManager
from flask_mail import Mail
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS

from .config import config

# Initialize extensions
mongo = PyMongo()
jwt = JWTManager()
mail = Mail()
limiter = Limiter(key_func=get_remote_address)


def create_app(config_name='default'):
    """Application factory"""
    app = Flask(__name__)
    app.config.from_object(config[config_name])
    
    # Initialize extensions with app
    mongo.init_app(app)
    jwt.init_app(app)
    mail.init_app(app)
    limiter.init_app(app)
    CORS(app, resources={r"/api/*": {"origins": ["http://localhost:3000", "http://localhost:3001"]}})
    
    # Register blueprints
    from .routes.auth import auth_bp
    from .routes.faculty import faculty_bp
    from .routes.hod import hod_bp
    from .routes.admin import admin_bp
    from .routes.audit import audit_bp
    
    app.register_blueprint(auth_bp, url_prefix='/api/auth')
    app.register_blueprint(faculty_bp, url_prefix='/api/faculty')
    app.register_blueprint(hod_bp, url_prefix='/api/hod')
    app.register_blueprint(admin_bp, url_prefix='/api/admin')
    app.register_blueprint(audit_bp, url_prefix='/api/audit')
    
    # Create indexes for MongoDB collections
    with app.app_context():
        create_indexes()
    
    return app


def create_indexes():
    """Create MongoDB indexes for better performance"""
    db = mongo.db
    
    # Users collection indexes
    db.users.create_index('username', unique=True)
    db.users.create_index('email', unique=True)
    db.users.create_index('department')
    
    # Subjects collection indexes
    db.subjects.create_index('code', unique=True)
    db.subjects.create_index('faculty_id')
    db.subjects.create_index('department')
    
    # Students collection indexes
    db.students.create_index('roll_number', unique=True)
    db.students.create_index('department')
    
    # Marks collection indexes
    db.marks.create_index('student_id')
    db.marks.create_index('subject_id')
    db.marks.create_index('faculty_id')
    db.marks.create_index('status')
    db.marks.create_index([('subject_id', 1), ('status', 1)])
    
    # Audit logs indexes
    db.audit_logs.create_index('user_id')
    db.audit_logs.create_index('timestamp')
    db.audit_logs.create_index('action')
    
    # Login attempts indexes
    db.login_attempts.create_index('username')
    db.login_attempts.create_index('timestamp')
    
    # OTPs indexes
    db.otps.create_index('user_id')
    db.otps.create_index('expires_at')
