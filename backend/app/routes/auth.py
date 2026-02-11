from flask import Blueprint, request, jsonify
from flask_jwt_extended import create_access_token, create_refresh_token, jwt_required, get_jwt_identity, get_jwt
from bson import ObjectId
from datetime import datetime
import bcrypt

from app import mongo, limiter
from app.services.otp_service import OTPService
from app.services.audit_service import AuditService
from app.services.signature_service import SignatureService
from app.utils.password_policy import PasswordPolicy
from app.middleware.auth_middleware import is_account_locked

auth_bp = Blueprint('auth', __name__)


@auth_bp.route('/login', methods=['POST'])
@limiter.limit("50 per minute")
def login():
    """
    Step 1 of login: Validate credentials and send OTP
    """
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '')
    
    if not username or not password:
        return jsonify({'error': 'Username and password are required'}), 400
    
    # Check if account is locked
    if is_account_locked(username):
        AuditService.log_login_attempt(username, False, 'Account locked')
        return jsonify({
            'error': 'Account temporarily locked',
            'message': 'Too many failed login attempts. Please try again later.'
        }), 429
    
    # Find user
    user = mongo.db.users.find_one({'username': username, 'is_active': True})
    
    if not user:
        AuditService.log_login_attempt(username, False, 'User not found')
        return jsonify({'error': 'Invalid credentials'}), 401
    
    # Verify password
    if not bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
        AuditService.log_login_attempt(username, False, 'Invalid password')
        return jsonify({'error': 'Invalid credentials'}), 401
    
    # Generate and send OTP
    otp = OTPService.create_otp(str(user['_id']))
    
    # Send OTP via email (routes based on user role)
    email_sent = OTPService.send_otp_email(user['email'], otp, user['username'], user['role'])
    
    if not email_sent:
        # For development, return OTP in response (remove in production!)
        return jsonify({
            'message': 'OTP generated (email service unavailable)',
            'requires_otp': True,
            'user_id': str(user['_id']),
            'dev_otp': otp  # REMOVE IN PRODUCTION
        }), 200
    
    return jsonify({
        'message': 'OTP sent to your email',
        'requires_otp': True,
        'user_id': str(user['_id'])
    }), 200


@auth_bp.route('/verify-otp', methods=['POST'])
@limiter.limit("50 per minute")
def verify_otp():
    """
    Step 2 of login: Verify OTP and issue JWT
    """
    data = request.get_json()
    user_id = data.get('user_id')
    otp = data.get('otp', '').strip()
    
    if not user_id or not otp:
        return jsonify({'error': 'User ID and OTP are required'}), 400
    
    # Verify OTP
    if not OTPService.verify_otp(user_id, otp):
        user = mongo.db.users.find_one({'_id': ObjectId(user_id)})
        if user:
            AuditService.log_login_attempt(user['username'], False, 'Invalid OTP')
        return jsonify({'error': 'Invalid or expired OTP'}), 401
    
    # Get user
    user = mongo.db.users.find_one({'_id': ObjectId(user_id)})
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # Create tokens with additional claims
    additional_claims = {
        'role': user['role'],
        'department': user.get('department'),
        'username': user['username']
    }
    
    access_token = create_access_token(
        identity=str(user['_id']),
        additional_claims=additional_claims
    )
    refresh_token = create_refresh_token(identity=str(user['_id']))
    
    # Log successful login
    AuditService.log_login_attempt(user['username'], True)
    AuditService.log_action(
        user_id=str(user['_id']),
        action='LOGIN',
        entity_type='user',
        entity_id=str(user['_id']),
        details='User logged in successfully'
    )
    
    return jsonify({
        'message': 'Login successful',
        'access_token': access_token,
        'refresh_token': refresh_token,
        'user': {
            'id': str(user['_id']),
            'username': user['username'],
            'email': user['email'],
            'role': user['role'],
            'department': user.get('department')
        }
    }), 200


@auth_bp.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    """Refresh access token"""
    current_user_id = get_jwt_identity()
    user = mongo.db.users.find_one({'_id': ObjectId(current_user_id)})
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    additional_claims = {
        'role': user['role'],
        'department': user.get('department'),
        'username': user['username']
    }
    
    access_token = create_access_token(
        identity=current_user_id,
        additional_claims=additional_claims
    )
    
    return jsonify({'access_token': access_token}), 200


@auth_bp.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    """Logout user"""
    current_user_id = get_jwt_identity()
    
    AuditService.log_action(
        user_id=current_user_id,
        action='LOGOUT',
        entity_type='user',
        entity_id=current_user_id,
        details='User logged out'
    )
    
    return jsonify({'message': 'Logged out successfully'}), 200


@auth_bp.route('/me', methods=['GET'])
@jwt_required()
def get_current_user():
    """Get current user profile"""
    current_user_id = get_jwt_identity()
    user = mongo.db.users.find_one({'_id': ObjectId(current_user_id)})
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    return jsonify({
        'id': str(user['_id']),
        'username': user['username'],
        'email': user['email'],
        'role': user['role'],
        'department': user.get('department')
    }), 200


@auth_bp.route('/validate-password', methods=['POST'])
def validate_password():
    """Validate password against NIST policy"""
    data = request.get_json()
    password = data.get('password', '')
    
    result = PasswordPolicy.validate(password)
    strength = PasswordPolicy.get_strength(password)
    
    return jsonify({
        **result,
        'strength': strength
    }), 200


@auth_bp.route('/register', methods=['POST'])
@limiter.limit("30 per minute")
def register():
    """
    Register a new user (for demo/testing purposes)
    In production, this should be admin-only
    """
    data = request.get_json()
    
    username = data.get('username', '').strip()
    email = data.get('email', '').strip()
    password = data.get('password', '')
    role = data.get('role', 'faculty')
    department = data.get('department', '').strip()
    
    # Validate required fields
    if not all([username, email, password]):
        return jsonify({'error': 'Username, email, and password are required'}), 400
    
    # Validate password
    password_validation = PasswordPolicy.validate(password)
    if not password_validation['valid']:
        return jsonify({
            'error': 'Password does not meet requirements',
            'details': password_validation['errors']
        }), 400
    
    # Check if user already exists
    if mongo.db.users.find_one({'$or': [{'username': username}, {'email': email}]}):
        return jsonify({'error': 'Username or email already exists'}), 409
    
    # Validate role
    if role not in ['faculty', 'hod', 'admin']:
        return jsonify({'error': 'Invalid role'}), 400
    
    # Hash password
    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    # Generate RSA key pair for digital signatures
    public_key, private_key = SignatureService.generate_key_pair()
    
    # Create user
    user = {
        'username': username,
        'email': email,
        'password_hash': password_hash,
        'role': role,
        'department': department,
        'public_key': public_key,
        'private_key_encrypted': private_key,  # In production, encrypt this with user's password
        'is_active': True,
        'created_at': datetime.utcnow()
    }
    
    result = mongo.db.users.insert_one(user)
    
    AuditService.log_action(
        user_id=str(result.inserted_id),
        action='REGISTER',
        entity_type='user',
        entity_id=str(result.inserted_id),
        details=f'New user registered: {username} ({role})'
    )
    
    return jsonify({
        'message': 'User registered successfully',
        'user_id': str(result.inserted_id)
    }), 201


@auth_bp.route('/register-request', methods=['POST'])
@limiter.limit("30 per minute")
def register_request():
    """
    Step 1 of registration: Submit registration request and send OTP for email verification
    After OTP verification, the request goes to admin for approval
    """
    data = request.get_json()
    
    username = data.get('username', '').strip()
    email = data.get('email', '').strip()
    password = data.get('password', '')
    role = data.get('role', 'faculty')
    department = data.get('department', '').strip()
    
    # Validate required fields
    if not all([username, email, password, department]):
        return jsonify({'error': 'Username, email, password, and department are required'}), 400
    
    # Validate email format
    import re
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_pattern, email):
        return jsonify({'error': 'Invalid email format'}), 400
    
    # Validate password
    password_validation = PasswordPolicy.validate(password)
    if not password_validation['valid']:
        return jsonify({
            'error': 'Password does not meet requirements',
            'details': password_validation['errors']
        }), 400
    
    # Validate role (only faculty and hod can self-register, admin is created by existing admin)
    if role not in ['faculty', 'hod']:
        return jsonify({'error': 'Invalid role. Only faculty and hod can register.'}), 400
    
    # Check if user already exists in users collection
    if mongo.db.users.find_one({'$or': [{'username': username}, {'email': email}]}):
        return jsonify({'error': 'Username or email already exists'}), 409
    
    # Check if there's already a pending registration
    existing_pending = mongo.db.pending_registrations.find_one({
        '$or': [{'username': username}, {'email': email}],
        'status': 'pending'
    })
    if existing_pending:
        return jsonify({'error': 'A registration request with this username or email is already pending'}), 409
    
    # Hash password
    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    # Create pending registration
    pending_reg = {
        'username': username,
        'email': email,
        'password_hash': password_hash,
        'role': role,
        'department': department,
        'email_verified': False,
        'status': 'pending',
        'created_at': datetime.utcnow()
    }
    
    result = mongo.db.pending_registrations.insert_one(pending_reg)
    pending_id = str(result.inserted_id)
    
    # Generate and send OTP
    otp = OTPService.create_otp(pending_id)
    email_sent = OTPService.send_otp_email(email, otp, username, role)
    
    if not email_sent:
        # For development, return OTP in response
        return jsonify({
            'message': 'OTP generated (email service unavailable)',
            'pending_id': pending_id,
            'dev_otp': otp  # REMOVE IN PRODUCTION
        }), 200
    
    return jsonify({
        'message': 'OTP sent to your email for verification',
        'pending_id': pending_id
    }), 200


@auth_bp.route('/verify-registration-otp', methods=['POST'])
@limiter.limit("50 per minute")
def verify_registration_otp():
    """
    Step 2 of registration: Verify OTP for email verification
    After this, the registration request is pending admin approval
    """
    data = request.get_json()
    pending_id = data.get('pending_id')
    otp = data.get('otp', '').strip()
    
    if not pending_id or not otp:
        return jsonify({'error': 'Pending ID and OTP are required'}), 400
    
    # Find pending registration
    try:
        pending_reg = mongo.db.pending_registrations.find_one({
            '_id': ObjectId(pending_id),
            'status': 'pending'
        })
    except:
        return jsonify({'error': 'Invalid pending ID'}), 400
    
    if not pending_reg:
        return jsonify({'error': 'Registration request not found or already processed'}), 404
    
    if pending_reg.get('email_verified'):
        return jsonify({'error': 'Email already verified. Waiting for admin approval.'}), 400
    
    # Verify OTP
    if not OTPService.verify_otp(pending_id, otp):
        return jsonify({'error': 'Invalid or expired OTP'}), 401
    
    # Mark email as verified
    mongo.db.pending_registrations.update_one(
        {'_id': ObjectId(pending_id)},
        {'$set': {'email_verified': True, 'verified_at': datetime.utcnow()}}
    )
    
    AuditService.log_action(
        user_id=pending_id,
        action='REGISTRATION_EMAIL_VERIFIED',
        entity_type='pending_registration',
        entity_id=pending_id,
        details=f'Email verified for registration: {pending_reg["username"]}'
    )
    
    return jsonify({
        'message': 'Email verified successfully. Your registration is pending admin approval.',
        'status': 'pending_approval'
    }), 200
