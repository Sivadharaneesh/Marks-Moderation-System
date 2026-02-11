from functools import wraps
from flask import jsonify
from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity, get_jwt
from app import mongo


def role_required(*allowed_roles):
    """
    Decorator to restrict access based on user roles
    
    Usage:
        @role_required('admin')
        @role_required('faculty', 'hod')
    """
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            verify_jwt_in_request()
            claims = get_jwt()
            user_role = claims.get('role', '')
            
            if user_role not in allowed_roles:
                return jsonify({
                    'error': 'Unauthorized',
                    'message': f'This action requires one of the following roles: {", ".join(allowed_roles)}'
                }), 403
            
            return fn(*args, **kwargs)
        return wrapper
    return decorator


def department_access(fn):
    """
    Decorator to ensure user can only access their department's data
    Applies to HOD role
    """
    @wraps(fn)
    def wrapper(*args, **kwargs):
        verify_jwt_in_request()
        user_id = get_jwt_identity()
        claims = get_jwt()
        
        user = mongo.db.users.find_one({'_id': user_id})
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Add user's department to kwargs for route to use
        kwargs['user_department'] = user.get('department')
        kwargs['user_role'] = claims.get('role')
        
        return fn(*args, **kwargs)
    return wrapper


def get_current_user():
    """Get the current authenticated user from JWT"""
    verify_jwt_in_request()
    user_id = get_jwt_identity()
    user = mongo.db.users.find_one({'_id': user_id})
    return user


def is_account_locked(username: str) -> bool:
    """Check if account is locked due to too many failed attempts"""
    from app.services.audit_service import AuditService
    from flask import current_app
    
    max_attempts = current_app.config.get('MAX_LOGIN_ATTEMPTS', 5)
    lockout_minutes = current_app.config.get('LOCKOUT_DURATION_MINUTES', 15)
    
    failed_attempts = AuditService.get_failed_login_count(username, lockout_minutes)
    return failed_attempts >= max_attempts
