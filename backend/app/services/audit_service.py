from datetime import datetime
from flask import request
from app import mongo


class AuditService:
    """Service for comprehensive audit logging"""
    
    @staticmethod
    def log_action(user_id: str, action: str, entity_type: str = None, 
                   entity_id: str = None, details: str = None) -> None:
        """
        Log an action to the audit trail
        
        Args:
            user_id: ID of the user performing the action
            action: Type of action (e.g., 'LOGIN', 'UPLOAD_MARKS', 'APPROVE')
            entity_type: Type of entity affected (e.g., 'marks', 'user')
            entity_id: ID of the affected entity
            details: Additional details about the action
        """
        log_entry = {
            'user_id': user_id,
            'action': action,
            'entity_type': entity_type,
            'entity_id': entity_id,
            'details': details,
            'ip_address': request.remote_addr if request else None,
            'user_agent': request.user_agent.string if request else None,
            'timestamp': datetime.utcnow()
        }
        
        mongo.db.audit_logs.insert_one(log_entry)
    
    @staticmethod
    def log_login_attempt(username: str, success: bool, reason: str = None) -> None:
        """Log a login attempt"""
        login_entry = {
            'username': username,
            'success': success,
            'reason': reason,
            'ip_address': request.remote_addr if request else None,
            'timestamp': datetime.utcnow()
        }
        
        mongo.db.login_attempts.insert_one(login_entry)
    
    @staticmethod
    def get_failed_login_count(username: str, minutes: int = 15) -> int:
        """Get count of failed login attempts in the last N minutes"""
        from datetime import timedelta
        
        cutoff = datetime.utcnow() - timedelta(minutes=minutes)
        count = mongo.db.login_attempts.count_documents({
            'username': username,
            'success': False,
            'timestamp': {'$gte': cutoff}
        })
        
        return count
    
    @staticmethod
    def get_audit_logs(filters: dict = None, page: int = 1, per_page: int = 50) -> dict:
        """
        Get paginated audit logs with optional filters
        
        Args:
            filters: Dict with optional keys: user_id, action, entity_type, start_date, end_date
            page: Page number (1-indexed)
            per_page: Number of items per page
        """
        query = {}
        
        if filters:
            if filters.get('user_id'):
                query['user_id'] = filters['user_id']
            if filters.get('action'):
                query['action'] = filters['action']
            if filters.get('entity_type'):
                query['entity_type'] = filters['entity_type']
            if filters.get('start_date'):
                query['timestamp'] = {'$gte': filters['start_date']}
            if filters.get('end_date'):
                if 'timestamp' in query:
                    query['timestamp']['$lte'] = filters['end_date']
                else:
                    query['timestamp'] = {'$lte': filters['end_date']}
        
        total = mongo.db.audit_logs.count_documents(query)
        skip = (page - 1) * per_page
        
        logs = list(mongo.db.audit_logs.find(query)
                    .sort('timestamp', -1)
                    .skip(skip)
                    .limit(per_page))
        
        # Convert ObjectId to string for JSON serialization
        for log in logs:
            log['_id'] = str(log['_id'])
            if log.get('user_id'):
                log['user_id'] = str(log['user_id'])
            if log.get('entity_id'):
                log['entity_id'] = str(log['entity_id'])
        
        return {
            'logs': logs,
            'total': total,
            'page': page,
            'per_page': per_page,
            'pages': (total + per_page - 1) // per_page
        }
    
    @staticmethod
    def get_unauthorized_attempts(page: int = 1, per_page: int = 50) -> dict:
        """Get failed login attempts and unauthorized access logs"""
        query = {'success': False}
        
        total = mongo.db.login_attempts.count_documents(query)
        skip = (page - 1) * per_page
        
        attempts = list(mongo.db.login_attempts.find(query)
                        .sort('timestamp', -1)
                        .skip(skip)
                        .limit(per_page))
        
        for attempt in attempts:
            attempt['_id'] = str(attempt['_id'])
        
        return {
            'attempts': attempts,
            'total': total,
            'page': page,
            'per_page': per_page,
            'pages': (total + per_page - 1) // per_page
        }
