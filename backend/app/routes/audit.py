from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from datetime import datetime
import csv
import io

from app import mongo
from app.services.audit_service import AuditService
from app.middleware.auth_middleware import role_required

audit_bp = Blueprint('audit', __name__)


@audit_bp.route('/logs', methods=['GET'])
@jwt_required()
@role_required('admin')
def get_audit_logs():
    """Get paginated audit logs"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    action = request.args.get('action')
    
    filters = {}
    if action:
        filters['action'] = action
    
    result = AuditService.get_audit_logs(filters, page, per_page)
    return jsonify(result), 200


@audit_bp.route('/unauthorized', methods=['GET'])
@jwt_required()
@role_required('admin')
def get_unauthorized_attempts():
    """Get failed login attempts"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    
    result = AuditService.get_unauthorized_attempts(page, per_page)
    return jsonify(result), 200


@audit_bp.route('/export', methods=['GET'])
@jwt_required()
@role_required('admin')
def export_logs():
    """Export audit logs as CSV"""
    logs = list(mongo.db.audit_logs.find().sort('timestamp', -1).limit(1000))
    
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Timestamp', 'User ID', 'Action', 'Entity Type', 'Entity ID', 'Details', 'IP Address'])
    
    for log in logs:
        writer.writerow([
            log['timestamp'].isoformat(),
            str(log.get('user_id', '')),
            log.get('action', ''),
            log.get('entity_type', ''),
            str(log.get('entity_id', '')),
            log.get('details', ''),
            log.get('ip_address', '')
        ])
    
    AuditService.log_action(get_jwt_identity(), 'EXPORT_LOGS', 'audit', details='Exported audit logs')
    
    return jsonify({
        'csv_data': output.getvalue(),
        'filename': f'audit_logs_{datetime.utcnow().strftime("%Y%m%d_%H%M%S")}.csv'
    }), 200
