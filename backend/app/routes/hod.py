from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt
from bson import ObjectId
from datetime import datetime
import json

from app import mongo
from app.services.encryption_service import EncryptionService
from app.services.signature_service import SignatureService
from app.services.audit_service import AuditService
from app.middleware.auth_middleware import role_required

hod_bp = Blueprint('hod', __name__)


@hod_bp.route('/department-marks', methods=['GET'])
@jwt_required()
@role_required('hod')
def get_department_marks():
    """Get all submitted marks for HOD's department"""
    current_user_id = get_jwt_identity()
    claims = get_jwt()
    department = claims.get('department')
    
    status_filter = request.args.get('status', 'submitted')
    
    # Get subjects in department
    subjects = list(mongo.db.subjects.find({'department': department}))
    subject_ids = [s['_id'] for s in subjects]
    
    # Get marks for those subjects
    query = {'subject_id': {'$in': subject_ids}}
    if status_filter:
        query['status'] = status_filter
    
    marks = list(mongo.db.marks.find(query))
    
    result = []
    for mark in marks:
        try:
            decrypted = json.loads(EncryptionService.decrypt(mark['encrypted_marks']))
            
            student = mongo.db.students.find_one({'_id': mark['student_id']})
            subject = mongo.db.subjects.find_one({'_id': mark['subject_id']})
            faculty = mongo.db.users.find_one({'_id': mark['faculty_id']})
            
            result.append({
                '_id': str(mark['_id']),
                'student': {
                    '_id': str(student['_id']) if student else None,
                    'roll_number': student['roll_number'] if student else None,
                    'name': student['name'] if student else None
                },
                'subject': {
                    '_id': str(subject['_id']) if subject else None,
                    'code': subject['code'] if subject else None,
                    'name': subject['name'] if subject else None
                },
                'faculty': {
                    '_id': str(faculty['_id']) if faculty else None,
                    'username': faculty['username'] if faculty else None
                },
                'marks': decrypted['marks'],
                'status': mark['status'],
                'marks_hash': mark['marks_hash'],
                'created_at': mark['created_at'].isoformat() if mark.get('created_at') else None
            })
        except Exception as e:
            result.append({
                '_id': str(mark['_id']),
                'error': 'Failed to decrypt marks',
                'status': mark['status']
            })
    
    return jsonify({
        'marks': result,
        'department': department
    }), 200


@hod_bp.route('/marks/<mark_id>', methods=['GET'])
@jwt_required()
@role_required('hod')
def get_mark_detail(mark_id):
    """Get detailed view of a specific mark entry"""
    current_user_id = get_jwt_identity()
    claims = get_jwt()
    department = claims.get('department')
    
    mark = mongo.db.marks.find_one({'_id': ObjectId(mark_id)})
    
    if not mark:
        return jsonify({'error': 'Mark not found'}), 404
    
    # Verify access to department
    subject = mongo.db.subjects.find_one({'_id': mark['subject_id']})
    if not subject or subject['department'] != department:
        return jsonify({'error': 'Access denied'}), 403
    
    try:
        decrypted = json.loads(EncryptionService.decrypt(mark['encrypted_marks']))
        
        # Verify integrity
        marks_plain = json.dumps({
            'student_id': decrypted['student_id'],
            'subject_id': decrypted['subject_id'],
            'marks': decrypted['marks'],
            'faculty_id': decrypted['faculty_id'],
            'timestamp': decrypted['timestamp']
        })
        integrity_valid = EncryptionService.verify_hash(marks_plain, mark['marks_hash'])
        
        student = mongo.db.students.find_one({'_id': mark['student_id']})
        faculty = mongo.db.users.find_one({'_id': mark['faculty_id']})
        
        # Get moderation history
        moderations = list(mongo.db.moderations.find({'marks_id': mark['_id']}).sort('moderated_at', -1))
        moderation_history = []
        for mod in moderations:
            hod = mongo.db.users.find_one({'_id': mod['hod_id']})
            moderation_history.append({
                '_id': str(mod['_id']),
                'hod': hod['username'] if hod else None,
                'original_hash': mod['original_hash'],
                'moderated_hash': mod['moderated_hash'],
                'reason': mod.get('moderation_reason'),
                'moderated_at': mod['moderated_at'].isoformat()
            })
        
        return jsonify({
            '_id': str(mark['_id']),
            'student': {
                '_id': str(student['_id']) if student else None,
                'roll_number': student['roll_number'] if student else None,
                'name': student['name'] if student else None
            },
            'subject': {
                'code': subject['code'],
                'name': subject['name']
            },
            'faculty': {
                'username': faculty['username'] if faculty else None
            },
            'marks': decrypted['marks'],
            'status': mark['status'],
            'integrity_valid': integrity_valid,
            'moderation_history': moderation_history
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to decrypt marks'}), 500


@hod_bp.route('/moderate/<mark_id>', methods=['PUT'])
@jwt_required()
@role_required('hod')
def moderate_marks(mark_id):
    """Apply moderation to marks"""
    current_user_id = get_jwt_identity()
    claims = get_jwt()
    department = claims.get('department')
    data = request.get_json()
    
    new_marks = data.get('moderated_marks')
    reason = data.get('reason', '')
    
    if new_marks is None:
        return jsonify({'error': 'Moderated marks value is required'}), 400
    
    # Validate marks range
    try:
        marks_value = float(new_marks)
        if marks_value < 0 or marks_value > 100:
            return jsonify({'error': 'Marks must be between 0 and 100'}), 400
    except (ValueError, TypeError):
        return jsonify({'error': 'Invalid marks value'}), 400
    
    # Find mark
    mark = mongo.db.marks.find_one({'_id': ObjectId(mark_id)})
    if not mark:
        return jsonify({'error': 'Mark not found'}), 404
    
    # Verify access
    subject = mongo.db.subjects.find_one({'_id': mark['subject_id']})
    if not subject or subject['department'] != department:
        return jsonify({'error': 'Access denied'}), 403
    
    # Check if already finalized
    if mark['status'] == 'finalized':
        return jsonify({'error': 'Marks are finalized and cannot be modified'}), 403
    
    # Store original hash
    original_hash = mark['marks_hash']
    
    # Decrypt original for comparison
    original_decrypted = json.loads(EncryptionService.decrypt(mark['encrypted_marks']))
    
    # Prepare moderated marks data
    moderated_plain = json.dumps({
        'student_id': str(mark['student_id']),
        'subject_id': str(mark['subject_id']),
        'marks': marks_value,
        'faculty_id': str(mark['faculty_id']),
        'moderated_by': current_user_id,
        'timestamp': datetime.utcnow().isoformat()
    })
    
    # Encrypt and hash moderated marks
    encrypted_marks = EncryptionService.encrypt(moderated_plain)
    moderated_hash = EncryptionService.hash_data(moderated_plain)
    
    # Update marks
    mongo.db.marks.update_one(
        {'_id': ObjectId(mark_id)},
        {
            '$set': {
                'encrypted_marks': encrypted_marks,
                'marks_hash': moderated_hash,
                'status': 'moderated',
                'updated_at': datetime.utcnow()
            }
        }
    )
    
    # Create moderation record
    moderation = {
        'marks_id': ObjectId(mark_id),
        'hod_id': ObjectId(current_user_id),
        'original_hash': original_hash,
        'moderated_hash': moderated_hash,
        'original_marks': original_decrypted['marks'],
        'moderated_marks': marks_value,
        'moderation_reason': reason,
        'moderated_at': datetime.utcnow()
    }
    mongo.db.moderations.insert_one(moderation)
    
    AuditService.log_action(
        user_id=current_user_id,
        action='MODERATE_MARKS',
        entity_type='marks',
        entity_id=mark_id,
        details=f'Moderated marks from {original_decrypted["marks"]} to {marks_value}. Reason: {reason}'
    )
    
    return jsonify({
        'message': 'Marks moderated successfully',
        'original_marks': original_decrypted['marks'],
        'moderated_marks': marks_value
    }), 200


@hod_bp.route('/approve/<mark_id>', methods=['POST'])
@jwt_required()
@role_required('hod')
def approve_marks(mark_id):
    """Approve marks with digital signature"""
    current_user_id = get_jwt_identity()
    claims = get_jwt()
    department = claims.get('department')
    
    # Find mark
    mark = mongo.db.marks.find_one({'_id': ObjectId(mark_id)})
    if not mark:
        return jsonify({'error': 'Mark not found'}), 404
    
    # Verify access
    subject = mongo.db.subjects.find_one({'_id': mark['subject_id']})
    if not subject or subject['department'] != department:
        return jsonify({'error': 'Access denied'}), 403
    
    # Check if already finalized or approved
    if mark['status'] == 'finalized':
        return jsonify({'error': 'Marks are already finalized'}), 403
    if mark['status'] == 'approved':
        return jsonify({'error': 'Marks are already approved'}), 403
    
    # Get HOD's private key
    hod = mongo.db.users.find_one({'_id': ObjectId(current_user_id)})
    if not hod or not hod.get('private_key_encrypted'):
        return jsonify({'error': 'HOD signing key not found'}), 500
    
    # Create signed approval
    marks_data = mark['marks_hash']
    signed_approval = SignatureService.create_signed_approval(
        marks_data=marks_data,
        private_key_pem=hod['private_key_encrypted'],
        approver_id=current_user_id
    )
    
    # Update moderation record with signature
    mongo.db.moderations.update_one(
        {'marks_id': ObjectId(mark_id)},
        {
            '$set': {
                'hod_signature': signed_approval['signature'],
                'approval_timestamp': datetime.utcnow()
            }
        },
        upsert=True
    )
    
    # Update marks status
    mongo.db.marks.update_one(
        {'_id': ObjectId(mark_id)},
        {
            '$set': {
                'status': 'approved',
                'updated_at': datetime.utcnow()
            }
        }
    )
    
    AuditService.log_action(
        user_id=current_user_id,
        action='APPROVE_MARKS',
        entity_type='marks',
        entity_id=mark_id,
        details='Marks approved with digital signature'
    )
    
    return jsonify({
        'message': 'Marks approved and digitally signed',
        'signature': signed_approval['signature'][:50] + '...'  # Truncate for display
    }), 200


@hod_bp.route('/bulk-approve', methods=['POST'])
@jwt_required()
@role_required('hod')
def bulk_approve():
    """Approve multiple marks at once"""
    current_user_id = get_jwt_identity()
    claims = get_jwt()
    department = claims.get('department')
    data = request.get_json()
    
    mark_ids = data.get('mark_ids', [])
    
    if not mark_ids:
        return jsonify({'error': 'No marks selected for approval'}), 400
    
    # Get HOD's private key
    hod = mongo.db.users.find_one({'_id': ObjectId(current_user_id)})
    if not hod or not hod.get('private_key_encrypted'):
        return jsonify({'error': 'HOD signing key not found'}), 500
    
    approved = []
    errors = []
    
    for mark_id in mark_ids:
        try:
            mark = mongo.db.marks.find_one({'_id': ObjectId(mark_id)})
            if not mark:
                errors.append({'mark_id': mark_id, 'error': 'Not found'})
                continue
            
            subject = mongo.db.subjects.find_one({'_id': mark['subject_id']})
            if not subject or subject['department'] != department:
                errors.append({'mark_id': mark_id, 'error': 'Access denied'})
                continue
            
            if mark['status'] in ['approved', 'finalized']:
                errors.append({'mark_id': mark_id, 'error': 'Already processed'})
                continue
            
            # Sign and approve
            signed_approval = SignatureService.create_signed_approval(
                marks_data=mark['marks_hash'],
                private_key_pem=hod['private_key_encrypted'],
                approver_id=current_user_id
            )
            
            mongo.db.moderations.update_one(
                {'marks_id': ObjectId(mark_id)},
                {
                    '$set': {
                        'hod_id': ObjectId(current_user_id),
                        'hod_signature': signed_approval['signature'],
                        'approval_timestamp': datetime.utcnow()
                    }
                },
                upsert=True
            )
            
            mongo.db.marks.update_one(
                {'_id': ObjectId(mark_id)},
                {'$set': {'status': 'approved', 'updated_at': datetime.utcnow()}}
            )
            
            approved.append(mark_id)
            
        except Exception as e:
            errors.append({'mark_id': mark_id, 'error': str(e)})
    
    AuditService.log_action(
        user_id=current_user_id,
        action='BULK_APPROVE_MARKS',
        entity_type='marks',
        details=f'Bulk approved {len(approved)} marks'
    )
    
    return jsonify({
        'message': f'Approved {len(approved)} marks',
        'approved': approved,
        'errors': errors
    }), 200
