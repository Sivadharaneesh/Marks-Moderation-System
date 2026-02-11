from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from bson import ObjectId
from datetime import datetime
import json
import bcrypt

from app import mongo
from app.services.encryption_service import EncryptionService
from app.services.signature_service import SignatureService
from app.services.audit_service import AuditService
from app.services.otp_service import OTPService
from app.middleware.auth_middleware import role_required

admin_bp = Blueprint('admin', __name__)


@admin_bp.route('/pending', methods=['GET'])
@jwt_required()
@role_required('admin')
def get_pending_marks():
    """Get all HOD-approved marks pending final approval"""
    marks = list(mongo.db.marks.find({'status': 'approved'}))
    
    result = []
    for mark in marks:
        try:
            decrypted = json.loads(EncryptionService.decrypt(mark['encrypted_marks']))
            student = mongo.db.students.find_one({'_id': mark['student_id']})
            subject = mongo.db.subjects.find_one({'_id': mark['subject_id']})
            
            # Check if HOD has signed this mark
            moderation = mongo.db.moderations.find_one({'marks_id': mark['_id']})
            has_hod_signature = moderation and moderation.get('hod_signature') is not None
            
            result.append({
                '_id': str(mark['_id']),
                'student': {
                    'roll_number': student['roll_number'] if student else None, 
                    'name': student['name'] if student else None
                },
                'subject': {
                    'code': subject['code'] if subject else None, 
                    'name': subject['name'] if subject else None,
                    'department': subject['department'] if subject else None
                },
                'marks': decrypted.get('marks'),
                'status': mark['status'],
                'has_hod_signature': has_hod_signature,
                'hod_signature_preview': moderation.get('hod_signature', '')[:50] + '...' if has_hod_signature else None
            })
        except:
            pass
    
    return jsonify({'marks': result}), 200


@admin_bp.route('/finalize/<mark_id>', methods=['POST'])
@jwt_required()
@role_required('admin')
def finalize_marks(mark_id):
    """Final lock marks with admin digital signature"""
    current_user_id = get_jwt_identity()
    
    mark = mongo.db.marks.find_one({'_id': ObjectId(mark_id)})
    if not mark:
        return jsonify({'error': 'Mark not found'}), 404
    
    if mark['status'] == 'finalized':
        return jsonify({'error': 'Already finalized'}), 403
    
    if mark['status'] != 'approved':
        return jsonify({'error': 'Must be approved by HOD first'}), 403
    
    admin = mongo.db.users.find_one({'_id': ObjectId(current_user_id)})
    if not admin or not admin.get('private_key_encrypted'):
        return jsonify({'error': 'Admin signing key not found'}), 500
    
    signed_approval = SignatureService.create_signed_approval(
        marks_data=mark['marks_hash'],
        private_key_pem=admin['private_key_encrypted'],
        approver_id=current_user_id
    )
    
    mongo.db.final_approvals.insert_one({
        'marks_id': ObjectId(mark_id),
        'admin_id': ObjectId(current_user_id),
        'admin_signature': signed_approval['signature'],
        'finalized_at': datetime.utcnow()
    })
    
    mongo.db.marks.update_one(
        {'_id': ObjectId(mark_id)},
        {'$set': {'status': 'finalized', 'updated_at': datetime.utcnow()}}
    )
    
    AuditService.log_action(current_user_id, 'FINALIZE_MARKS', 'marks', mark_id, 'Marks finalized')
    
    return jsonify({'message': 'Marks finalized and locked'}), 200


@admin_bp.route('/bulk-finalize', methods=['POST'])
@jwt_required()
@role_required('admin')
def bulk_finalize_marks():
    """Bulk finalize multiple marks at once"""
    current_user_id = get_jwt_identity()
    data = request.get_json()
    
    mark_ids = data.get('mark_ids', [])
    if not mark_ids:
        return jsonify({'error': 'No mark IDs provided'}), 400
    
    admin = mongo.db.users.find_one({'_id': ObjectId(current_user_id)})
    if not admin or not admin.get('private_key_encrypted'):
        return jsonify({'error': 'Admin signing key not found'}), 500
    
    success_count = 0
    failed_count = 0
    failed_ids = []
    
    for mark_id in mark_ids:
        try:
            mark = mongo.db.marks.find_one({'_id': ObjectId(mark_id)})
            if not mark:
                failed_count += 1
                failed_ids.append(mark_id)
                continue
            
            if mark['status'] == 'finalized':
                # Already finalized, skip but count as success
                success_count += 1
                continue
            
            if mark['status'] != 'approved':
                failed_count += 1
                failed_ids.append(mark_id)
                continue
            
            # Create signed approval
            signed_approval = SignatureService.create_signed_approval(
                marks_data=mark['marks_hash'],
                private_key_pem=admin['private_key_encrypted'],
                approver_id=current_user_id
            )
            
            # Store final approval
            mongo.db.final_approvals.insert_one({
                'marks_id': ObjectId(mark_id),
                'admin_id': ObjectId(current_user_id),
                'admin_signature': signed_approval['signature'],
                'finalized_at': datetime.utcnow()
            })
            
            # Update mark status
            mongo.db.marks.update_one(
                {'_id': ObjectId(mark_id)},
                {'$set': {'status': 'finalized', 'updated_at': datetime.utcnow()}}
            )
            
            AuditService.log_action(current_user_id, 'FINALIZE_MARKS', 'marks', mark_id, 'Marks finalized (bulk)')
            success_count += 1
            
        except Exception as e:
            failed_count += 1
            failed_ids.append(mark_id)
    
    message = f'Successfully finalized {success_count} marks'
    if failed_count > 0:
        message += f', {failed_count} failed'
    
    return jsonify({
        'message': message,
        'success_count': success_count,
        'failed_count': failed_count,
        'failed_ids': failed_ids
    }), 200


@admin_bp.route('/verify/<mark_id>', methods=['POST'])
@jwt_required()
@role_required('admin')
def verify_marks(mark_id):
    """Verify hash integrity and HOD digital signature"""
    try:
        mark = mongo.db.marks.find_one({'_id': ObjectId(mark_id)})
        if not mark:
            return jsonify({'error': 'Mark not found'}), 404
        
        # Verify hash integrity
        try:
            decrypted = EncryptionService.decrypt(mark['encrypted_marks'])
            current_hash = EncryptionService.hash_data(decrypted)
            hash_valid = current_hash == mark['marks_hash']
        except Exception as e:
            hash_valid = False
        
        # Verify HOD signature
        signature_valid = False
        hod_username = None
        
        moderation = mongo.db.moderations.find_one({'marks_id': mark['_id']})
        if moderation and moderation.get('hod_signature') and moderation.get('hod_id'):
            hod = mongo.db.users.find_one({'_id': moderation['hod_id']})
            if hod and hod.get('public_key'):
                try:
                    # Reconstruct the signed data
                    signed_data = moderation.get('signed_data', mark['marks_hash'])
                    signature_valid = SignatureService.verify_signature(
                        data=signed_data,
                        signature=moderation['hod_signature'],
                        public_key_pem=hod['public_key']
                    )
                    hod_username = hod.get('username')
                except Exception as e:
                    signature_valid = False
        
        return jsonify({
            'mark_id': mark_id,
            'hash_valid': hash_valid,
            'signature_valid': signature_valid,
            'hod_signed_by': hod_username,
            'status': mark['status'],
            'message': 'Verification complete'
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Verification failed: {str(e)}'}), 500


@admin_bp.route('/dashboard', methods=['GET'])
@jwt_required()
@role_required('admin')
def get_dashboard():
    """Get admin dashboard statistics"""
    return jsonify({
        'total_users': mongo.db.users.count_documents({}),
        'marks_stats': {
            'submitted': mongo.db.marks.count_documents({'status': 'submitted'}),
            'approved': mongo.db.marks.count_documents({'status': 'approved'}),
            'finalized': mongo.db.marks.count_documents({'status': 'finalized'})
        }
    }), 200


@admin_bp.route('/finalized', methods=['GET'])
@jwt_required()
@role_required('admin')
def get_finalized_marks():
    """Get all finalized marks with pagination"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    
    # Limit per_page to prevent excessive data
    per_page = min(per_page, 100)
    skip = (page - 1) * per_page
    
    # Get total count
    total = mongo.db.marks.count_documents({'status': 'finalized'})
    
    # Get paginated marks
    marks = list(mongo.db.marks.find({'status': 'finalized'}).skip(skip).limit(per_page))
    
    result = []
    for mark in marks:
        try:
            decrypted = json.loads(EncryptionService.decrypt(mark['encrypted_marks']))
            student = mongo.db.students.find_one({'_id': mark['student_id']})
            subject = mongo.db.subjects.find_one({'_id': mark['subject_id']})
            faculty = mongo.db.users.find_one({'_id': mark.get('faculty_id')})
            
            # Get the final approval record if exists
            final_approval = mongo.db.final_approvals.find_one({'marks_id': mark['_id']})
            
            result.append({
                '_id': str(mark['_id']),
                'student': {
                    'roll_number': student['roll_number'] if student else None, 
                    'name': student['name'] if student else None
                },
                'subject': {
                    'code': subject['code'] if subject else None, 
                    'name': subject['name'] if subject else None
                },
                'faculty': {
                    'username': faculty['username'] if faculty else None
                },
                'marks': decrypted.get('marks'),
                'status': mark['status'],
                'finalized_at': final_approval['finalized_at'].isoformat() if final_approval and final_approval.get('finalized_at') else None,
                'created_at': mark.get('created_at').isoformat() if mark.get('created_at') else None
            })
        except Exception as e:
            # Log error but continue processing other marks
            pass
    
    return jsonify({
        'marks': result,
        'pagination': {
            'page': page,
            'per_page': per_page,
            'total': total,
            'pages': (total + per_page - 1) // per_page
        }
    }), 200


@admin_bp.route('/users', methods=['GET'])
@jwt_required()
@role_required('admin')
def get_users():
    """Get all users (admin only) - Access Control List demonstration"""
    users = list(mongo.db.users.find({}, {
        'password_hash': 0,
        'private_key_encrypted': 0
    }))
    
    result = []
    for user in users:
        result.append({
            '_id': str(user['_id']),
            'username': user['username'],
            'email': user['email'],
            'role': user['role'],
            'department': user.get('department'),
            'is_active': user.get('is_active', True),
            'created_at': user.get('created_at').isoformat() if user.get('created_at') else None
        })
    
    return jsonify({'users': result}), 200


@admin_bp.route('/users/<user_id>/toggle-status', methods=['POST'])
@jwt_required()
@role_required('admin')
def toggle_user_status(user_id):
    """Toggle user active status (admin only)"""
    current_user_id = get_jwt_identity()
    
    user = mongo.db.users.find_one({'_id': ObjectId(user_id)})
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # Prevent admin from deactivating themselves
    if str(user['_id']) == current_user_id:
        return jsonify({'error': 'Cannot deactivate yourself'}), 403
    
    new_status = not user.get('is_active', True)
    mongo.db.users.update_one(
        {'_id': ObjectId(user_id)},
        {'$set': {'is_active': new_status}}
    )
    
    AuditService.log_action(
        current_user_id, 
        'TOGGLE_USER_STATUS', 
        'user', 
        user_id, 
        f"User {'activated' if new_status else 'deactivated'}: {user['username']}"
    )
    
    return jsonify({
        'message': f"User {'activated' if new_status else 'deactivated'}",
        'is_active': new_status
    }), 200


@admin_bp.route('/pending-registrations', methods=['GET'])
@jwt_required()
@role_required('admin')
def get_pending_registrations():
    """Get all pending registrations that have verified their email"""
    pending = list(mongo.db.pending_registrations.find({
        'email_verified': True,
        'status': 'pending'
    }))
    
    result = []
    for reg in pending:
        result.append({
            '_id': str(reg['_id']),
            'username': reg['username'],
            'email': reg['email'],
            'role': reg['role'],
            'department': reg['department'],
            'created_at': reg.get('created_at').isoformat() if reg.get('created_at') else None,
            'verified_at': reg.get('verified_at').isoformat() if reg.get('verified_at') else None
        })
    
    return jsonify({'pending_registrations': result}), 200


@admin_bp.route('/approve-registration/<pending_id>', methods=['POST'])
@jwt_required()
@role_required('admin')
def approve_registration(pending_id):
    """Approve a pending registration and create the user account"""
    current_user_id = get_jwt_identity()
    
    try:
        pending_reg = mongo.db.pending_registrations.find_one({
            '_id': ObjectId(pending_id),
            'status': 'pending',
            'email_verified': True
        })
    except:
        return jsonify({'error': 'Invalid pending ID'}), 400
    
    if not pending_reg:
        return jsonify({'error': 'Pending registration not found or already processed'}), 404
    
    # Generate RSA key pair for digital signatures
    public_key, private_key = SignatureService.generate_key_pair()
    
    # Create user account
    user = {
        'username': pending_reg['username'],
        'email': pending_reg['email'],
        'password_hash': pending_reg['password_hash'],
        'role': pending_reg['role'],
        'department': pending_reg['department'],
        'public_key': public_key,
        'private_key_encrypted': private_key,
        'is_active': True,
        'created_at': datetime.utcnow(),
        'approved_by': ObjectId(current_user_id),
        'approved_at': datetime.utcnow()
    }
    
    result = mongo.db.users.insert_one(user)
    
    # Update pending registration status
    mongo.db.pending_registrations.update_one(
        {'_id': ObjectId(pending_id)},
        {'$set': {
            'status': 'approved',
            'approved_by': ObjectId(current_user_id),
            'approved_at': datetime.utcnow()
        }}
    )
    
    # Log the action
    AuditService.log_action(
        user_id=current_user_id,
        action='APPROVE_REGISTRATION',
        entity_type='user',
        entity_id=str(result.inserted_id),
        details=f'Approved registration for {pending_reg["username"]} ({pending_reg["role"]})'
    )
    
    # Send approval email notification
    try:
        from flask_mail import Message
        from app import mail
        
        msg = Message(
            subject='Registration Approved - Marks Moderation System',
            recipients=[pending_reg['email']],
            html=f'''
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                <h2 style="color: #10b981;">Registration Approved!</h2>
                <p>Hello <strong>{pending_reg['username']}</strong>,</p>
                <p>Your registration request has been approved. You can now login to the Marks Moderation System.</p>
                <div style="background: #f3f4f6; padding: 20px; border-radius: 8px; margin: 20px 0;">
                    <p><strong>Role:</strong> {pending_reg['role'].upper()}</p>
                    <p><strong>Department:</strong> {pending_reg['department']}</p>
                </div>
                <p>You can login using your registered username and password.</p>
                <hr style="border: none; border-top: 1px solid #e5e7eb; margin: 20px 0;">
                <p style="color: #9ca3af; font-size: 12px;">This is an automated message. Please do not reply.</p>
            </div>
            '''
        )
        mail.send(msg)
    except Exception as e:
        # Email sending failed, but registration is still approved
        pass
    
    return jsonify({
        'message': 'Registration approved successfully',
        'user_id': str(result.inserted_id)
    }), 200


@admin_bp.route('/reject-registration/<pending_id>', methods=['POST'])
@jwt_required()
@role_required('admin')
def reject_registration(pending_id):
    """Reject a pending registration"""
    current_user_id = get_jwt_identity()
    data = request.get_json() or {}
    reason = data.get('reason', 'Your registration request has been declined.')
    
    try:
        pending_reg = mongo.db.pending_registrations.find_one({
            '_id': ObjectId(pending_id),
            'status': 'pending'
        })
    except:
        return jsonify({'error': 'Invalid pending ID'}), 400
    
    if not pending_reg:
        return jsonify({'error': 'Pending registration not found or already processed'}), 404
    
    # Update pending registration status
    mongo.db.pending_registrations.update_one(
        {'_id': ObjectId(pending_id)},
        {'$set': {
            'status': 'rejected',
            'rejected_by': ObjectId(current_user_id),
            'rejected_at': datetime.utcnow(),
            'rejection_reason': reason
        }}
    )
    
    # Log the action
    AuditService.log_action(
        user_id=current_user_id,
        action='REJECT_REGISTRATION',
        entity_type='pending_registration',
        entity_id=pending_id,
        details=f'Rejected registration for {pending_reg["username"]}: {reason}'
    )
    
    # Send rejection email notification
    try:
        from flask_mail import Message
        from app import mail
        
        msg = Message(
            subject='Registration Status - Marks Moderation System',
            recipients=[pending_reg['email']],
            html=f'''
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                <h2 style="color: #ef4444;">Registration Not Approved</h2>
                <p>Hello <strong>{pending_reg['username']}</strong>,</p>
                <p>We regret to inform you that your registration request has not been approved.</p>
                <div style="background: #fef2f2; padding: 20px; border-radius: 8px; margin: 20px 0;">
                    <p><strong>Reason:</strong> {reason}</p>
                </div>
                <p>If you believe this is an error, please contact the administrator.</p>
                <hr style="border: none; border-top: 1px solid #e5e7eb; margin: 20px 0;">
                <p style="color: #9ca3af; font-size: 12px;">This is an automated message. Please do not reply.</p>
            </div>
            '''
        )
        mail.send(msg)
    except Exception as e:
        # Email sending failed, but rejection is still recorded
        pass
    
    return jsonify({
        'message': 'Registration rejected',
        'pending_id': pending_id
    }), 200


# ============================================
# Subject Management Endpoints
# ============================================

@admin_bp.route('/subjects', methods=['GET'])
@jwt_required()
@role_required('admin')
def get_all_subjects():
    """Get all subjects with assigned faculty info"""
    subjects = list(mongo.db.subjects.find({}))
    
    result = []
    for subject in subjects:
        faculty = None
        if subject.get('faculty_id'):
            faculty_user = mongo.db.users.find_one({'_id': subject['faculty_id']})
            if faculty_user:
                faculty = {
                    '_id': str(faculty_user['_id']),
                    'username': faculty_user['username'],
                    'department': faculty_user.get('department')
                }
        
        result.append({
            '_id': str(subject['_id']),
            'code': subject['code'],
            'name': subject['name'],
            'department': subject.get('department'),
            'faculty': faculty
        })
    
    return jsonify({'subjects': result}), 200


@admin_bp.route('/subjects', methods=['POST'])
@jwt_required()
@role_required('admin')
def create_subject():
    """Create a new subject"""
    current_user_id = get_jwt_identity()
    data = request.get_json()
    
    code = data.get('code', '').strip()
    name = data.get('name', '').strip()
    department = data.get('department', '').strip()
    faculty_id = data.get('faculty_id')
    
    if not all([code, name, department]):
        return jsonify({'error': 'Code, name, and department are required'}), 400
    
    # Check if subject code already exists
    if mongo.db.subjects.find_one({'code': code}):
        return jsonify({'error': 'Subject code already exists'}), 409
    
    subject = {
        'code': code,
        'name': name,
        'department': department,
        'created_at': datetime.utcnow()
    }
    
    # Optionally assign faculty
    if faculty_id:
        faculty = mongo.db.users.find_one({
            '_id': ObjectId(faculty_id),
            'role': 'faculty'
        })
        if faculty:
            subject['faculty_id'] = ObjectId(faculty_id)
    
    result = mongo.db.subjects.insert_one(subject)
    
    AuditService.log_action(
        user_id=current_user_id,
        action='CREATE_SUBJECT',
        entity_type='subject',
        entity_id=str(result.inserted_id),
        details=f'Created subject: {code} - {name}'
    )
    
    return jsonify({
        'message': 'Subject created successfully',
        'subject_id': str(result.inserted_id)
    }), 201


@admin_bp.route('/subjects/<subject_id>/assign', methods=['PUT'])
@jwt_required()
@role_required('admin')
def assign_subject_to_faculty(subject_id):
    """Assign a subject to a faculty member"""
    current_user_id = get_jwt_identity()
    data = request.get_json()
    
    faculty_id = data.get('faculty_id')
    
    try:
        subject = mongo.db.subjects.find_one({'_id': ObjectId(subject_id)})
    except:
        return jsonify({'error': 'Invalid subject ID'}), 400
    
    if not subject:
        return jsonify({'error': 'Subject not found'}), 404
    
    update_data = {'updated_at': datetime.utcnow()}
    
    if faculty_id:
        # Assign to faculty
        faculty = mongo.db.users.find_one({
            '_id': ObjectId(faculty_id),
            'role': 'faculty'
        })
        if not faculty:
            return jsonify({'error': 'Faculty not found'}), 404
        
        update_data['faculty_id'] = ObjectId(faculty_id)
        action_detail = f'Assigned {subject["code"]} to {faculty["username"]}'
    else:
        # Unassign (remove faculty)
        update_data['faculty_id'] = None
        action_detail = f'Unassigned faculty from {subject["code"]}'
    
    mongo.db.subjects.update_one(
        {'_id': ObjectId(subject_id)},
        {'$set': update_data}
    )
    
    AuditService.log_action(
        user_id=current_user_id,
        action='ASSIGN_SUBJECT',
        entity_type='subject',
        entity_id=subject_id,
        details=action_detail
    )
    
    return jsonify({'message': 'Subject assignment updated'}), 200


@admin_bp.route('/subjects/<subject_id>', methods=['DELETE'])
@jwt_required()
@role_required('admin')
def delete_subject(subject_id):
    """Delete a subject (only if no marks exist)"""
    current_user_id = get_jwt_identity()
    
    try:
        subject = mongo.db.subjects.find_one({'_id': ObjectId(subject_id)})
    except:
        return jsonify({'error': 'Invalid subject ID'}), 400
    
    if not subject:
        return jsonify({'error': 'Subject not found'}), 404
    
    # Check if marks exist for this subject
    marks_count = mongo.db.marks.count_documents({'subject_id': ObjectId(subject_id)})
    if marks_count > 0:
        return jsonify({'error': f'Cannot delete: {marks_count} marks records exist for this subject'}), 400
    
    mongo.db.subjects.delete_one({'_id': ObjectId(subject_id)})
    
    AuditService.log_action(
        user_id=current_user_id,
        action='DELETE_SUBJECT',
        entity_type='subject',
        entity_id=subject_id,
        details=f'Deleted subject: {subject["code"]}'
    )
    
    return jsonify({'message': 'Subject deleted successfully'}), 200


@admin_bp.route('/faculty', methods=['GET'])
@jwt_required()
@role_required('admin')
def get_all_faculty():
    """Get all faculty users for assignment dropdown"""
    faculty = list(mongo.db.users.find({'role': 'faculty', 'is_active': True}))
    
    result = []
    for f in faculty:
        result.append({
            '_id': str(f['_id']),
            'username': f['username'],
            'email': f.get('email'),
            'department': f.get('department')
        })
    
    return jsonify({'faculty': result}), 200


# ============================================
# Student Management Endpoints
# ============================================

@admin_bp.route('/students', methods=['GET'])
@jwt_required()
@role_required('admin')
def get_all_students():
    """Get all students"""
    students = list(mongo.db.students.find({}))
    
    result = []
    for student in students:
        result.append({
            '_id': str(student['_id']),
            'roll_number': student['roll_number'],
            'name': student['name'],
            'department': student.get('department'),
            'semester': student.get('semester'),
            'email': student.get('email', '')
        })
    
    return jsonify({'students': result}), 200


@admin_bp.route('/students', methods=['POST'])
@jwt_required()
@role_required('admin')
def create_student():
    """Create a new student"""
    current_user_id = get_jwt_identity()
    data = request.get_json()
    
    roll_number = data.get('roll_number', '').strip()
    name = data.get('name', '').strip()
    department = data.get('department', '').strip()
    semester = data.get('semester')
    email = data.get('email', '').strip()
    
    if not all([roll_number, name, department]):
        return jsonify({'error': 'Roll number, name, and department are required'}), 400
    
    # Check if roll number already exists
    if mongo.db.students.find_one({'roll_number': roll_number}):
        return jsonify({'error': 'Roll number already exists'}), 409
    
    student = {
        'roll_number': roll_number,
        'name': name,
        'department': department,
        'semester': int(semester) if semester else 1,
        'email': email,
        'created_at': datetime.utcnow()
    }
    
    result = mongo.db.students.insert_one(student)
    
    AuditService.log_action(
        user_id=current_user_id,
        action='CREATE_STUDENT',
        entity_type='student',
        entity_id=str(result.inserted_id),
        details=f'Created student: {roll_number} - {name}'
    )
    
    return jsonify({
        'message': 'Student created successfully',
        'student_id': str(result.inserted_id)
    }), 201


@admin_bp.route('/students/<student_id>', methods=['PUT'])
@jwt_required()
@role_required('admin')
def update_student(student_id):
    """Update a student"""
    current_user_id = get_jwt_identity()
    data = request.get_json()
    
    try:
        student = mongo.db.students.find_one({'_id': ObjectId(student_id)})
    except:
        return jsonify({'error': 'Invalid student ID'}), 400
    
    if not student:
        return jsonify({'error': 'Student not found'}), 404
    
    update_data = {'updated_at': datetime.utcnow()}
    
    if data.get('name'):
        update_data['name'] = data['name'].strip()
    if data.get('department'):
        update_data['department'] = data['department'].strip()
    if data.get('semester'):
        update_data['semester'] = int(data['semester'])
    if 'email' in data:
        update_data['email'] = data['email'].strip()
    
    mongo.db.students.update_one(
        {'_id': ObjectId(student_id)},
        {'$set': update_data}
    )
    
    AuditService.log_action(
        user_id=current_user_id,
        action='UPDATE_STUDENT',
        entity_type='student',
        entity_id=student_id,
        details=f'Updated student: {student["roll_number"]}'
    )
    
    return jsonify({'message': 'Student updated successfully'}), 200


@admin_bp.route('/students/<student_id>', methods=['DELETE'])
@jwt_required()
@role_required('admin')
def delete_student(student_id):
    """Delete a student (only if no marks exist)"""
    current_user_id = get_jwt_identity()
    
    try:
        student = mongo.db.students.find_one({'_id': ObjectId(student_id)})
    except:
        return jsonify({'error': 'Invalid student ID'}), 400
    
    if not student:
        return jsonify({'error': 'Student not found'}), 404
    
    # Check if marks exist for this student
    marks_count = mongo.db.marks.count_documents({'student_id': ObjectId(student_id)})
    if marks_count > 0:
        return jsonify({'error': f'Cannot delete: {marks_count} marks records exist for this student'}), 400
    
    mongo.db.students.delete_one({'_id': ObjectId(student_id)})
    
    AuditService.log_action(
        user_id=current_user_id,
        action='DELETE_STUDENT',
        entity_type='student',
        entity_id=student_id,
        details=f'Deleted student: {student["roll_number"]}'
    )
    
    return jsonify({'message': 'Student deleted successfully'}), 200
