from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt
from bson import ObjectId
from datetime import datetime
import json

from app import mongo
from app.services.encryption_service import EncryptionService
from app.services.audit_service import AuditService
from app.middleware.auth_middleware import role_required

faculty_bp = Blueprint('faculty', __name__)


@faculty_bp.route('/subjects', methods=['GET'])
@jwt_required()
@role_required('faculty')
def get_subjects():
    """Get subjects assigned to the current faculty"""
    current_user_id = get_jwt_identity()
    
    subjects = list(mongo.db.subjects.find({
        'faculty_id': ObjectId(current_user_id)
    }))
    
    # Convert ObjectId to string
    for subject in subjects:
        subject['_id'] = str(subject['_id'])
        subject['faculty_id'] = str(subject['faculty_id'])
    
    return jsonify({'subjects': subjects}), 200


@faculty_bp.route('/students/<subject_id>', methods=['GET'])
@jwt_required()
@role_required('faculty')
def get_students(subject_id):
    """Get students enrolled in a subject"""
    current_user_id = get_jwt_identity()
    
    # Verify faculty owns this subject
    subject = mongo.db.subjects.find_one({
        '_id': ObjectId(subject_id),
        'faculty_id': ObjectId(current_user_id)
    })
    
    if not subject:
        return jsonify({'error': 'Subject not found or access denied'}), 404
    
    # Get students in the same department
    students = list(mongo.db.students.find({
        'department': subject['department']
    }))
    
    for student in students:
        student['_id'] = str(student['_id'])
    
    return jsonify({'students': students}), 200


@faculty_bp.route('/marks', methods=['POST'])
@jwt_required()
@role_required('faculty')
def submit_marks():
    """
    Submit internal marks for students
    Marks are encrypted and hashed for security
    """
    current_user_id = get_jwt_identity()
    data = request.get_json()
    
    subject_id = data.get('subject_id')
    marks_data = data.get('marks', [])  # List of {student_id, marks}
    
    if not subject_id or not marks_data:
        return jsonify({'error': 'Subject ID and marks data are required'}), 400
    
    # Verify faculty owns this subject
    subject = mongo.db.subjects.find_one({
        '_id': ObjectId(subject_id),
        'faculty_id': ObjectId(current_user_id)
    })
    
    if not subject:
        return jsonify({'error': 'Subject not found or access denied'}), 404
    
    saved_marks = []
    errors = []
    
    for mark_entry in marks_data:
        student_id = mark_entry.get('student_id')
        marks = mark_entry.get('marks')
        
        # Validate marks range
        try:
            marks_value = float(marks)
            if marks_value < 0 or marks_value > 100:
                errors.append({
                    'student_id': student_id,
                    'error': 'Marks must be between 0 and 100'
                })
                continue
        except (ValueError, TypeError):
            errors.append({
                'student_id': student_id,
                'error': 'Invalid marks value'
            })
            continue
        
        # Check if student exists
        student = mongo.db.students.find_one({'_id': ObjectId(student_id)})
        if not student:
            errors.append({
                'student_id': student_id,
                'error': 'Student not found'
            })
            continue
        
        # Prepare marks data for encryption
        marks_plain = json.dumps({
            'student_id': student_id,
            'subject_id': subject_id,
            'marks': marks_value,
            'faculty_id': current_user_id,
            'timestamp': datetime.utcnow().isoformat()
        })
        
        # Encrypt marks
        encrypted_marks = EncryptionService.encrypt(marks_plain)
        
        # Generate hash for integrity verification
        marks_hash = EncryptionService.hash_data(marks_plain)
        
        # Check if marks already exist for this student/subject
        existing = mongo.db.marks.find_one({
            'student_id': ObjectId(student_id),
            'subject_id': ObjectId(subject_id)
        })
        
        if existing:
            # Check if already locked
            if existing['status'] in ['approved', 'finalized']:
                errors.append({
                    'student_id': student_id,
                    'error': 'Marks are locked and cannot be modified'
                })
                continue
            
            # Update existing marks
            mongo.db.marks.update_one(
                {'_id': existing['_id']},
                {
                    '$set': {
                        'encrypted_marks': encrypted_marks,
                        'marks_hash': marks_hash,
                        'status': 'submitted',
                        'updated_at': datetime.utcnow()
                    }
                }
            )
            saved_marks.append(str(existing['_id']))
        else:
            # Create new marks entry
            mark_doc = {
                'student_id': ObjectId(student_id),
                'subject_id': ObjectId(subject_id),
                'faculty_id': ObjectId(current_user_id),
                'encrypted_marks': encrypted_marks,
                'marks_hash': marks_hash,
                'status': 'submitted',
                'created_at': datetime.utcnow(),
                'updated_at': datetime.utcnow()
            }
            result = mongo.db.marks.insert_one(mark_doc)
            saved_marks.append(str(result.inserted_id))
    
    # Log the action
    AuditService.log_action(
        user_id=current_user_id,
        action='UPLOAD_MARKS',
        entity_type='marks',
        entity_id=subject_id,
        details=f'Uploaded marks for {len(saved_marks)} students'
    )
    
    return jsonify({
        'message': f'Marks submitted for {len(saved_marks)} students',
        'saved': saved_marks,
        'errors': errors
    }), 201


@faculty_bp.route('/marks', methods=['GET'])
@jwt_required()
@role_required('faculty')
def get_marks():
    """Get marks submitted by current faculty"""
    current_user_id = get_jwt_identity()
    subject_id = request.args.get('subject_id')
    
    query = {'faculty_id': ObjectId(current_user_id)}
    if subject_id:
        query['subject_id'] = ObjectId(subject_id)
    
    marks = list(mongo.db.marks.find(query))
    
    result = []
    for mark in marks:
        # Decrypt marks for viewing
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
            
            # Get student details - handle both ObjectId and string
            student_id = mark.get('student_id')
            if isinstance(student_id, str):
                student_id = ObjectId(student_id)
            student = mongo.db.students.find_one({'_id': student_id})
            
            # Get subject details - handle both ObjectId and string
            subj_id = mark.get('subject_id')
            if isinstance(subj_id, str):
                subj_id = ObjectId(subj_id)
            subject = mongo.db.subjects.find_one({'_id': subj_id})
            
            result.append({
                '_id': str(mark['_id']),
                'student': {
                    '_id': str(student['_id']) if student else None,
                    'roll_number': student.get('roll_number') if student else 'Unknown',
                    'name': student.get('name') if student else 'Unknown Student'
                } if student else {'_id': None, 'roll_number': 'N/A', 'name': 'Unknown Student'},
                'subject': {
                    '_id': str(subject['_id']) if subject else None,
                    'code': subject.get('code') if subject else 'N/A',
                    'name': subject.get('name') if subject else 'Unknown Subject'
                } if subject else {'_id': None, 'code': 'N/A', 'name': 'Unknown Subject'},
                'marks': decrypted['marks'],
                'status': mark['status'],
                'integrity_valid': integrity_valid,
                'created_at': mark['created_at'].isoformat() if mark.get('created_at') else None,
                'updated_at': mark['updated_at'].isoformat() if mark.get('updated_at') else None
            })
        except Exception as e:
            current_app.logger.error(f'Error decrypting marks {mark["_id"]}: {str(e)}')
            result.append({
                '_id': str(mark['_id']),
                'student': {'_id': None, 'roll_number': 'Error', 'name': 'Decryption Failed'},
                'subject': {'_id': None, 'code': 'Error', 'name': 'Decryption Failed'},
                'marks': 'N/A',
                'error': 'Failed to decrypt marks',
                'status': mark.get('status', 'unknown'),
                'integrity_valid': False
            })
    
    return jsonify({'marks': result}), 200


@faculty_bp.route('/marks/<mark_id>', methods=['PUT'])
@jwt_required()
@role_required('faculty')
def update_marks(mark_id):
    """Update marks (only if not locked)"""
    current_user_id = get_jwt_identity()
    data = request.get_json()
    new_marks = data.get('marks')
    
    if new_marks is None:
        return jsonify({'error': 'Marks value is required'}), 400
    
    # Validate marks range
    try:
        marks_value = float(new_marks)
        if marks_value < 0 or marks_value > 100:
            return jsonify({'error': 'Marks must be between 0 and 100'}), 400
    except (ValueError, TypeError):
        return jsonify({'error': 'Invalid marks value'}), 400
    
    # Find marks entry
    mark = mongo.db.marks.find_one({
        '_id': ObjectId(mark_id),
        'faculty_id': ObjectId(current_user_id)
    })
    
    if not mark:
        return jsonify({'error': 'Marks not found or access denied'}), 404
    
    # Check if locked
    if mark['status'] in ['approved', 'finalized']:
        return jsonify({'error': 'Marks are locked and cannot be modified'}), 403
    
    # Prepare new marks data
    marks_plain = json.dumps({
        'student_id': str(mark['student_id']),
        'subject_id': str(mark['subject_id']),
        'marks': marks_value,
        'faculty_id': current_user_id,
        'timestamp': datetime.utcnow().isoformat()
    })
    
    # Encrypt and hash
    encrypted_marks = EncryptionService.encrypt(marks_plain)
    marks_hash = EncryptionService.hash_data(marks_plain)
    
    # Update
    mongo.db.marks.update_one(
        {'_id': ObjectId(mark_id)},
        {
            '$set': {
                'encrypted_marks': encrypted_marks,
                'marks_hash': marks_hash,
                'status': 'submitted',
                'updated_at': datetime.utcnow()
            }
        }
    )
    
    AuditService.log_action(
        user_id=current_user_id,
        action='UPDATE_MARKS',
        entity_type='marks',
        entity_id=mark_id,
        details=f'Updated marks to {marks_value}'
    )
    
    return jsonify({'message': 'Marks updated successfully'}), 200
