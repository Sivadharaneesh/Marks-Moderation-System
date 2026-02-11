"""
Database seed script to create demo data
Run this script to populate the database with sample users, subjects, and students
"""
from pymongo import MongoClient
from datetime import datetime
import bcrypt
from Crypto.PublicKey import RSA

# Connect to MongoDB
client = MongoClient('mongodb://localhost:27017/')
db = client['marks_system']


def generate_key_pair():
    """Generate RSA key pair"""
    key = RSA.generate(2048)
    private_key = key.export_key().decode('utf-8')
    public_key = key.publickey().export_key().decode('utf-8')
    return public_key, private_key


def hash_password(password):
    """Hash password with bcrypt"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')


def seed_database():
    print("🌱 Seeding database...")
    
    # Clear existing data
    db.users.delete_many({})
    db.subjects.delete_many({})
    db.students.delete_many({})
    db.marks.delete_many({})
    db.moderations.delete_many({})
    db.final_approvals.delete_many({})
    db.audit_logs.delete_many({})
    db.login_attempts.delete_many({})
    db.otps.delete_many({})
    print("✓ Cleared existing data")
    
    # Create users
    users = []
    
    # Faculty users
    for i, (username, dept) in enumerate([
        ('faculty1', 'Computer Science'),
        ('faculty2', 'Computer Science'),
        ('faculty3', 'Electronics')
    ]):
        pub_key, priv_key = generate_key_pair()
        user = {
            'username': username,
            'email': f'{username}@university.edu',
            'password_hash': hash_password('password123'),
            'role': 'faculty',
            'department': dept,
            'public_key': pub_key,
            'private_key_encrypted': priv_key,
            'is_active': True,
            'created_at': datetime.utcnow()
        }
        result = db.users.insert_one(user)
        users.append({'_id': result.inserted_id, **user})
        print(f"✓ Created faculty: {username}")
    
    # HOD users
    for username, dept in [('hod_cs', 'Computer Science'), ('hod_ec', 'Electronics')]:
        pub_key, priv_key = generate_key_pair()
        user = {
            'username': username,
            'email': f'{username}@university.edu',
            'password_hash': hash_password('password123'),
            'role': 'hod',
            'department': dept,
            'public_key': pub_key,
            'private_key_encrypted': priv_key,
            'is_active': True,
            'created_at': datetime.utcnow()
        }
        result = db.users.insert_one(user)
        users.append({'_id': result.inserted_id, **user})
        print(f"✓ Created HOD: {username}")
    
    # Admin user
    pub_key, priv_key = generate_key_pair()
    admin = {
        'username': 'admin',
        'email': 'admin@university.edu',
        'password_hash': hash_password('admin123'),
        'role': 'admin',
        'department': 'Administration',
        'public_key': pub_key,
        'private_key_encrypted': priv_key,
        'is_active': True,
        'created_at': datetime.utcnow()
    }
    db.users.insert_one(admin)
    print("✓ Created admin: admin")
    
    # Create subjects
    faculty1 = next(u for u in users if u['username'] == 'faculty1')
    faculty2 = next(u for u in users if u['username'] == 'faculty2')
    faculty3 = next(u for u in users if u['username'] == 'faculty3')
    
    subjects = [
        {'code': 'CS101', 'name': 'Data Structures', 'faculty_id': faculty1['_id'], 'department': 'Computer Science'},
        {'code': 'CS102', 'name': 'Algorithms', 'faculty_id': faculty1['_id'], 'department': 'Computer Science'},
        {'code': 'CS201', 'name': 'Database Systems', 'faculty_id': faculty2['_id'], 'department': 'Computer Science'},
        {'code': 'EC101', 'name': 'Digital Electronics', 'faculty_id': faculty3['_id'], 'department': 'Electronics'},
    ]
    
    for subject in subjects:
        db.subjects.insert_one(subject)
        print(f"✓ Created subject: {subject['code']}")
    
    # Create students
    students_data = [
        # CS Students
        {'roll_number': 'CS001', 'name': 'Alice Johnson', 'department': 'Computer Science', 'semester': 4},
        {'roll_number': 'CS002', 'name': 'Bob Smith', 'department': 'Computer Science', 'semester': 4},
        {'roll_number': 'CS003', 'name': 'Charlie Brown', 'department': 'Computer Science', 'semester': 4},
        {'roll_number': 'CS004', 'name': 'Diana Ross', 'department': 'Computer Science', 'semester': 4},
        {'roll_number': 'CS005', 'name': 'Edward Lee', 'department': 'Computer Science', 'semester': 4},
        # EC Students
        {'roll_number': 'EC001', 'name': 'Frank White', 'department': 'Electronics', 'semester': 4},
        {'roll_number': 'EC002', 'name': 'Grace Kim', 'department': 'Electronics', 'semester': 4},
        {'roll_number': 'EC003', 'name': 'Henry Chen', 'department': 'Electronics', 'semester': 4},
    ]
    
    for student in students_data:
        db.students.insert_one(student)
        print(f"✓ Created student: {student['roll_number']}")
    
    print("\n" + "="*50)
    print("🎉 Database seeded successfully!")
    print("="*50)
    print("\nDemo Credentials:")
    print("-"*30)
    print("Faculty:  faculty1 / password123")
    print("          faculty2 / password123")
    print("HOD:      hod_cs / password123")
    print("Admin:    admin / admin123")
    print("-"*30)
    print("\nNote: OTP will be shown in console if email is not configured.")


if __name__ == '__main__':
    seed_database()
