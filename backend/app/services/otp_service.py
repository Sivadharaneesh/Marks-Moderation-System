import random
import hashlib
from datetime import datetime, timedelta
from flask import current_app
from flask_mail import Message
from app import mongo, mail


class OTPService:
    """Service for OTP generation, storage, and verification"""
    
    @staticmethod
    def generate_otp() -> str:
        """Generate a 6-digit OTP"""
        return str(random.randint(100000, 999999))
    
    @staticmethod
    def hash_otp(otp: str) -> str:
        """Hash OTP for secure storage"""
        return hashlib.sha256(otp.encode('utf-8')).hexdigest()
    
    @staticmethod
    def create_otp(user_id: str) -> str:
        """
        Create and store OTP for user
        Returns the plain OTP (to be sent via email)
        """
        # Invalidate any existing OTPs for this user
        mongo.db.otps.update_many(
            {'user_id': user_id, 'is_used': False},
            {'$set': {'is_used': True}}
        )
        
        otp = OTPService.generate_otp()
        expiry_minutes = current_app.config.get('OTP_EXPIRY_MINUTES', 5)
        
        otp_doc = {
            'user_id': user_id,
            'otp_hash': OTPService.hash_otp(otp),
            'expires_at': datetime.utcnow() + timedelta(minutes=expiry_minutes),
            'is_used': False,
            'created_at': datetime.utcnow()
        }
        
        mongo.db.otps.insert_one(otp_doc)
        return otp
    
    @staticmethod
    def verify_otp(user_id: str, otp: str) -> bool:
        """Verify OTP for user"""
        otp_hash = OTPService.hash_otp(otp)
        
        otp_doc = mongo.db.otps.find_one({
            'user_id': user_id,
            'otp_hash': otp_hash,
            'is_used': False,
            'expires_at': {'$gt': datetime.utcnow()}
        })
        
        if otp_doc:
            # Mark OTP as used
            mongo.db.otps.update_one(
                {'_id': otp_doc['_id']},
                {'$set': {'is_used': True}}
            )
            return True
        
        return False
    
    @staticmethod
    def send_otp_email(email: str, otp: str, username: str, role: str = 'faculty') -> bool:
        """
        Send OTP via email
        Routes email based on role:
        - admin: sivadharaneesh017@gmail.com
        - others (faculty, hod): sivadharaneesh4@gmail.com
        """
        try:
            # Route email based on role
            if role == 'admin':
                recipient_email = 'sivadharaneesh017@gmail.com'
            else:
                recipient_email = 'sivadharaneesh4@gmail.com'
            
            msg = Message(
                subject='Your OTP for Marks System Login',
                recipients=[recipient_email],
                html=f'''
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <h2 style="color: #2563eb;">Marks Moderation System</h2>
                    <p>Hello <strong>{username}</strong>,</p>
                    <p>Your One-Time Password (OTP) for login is:</p>
                    <div style="background: #f3f4f6; padding: 20px; text-align: center; border-radius: 8px; margin: 20px 0;">
                        <h1 style="color: #1f2937; letter-spacing: 8px; margin: 0;">{otp}</h1>
                    </div>
                    <p style="color: #6b7280;">This OTP is valid for 5 minutes. Do not share it with anyone.</p>
                    <p style="color: #6b7280;">If you did not request this OTP, please ignore this email.</p>
                    <hr style="border: none; border-top: 1px solid #e5e7eb; margin: 20px 0;">
                    <p style="color: #9ca3af; font-size: 12px;">This is an automated message. Please do not reply.</p>
                </div>
                '''
            )
            mail.send(msg)
            return True
        except Exception as e:
            current_app.logger.error(f'Failed to send OTP email: {str(e)}')
            return False
