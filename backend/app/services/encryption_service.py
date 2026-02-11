import base64
import hashlib
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from flask import current_app


class EncryptionService:
    """Service for AES encryption and SHA-256 hashing"""
    
    @staticmethod
    def get_key():
        """Get AES key from config, ensure it's 32 bytes"""
        key = current_app.config.get('AES_KEY', 'default-key-change-this!!!!!!!!')
        # Ensure key is exactly 32 bytes
        return key.encode('utf-8')[:32].ljust(32, b'0')
    
    @staticmethod
    def encrypt(plaintext: str) -> str:
        """
        Encrypt data using AES-256-CBC
        Returns base64 encoded string of IV + ciphertext
        """
        key = EncryptionService.get_key()
        iv = os.urandom(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        
        padded_data = pad(plaintext.encode('utf-8'), AES.block_size)
        ciphertext = cipher.encrypt(padded_data)
        
        # Combine IV and ciphertext, encode as base64
        encrypted = base64.b64encode(iv + ciphertext).decode('utf-8')
        return encrypted
    
    @staticmethod
    def decrypt(encrypted: str) -> str:
        """
        Decrypt AES-256-CBC encrypted data
        Expects base64 encoded string of IV + ciphertext
        """
        key = EncryptionService.get_key()
        encrypted_bytes = base64.b64decode(encrypted)
        
        iv = encrypted_bytes[:16]
        ciphertext = encrypted_bytes[16:]
        
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
        
        return decrypted.decode('utf-8')
    
    @staticmethod
    def hash_data(data: str) -> str:
        """Generate SHA-256 hash of data"""
        return hashlib.sha256(data.encode('utf-8')).hexdigest()
    
    @staticmethod
    def verify_hash(data: str, expected_hash: str) -> bool:
        """Verify data against expected hash"""
        return EncryptionService.hash_data(data) == expected_hash
