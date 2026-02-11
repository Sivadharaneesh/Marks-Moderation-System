import base64
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from datetime import datetime


class SignatureService:
    """Service for RSA digital signatures"""
    
    @staticmethod
    def generate_key_pair() -> tuple:
        """
        Generate RSA key pair for digital signatures
        Returns (public_key_pem, private_key_pem)
        """
        key = RSA.generate(2048)
        private_key = key.export_key().decode('utf-8')
        public_key = key.publickey().export_key().decode('utf-8')
        return public_key, private_key
    
    @staticmethod
    def sign_data(data: str, private_key_pem: str) -> str:
        """
        Sign data using RSA private key
        Returns base64 encoded signature
        """
        private_key = RSA.import_key(private_key_pem)
        h = SHA256.new(data.encode('utf-8'))
        signature = pkcs1_15.new(private_key).sign(h)
        return base64.b64encode(signature).decode('utf-8')
    
    @staticmethod
    def verify_signature(data: str, signature: str, public_key_pem: str) -> bool:
        """
        Verify signature using RSA public key
        """
        try:
            public_key = RSA.import_key(public_key_pem)
            h = SHA256.new(data.encode('utf-8'))
            signature_bytes = base64.b64decode(signature)
            pkcs1_15.new(public_key).verify(h, signature_bytes)
            return True
        except (ValueError, TypeError):
            return False
    
    @staticmethod
    def create_signed_approval(marks_data: str, private_key_pem: str, approver_id: str) -> dict:
        """
        Create a signed approval record with timestamp
        """
        timestamp = datetime.utcnow().isoformat()
        data_to_sign = f"{marks_data}|{approver_id}|{timestamp}"
        signature = SignatureService.sign_data(data_to_sign, private_key_pem)
        
        return {
            'signature': signature,
            'timestamp': timestamp,
            'approver_id': approver_id,
            'signed_data': data_to_sign
        }
