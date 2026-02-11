"""
Test Encryption and Digital Signature Services
"""
import sys
sys.path.insert(0, 'backend')

# Need to create Flask app context
from flask import Flask
app = Flask(__name__)
app.config['AES_KEY'] = 'test-key-for-aes-256-encryption!'

with app.app_context():
    from app.services.encryption_service import EncryptionService
    from app.services.signature_service import SignatureService
    
    print("="*70)
    print("ENCRYPTION & SIGNATURE SERVICE TESTS")
    print("="*70)
    
    results = []
    
    # =========================================================================
    # ENCRYPTION TESTS
    # =========================================================================
    print("\n[ENCRYPTION TESTS]")
    print("-"*50)
    
    # Test 1: Basic encryption/decryption
    try:
        original = "Hello, this is sensitive data!"
        encrypted = EncryptionService.encrypt(original)
        decrypted = EncryptionService.decrypt(encrypted)
        passed = original == decrypted
        results.append(f"[{'PASS' if passed else 'FAIL'}] Basic encrypt/decrypt")
        print(f"  Original:  {original}")
        print(f"  Encrypted: {encrypted[:50]}...")
        print(f"  Decrypted: {decrypted}")
    except Exception as e:
        results.append(f"[FAIL] Basic encrypt/decrypt: {e}")
        print(f"  Error: {e}")
    
    # Test 2: Special characters
    try:
        original = "Data with special chars: @#$%^&*(){}[]|\\:\";<>?/"
        encrypted = EncryptionService.encrypt(original)
        decrypted = EncryptionService.decrypt(encrypted)
        passed = original == decrypted
        results.append(f"[{'PASS' if passed else 'FAIL'}] Special characters")
        print(f"\n  Special chars test: {'PASS' if passed else 'FAIL'}")
    except Exception as e:
        results.append(f"[FAIL] Special characters: {e}")
    
    # Test 3: Unicode characters
    try:
        original = "Unicode: 你好世界 🔐 مرحبا"
        encrypted = EncryptionService.encrypt(original)
        decrypted = EncryptionService.decrypt(encrypted)
        passed = original == decrypted
        results.append(f"[{'PASS' if passed else 'FAIL'}] Unicode characters")
        print(f"  Unicode test: {'PASS' if passed else 'FAIL'}")
    except Exception as e:
        results.append(f"[FAIL] Unicode characters: {e}")
    
    # Test 4: Empty string
    try:
        original = ""
        encrypted = EncryptionService.encrypt(original)
        decrypted = EncryptionService.decrypt(encrypted)
        passed = original == decrypted
        results.append(f"[{'PASS' if passed else 'FAIL'}] Empty string")
        print(f"  Empty string test: {'PASS' if passed else 'FAIL'}")
    except Exception as e:
        results.append(f"[FAIL] Empty string: {e}")
    
    # Test 5: Large data
    try:
        original = "A" * 10000
        encrypted = EncryptionService.encrypt(original)
        decrypted = EncryptionService.decrypt(encrypted)
        passed = original == decrypted
        results.append(f"[{'PASS' if passed else 'FAIL'}] Large data (10KB)")
        print(f"  Large data test: {'PASS' if passed else 'FAIL'}")
    except Exception as e:
        results.append(f"[FAIL] Large data: {e}")
    
    # Test 6: Different encryptions produce different ciphertexts (random IV)
    try:
        original = "Same plaintext"
        enc1 = EncryptionService.encrypt(original)
        enc2 = EncryptionService.encrypt(original)
        passed = enc1 != enc2  # Should be different due to random IV
        results.append(f"[{'PASS' if passed else 'FAIL'}] Random IV (different ciphertexts)")
        print(f"  Random IV test: {'PASS' if passed else 'FAIL'}")
    except Exception as e:
        results.append(f"[FAIL] Random IV: {e}")
    
    # =========================================================================
    # HASHING TESTS
    # =========================================================================
    print("\n[HASHING TESTS]")
    print("-"*50)
    
    # Test 7: SHA-256 hashing
    try:
        data = "password123"
        hash1 = EncryptionService.hash_data(data)
        hash2 = EncryptionService.hash_data(data)
        passed = hash1 == hash2 and len(hash1) == 64  # SHA-256 = 64 hex chars
        results.append(f"[{'PASS' if passed else 'FAIL'}] SHA-256 hash consistency")
        print(f"  Hash: {hash1}")
        print(f"  Length: {len(hash1)} chars (expected 64)")
    except Exception as e:
        results.append(f"[FAIL] SHA-256 hash: {e}")
    
    # Test 8: Hash verification
    try:
        data = "verify this data"
        hash_val = EncryptionService.hash_data(data)
        passed = EncryptionService.verify_hash(data, hash_val)
        results.append(f"[{'PASS' if passed else 'FAIL'}] Hash verification")
        print(f"  Hash verification: {'PASS' if passed else 'FAIL'}")
    except Exception as e:
        results.append(f"[FAIL] Hash verification: {e}")
    
    # Test 9: Hash verification fails for different data
    try:
        data = "original data"
        hash_val = EncryptionService.hash_data(data)
        passed = not EncryptionService.verify_hash("modified data", hash_val)
        results.append(f"[{'PASS' if passed else 'FAIL'}] Hash mismatch detection")
        print(f"  Hash mismatch detection: {'PASS' if passed else 'FAIL'}")
    except Exception as e:
        results.append(f"[FAIL] Hash mismatch: {e}")
    
    # =========================================================================
    # DIGITAL SIGNATURE TESTS
    # =========================================================================
    print("\n[DIGITAL SIGNATURE TESTS]")
    print("-"*50)
    
    # Test 10: Key pair generation
    try:
        public_key, private_key = SignatureService.generate_key_pair()
        passed = "BEGIN PUBLIC KEY" in public_key and "BEGIN RSA PRIVATE KEY" in private_key
        results.append(f"[{'PASS' if passed else 'FAIL'}] RSA key pair generation")
        print(f"  Public key length: {len(public_key)} chars")
        print(f"  Private key length: {len(private_key)} chars")
    except Exception as e:
        results.append(f"[FAIL] Key generation: {e}")
        public_key, private_key = None, None
    
    # Test 11: Sign and verify
    if public_key and private_key:
        try:
            data = "Important marks data to sign"
            signature = SignatureService.sign_data(data, private_key)
            verified = SignatureService.verify_signature(data, signature, public_key)
            passed = verified
            results.append(f"[{'PASS' if passed else 'FAIL'}] Sign and verify")
            print(f"  Signature: {signature[:50]}...")
            print(f"  Verified: {verified}")
        except Exception as e:
            results.append(f"[FAIL] Sign/verify: {e}")
    
    # Test 12: Signature fails for modified data
    if public_key and private_key:
        try:
            data = "Original data"
            signature = SignatureService.sign_data(data, private_key)
            verified = SignatureService.verify_signature("Modified data", signature, public_key)
            passed = not verified  # Should NOT verify
            results.append(f"[{'PASS' if passed else 'FAIL'}] Signature tamper detection")
            print(f"  Tamper detection: {'PASS' if passed else 'FAIL'}")
        except Exception as e:
            results.append(f"[FAIL] Tamper detection: {e}")
    
    # Test 13: Invalid signature rejected
    if public_key:
        try:
            data = "Some data"
            verified = SignatureService.verify_signature(data, "invalid_signature", public_key)
            passed = not verified
            results.append(f"[{'PASS' if passed else 'FAIL'}] Invalid signature rejected")
            print(f"  Invalid signature rejected: {'PASS' if passed else 'FAIL'}")
        except Exception as e:
            results.append(f"[FAIL] Invalid signature: {e}")
    
    # Test 14: Create signed approval (workflow test)
    if public_key and private_key:
        try:
            marks_data = '{"student": "CS001", "marks": 85}'
            approval = SignatureService.create_signed_approval(marks_data, private_key, "HOD001")
            passed = all(k in approval for k in ['signature', 'timestamp', 'approver_id', 'signed_data'])
            results.append(f"[{'PASS' if passed else 'FAIL'}] Signed approval creation")
            print(f"  Approval timestamp: {approval.get('timestamp')}")
            print(f"  Approver ID: {approval.get('approver_id')}")
        except Exception as e:
            results.append(f"[FAIL] Signed approval: {e}")
    
    # =========================================================================
    # SUMMARY
    # =========================================================================
    print("\n" + "="*70)
    print("TEST SUMMARY")
    print("="*70)
    
    passed_count = sum(1 for r in results if "[PASS]" in r)
    failed_count = sum(1 for r in results if "[FAIL]" in r)
    
    for r in results:
        print(r)
    
    print("="*70)
    print(f"TOTAL: {len(results)} | PASSED: {passed_count} | FAILED: {failed_count}")
    print("="*70)
