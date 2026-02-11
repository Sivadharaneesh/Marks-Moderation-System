"""
Test Password Hashing with Salt (bcrypt)
"""
import bcrypt

print("="*70)
print("PASSWORD HASHING WITH SALT (BCRYPT) TESTS")
print("="*70)

results = []

# Test 1: Basic password hashing
try:
    password = "MySecurePassword123!"
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    passed = hashed != password.encode('utf-8')
    results.append(f"[{'PASS' if passed else 'FAIL'}] Password hashing works")
    print(f"\nOriginal:  {password}")
    print(f"Hashed:    {hashed.decode('utf-8')}")
except Exception as e:
    results.append(f"[FAIL] Password hashing: {e}")

# Test 2: Salt is unique each time
try:
    password = "SamePassword"
    hash1 = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    hash2 = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    passed = hash1 != hash2  # Same password = different hashes due to salt
    results.append(f"[{'PASS' if passed else 'FAIL'}] Salt uniqueness (different hashes for same password)")
    print(f"\nHash1: {hash1.decode('utf-8')}")
    print(f"Hash2: {hash2.decode('utf-8')}")
    print(f"Different: {hash1 != hash2}")
except Exception as e:
    results.append(f"[FAIL] Salt uniqueness: {e}")

# Test 3: Password verification works
try:
    password = "VerifyMe123"
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    verified = bcrypt.checkpw(password.encode('utf-8'), hashed)
    passed = verified
    results.append(f"[{'PASS' if passed else 'FAIL'}] Password verification (correct password)")
    print(f"\nCorrect password verification: {verified}")
except Exception as e:
    results.append(f"[FAIL] Password verification: {e}")

# Test 4: Wrong password fails verification
try:
    password = "CorrectPassword"
    wrong_password = "WrongPassword"
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    verified = bcrypt.checkpw(wrong_password.encode('utf-8'), hashed)
    passed = not verified  # Should NOT verify
    results.append(f"[{'PASS' if passed else 'FAIL'}] Wrong password rejected")
    print(f"Wrong password verification: {verified} (expected False)")
except Exception as e:
    results.append(f"[FAIL] Wrong password: {e}")

# Test 5: Hash contains salt prefix
try:
    password = "TestSaltPrefix"
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    hashed_str = hashed.decode('utf-8')
    # bcrypt format: $2b$12$<22-char-salt><31-char-hash>
    passed = hashed_str.startswith('$2') and len(hashed_str) == 60
    results.append(f"[{'PASS' if passed else 'FAIL'}] Bcrypt format with salt")
    print(f"\nHash format: {hashed_str[:7]}... (length: {len(hashed_str)})")
except Exception as e:
    results.append(f"[FAIL] Hash format: {e}")

# Test 6: Cost factor (work factor) test
try:
    password = "CostFactorTest"
    # Default cost factor is 12
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    # Extract cost factor from hash
    cost = int(hashed.decode('utf-8').split('$')[2])
    passed = cost == 12
    results.append(f"[{'PASS' if passed else 'FAIL'}] Cost factor = 12")
    print(f"Cost factor: {cost}")
except Exception as e:
    results.append(f"[FAIL] Cost factor: {e}")

# Test 7: Special characters in password
try:
    password = "P@$$w0rd!#$%^&*()_+{}[]|:;<>?/"
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    verified = bcrypt.checkpw(password.encode('utf-8'), hashed)
    passed = verified
    results.append(f"[{'PASS' if passed else 'FAIL'}] Special characters handled")
    print(f"\nSpecial char password verified: {verified}")
except Exception as e:
    results.append(f"[FAIL] Special chars: {e}")

# Test 8: Unicode password
try:
    password = "密码Password123"
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    verified = bcrypt.checkpw(password.encode('utf-8'), hashed)
    passed = verified
    results.append(f"[{'PASS' if passed else 'FAIL'}] Unicode password handled")
    print(f"Unicode password verified: {verified}")
except Exception as e:
    results.append(f"[FAIL] Unicode: {e}")

print("\n" + "="*70)
print("SUMMARY")
print("="*70)

passed_count = sum(1 for r in results if "[PASS]" in r)
failed_count = sum(1 for r in results if "[FAIL]" in r)

for r in results:
    print(r)

print("="*70)
print(f"TOTAL: {len(results)} | PASSED: {passed_count} | FAILED: {failed_count}")
print("="*70)
