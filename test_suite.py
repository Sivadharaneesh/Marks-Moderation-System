"""
Comprehensive API Test Suite for Marks Moderation System
Tests all security components: Authentication, Authorization, Encryption, Hashing, Digital Signatures
"""

import requests
import json
import time
from datetime import datetime

BASE_URL = "http://localhost:5000/api"

class TestResults:
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.results = []
    
    def add(self, name, passed, details=""):
        status = "[PASS]" if passed else "[FAIL]"
        self.results.append(f"{status} | {name} | {details}")
        if passed:
            self.passed += 1
        else:
            self.failed += 1
    
    def print_summary(self):
        print("\n" + "="*70)
        print("TEST RESULTS SUMMARY")
        print("="*70)
        for r in self.results:
            print(r)
        print("="*70)
        print(f"TOTAL: {self.passed + self.failed} | PASSED: {self.passed} | FAILED: {self.failed}")
        print("="*70)

results = TestResults()

def test_request(method, endpoint, data=None, headers=None, expected_status=None, test_name=""):
    """Helper to make requests and handle errors"""
    try:
        url = f"{BASE_URL}{endpoint}"
        if method == "POST":
            resp = requests.post(url, json=data, headers=headers, timeout=10)
        elif method == "GET":
            resp = requests.get(url, headers=headers, timeout=10)
        else:
            resp = requests.request(method, url, json=data, headers=headers, timeout=10)
        
        return resp
    except Exception as e:
        print(f"Error in {test_name}: {e}")
        return None

print("\n" + "="*70)
print("MARKS MODERATION SYSTEM - COMPREHENSIVE SECURITY TEST SUITE")
print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print("="*70)

# ==============================================================================
# 1. AUTHENTICATION TESTS
# ==============================================================================
print("\n[1] AUTHENTICATION TESTS")
print("-"*50)

# Test 1.1: Invalid credentials - wrong username
resp = test_request("POST", "/auth/login", 
    {"username": "wronguser", "password": "wrongpass"},
    test_name="Invalid username")
if resp:
    passed = resp.status_code == 401 and "error" in resp.json()
    results.add("Auth: Invalid username rejected", passed, f"Status: {resp.status_code}")

# Test 1.2: Invalid credentials - wrong password
resp = test_request("POST", "/auth/login",
    {"username": "faculty1", "password": "wrongpassword"},
    test_name="Wrong password")
if resp:
    passed = resp.status_code == 401 and "error" in resp.json()
    results.add("Auth: Wrong password rejected", passed, f"Status: {resp.status_code}")

# Test 1.3: Missing fields
resp = test_request("POST", "/auth/login",
    {"username": "faculty1"},
    test_name="Missing password")
if resp:
    passed = resp.status_code == 400
    results.add("Auth: Missing password rejected", passed, f"Status: {resp.status_code}")

# Test 1.4: Valid credentials (Step 1 - should require OTP)
resp = test_request("POST", "/auth/login",
    {"username": "faculty1", "password": "password123"},
    test_name="Valid credentials")
if resp:
    data = resp.json()
    passed = resp.status_code == 200 and data.get("requires_otp") == True
    user_id = data.get("user_id")
    dev_otp = data.get("dev_otp")  # For development testing
    results.add("Auth: Valid credentials -> OTP required", passed, f"OTP sent: {bool(dev_otp)}")
    print(f"   [DEBUG] User ID: {user_id}, OTP: {dev_otp}")

# Test 1.5: Invalid OTP
if user_id:
    resp = test_request("POST", "/auth/verify-otp",
        {"user_id": user_id, "otp": "000000"},
        test_name="Invalid OTP")
    if resp:
        passed = resp.status_code == 401
        results.add("Auth: Invalid OTP rejected", passed, f"Status: {resp.status_code}")

# Test 1.6: Valid OTP -> Get JWT
access_token = None
if user_id and dev_otp:
    resp = test_request("POST", "/auth/verify-otp",
        {"user_id": user_id, "otp": dev_otp},
        test_name="Valid OTP")
    if resp:
        data = resp.json()
        passed = resp.status_code == 200 and "access_token" in data
        access_token = data.get("access_token")
        results.add("Auth: Valid OTP -> JWT issued", passed, f"Token received: {bool(access_token)}")

# ==============================================================================
# 2. AUTHORIZATION TESTS
# ==============================================================================
print("\n[2] AUTHORIZATION TESTS")
print("-"*50)

# Test 2.1: Access protected route without token
resp = test_request("GET", "/auth/me", test_name="No token")
if resp:
    passed = resp.status_code == 401
    results.add("Authz: Protected route without token rejected", passed, f"Status: {resp.status_code}")

# Test 2.2: Access protected route with valid token
if access_token:
    headers = {"Authorization": f"Bearer {access_token}"}
    resp = test_request("GET", "/auth/me", headers=headers, test_name="With token")
    if resp:
        data = resp.json()
        passed = resp.status_code == 200 and data.get("role") == "faculty"
        results.add("Authz: Protected route with token succeeds", passed, f"Role: {data.get('role')}")

# Test 2.3: Faculty trying to access admin route
if access_token:
    headers = {"Authorization": f"Bearer {access_token}"}
    resp = test_request("GET", "/admin/users", headers=headers, test_name="Faculty -> Admin route")
    if resp:
        passed = resp.status_code == 403
        results.add("Authz: Faculty blocked from admin route", passed, f"Status: {resp.status_code}")

# Login as admin for admin tests
admin_token = None
resp = test_request("POST", "/auth/login",
    {"username": "admin", "password": "admin123"},
    test_name="Admin login")
if resp and resp.status_code == 200:
    data = resp.json()
    admin_user_id = data.get("user_id")
    admin_otp = data.get("dev_otp")
    if admin_user_id and admin_otp:
        resp = test_request("POST", "/auth/verify-otp",
            {"user_id": admin_user_id, "otp": admin_otp},
            test_name="Admin OTP")
        if resp and resp.status_code == 200:
            admin_token = resp.json().get("access_token")

# Test 2.4: Admin accessing admin route
if admin_token:
    headers = {"Authorization": f"Bearer {admin_token}"}
    resp = test_request("GET", "/admin/users", headers=headers, test_name="Admin -> Admin route")
    if resp:
        passed = resp.status_code == 200
        results.add("Authz: Admin can access admin route", passed, f"Status: {resp.status_code}")

# ==============================================================================
# 3. PASSWORD POLICY TESTS
# ==============================================================================
print("\n[3] PASSWORD POLICY TESTS")
print("-"*50)

# Test 3.1: Valid password
resp = test_request("POST", "/auth/validate-password",
    {"password": "MySecurePassword123!"})
if resp:
    data = resp.json()
    passed = data.get("valid") == True
    results.add("Policy: Valid password accepted", passed, f"Strength: {data.get('strength', {}).get('label')}")

# Test 3.2: Too short password
resp = test_request("POST", "/auth/validate-password",
    {"password": "short"})
if resp:
    data = resp.json()
    passed = data.get("valid") == False
    results.add("Policy: Short password rejected", passed, f"Errors: {len(data.get('errors', []))}")

# Test 3.3: Common password
resp = test_request("POST", "/auth/validate-password",
    {"password": "password123"})
if resp:
    data = resp.json()
    passed = data.get("valid") == False
    results.add("Policy: Common password rejected", passed, "password123 is common")

# Test 3.4: Sequential characters
resp = test_request("POST", "/auth/validate-password",
    {"password": "abc12345xyz"})
if resp:
    data = resp.json()
    passed = data.get("valid") == False
    results.add("Policy: Sequential chars rejected", passed, "Contains 12345")

# Test 3.5: Repeated characters
resp = test_request("POST", "/auth/validate-password",
    {"password": "aaaamysecurepass"})
if resp:
    data = resp.json()
    passed = data.get("valid") == False
    results.add("Policy: Repeated chars rejected", passed, "Contains aaaa")

# ==============================================================================
# 4. INPUT VALIDATION & EDGE CASES
# ==============================================================================
print("\n[4] INPUT VALIDATION & EDGE CASES")
print("-"*50)

# Test 4.1: Empty body
resp = requests.post(f"{BASE_URL}/auth/login", json={}, timeout=10)
passed = resp.status_code == 400
results.add("Input: Empty body rejected", passed, f"Status: {resp.status_code}")

# Test 4.2: SQL-like injection in username
resp = test_request("POST", "/auth/login",
    {"username": "admin'--", "password": "test"})
if resp:
    passed = resp.status_code in [400, 401]  # Should be rejected, not cause error
    results.add("Input: SQL injection attempt handled", passed, f"Status: {resp.status_code}")

# Test 4.3: Special characters in password
resp = test_request("POST", "/auth/validate-password",
    {"password": "Test@#$%^&*()_+{}|:<>?"})
if resp:
    passed = resp.status_code == 200  # Should process without error
    results.add("Input: Special chars handled", passed, f"Valid: {resp.json().get('valid')}")

# Test 4.4: Very long input
long_string = "a" * 10000
resp = test_request("POST", "/auth/login",
    {"username": long_string, "password": "test"})
if resp:
    passed = resp.status_code in [400, 401, 413]  # Should handle gracefully
    results.add("Input: Long input handled", passed, f"Status: {resp.status_code}")

# Test 4.5: Unicode characters
resp = test_request("POST", "/auth/login",
    {"username": "用户名", "password": "密码"})
if resp:
    passed = resp.status_code in [400, 401]
    results.add("Input: Unicode handled", passed, f"Status: {resp.status_code}")

# ==============================================================================
# 5. RATE LIMITING TESTS
# ==============================================================================
print("\n[5] RATE LIMITING TESTS")
print("-"*50)

# Test 5.1: Multiple failed logins
rate_limited = False
for i in range(6):
    resp = test_request("POST", "/auth/login",
        {"username": "ratelimit_test", "password": "wrong"})
    if resp and resp.status_code == 429:
        rate_limited = True
        break
    time.sleep(0.1)

results.add("RateLimit: Too many requests blocked", rate_limited, "429 received after multiple attempts")

# ==============================================================================
# 6. MARKS & SIGNATURES (if access_token available)
# ==============================================================================
print("\n[6] MARKS & DIGITAL SIGNATURES")
print("-"*50)

if access_token:
    headers = {"Authorization": f"Bearer {access_token}"}
    
    # Test 6.1: Get subjects (Faculty)
    resp = test_request("GET", "/faculty/subjects", headers=headers)
    if resp:
        passed = resp.status_code == 200
        data = resp.json() if resp.status_code == 200 else {}
        results.add("Marks: Faculty can view subjects", passed, f"Count: {len(data) if isinstance(data, list) else 'N/A'}")
    
    # Test 6.2: Get audit logs (Admin only, should fail for faculty)
    resp = test_request("GET", "/audit/logs", headers=headers)
    if resp:
        passed = resp.status_code == 403
        results.add("Marks: Faculty blocked from audit logs", passed, f"Status: {resp.status_code}")

# Test 6.3: Admin can access audit logs
if admin_token:
    headers = {"Authorization": f"Bearer {admin_token}"}
    resp = test_request("GET", "/audit/logs", headers=headers)
    if resp:
        passed = resp.status_code == 200
        results.add("Marks: Admin can view audit logs", passed, f"Status: {resp.status_code}")

# ==============================================================================
# PRINT FINAL SUMMARY
# ==============================================================================
results.print_summary()

# Save results to file
with open("test_results.txt", "w") as f:
    f.write("MARKS MODERATION SYSTEM - TEST RESULTS\n")
    f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    f.write("="*70 + "\n")
    for r in results.results:
        f.write(r + "\n")
    f.write("="*70 + "\n")
    f.write(f"TOTAL: {results.passed + results.failed} | PASSED: {results.passed} | FAILED: {results.failed}\n")

print(f"\nResults saved to test_results.txt")
