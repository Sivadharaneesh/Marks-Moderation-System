import re


class PasswordPolicy:
    """
    NIST SP 800-63B compliant password policy
    
    Key requirements:
    - Minimum 8 characters
    - Maximum 128 characters
    - No composition rules (uppercase, numbers, symbols not required)
    - Check against common/breached passwords
    """
    
    # Common passwords list (subset for demonstration)
    COMMON_PASSWORDS = {
        'password', 'password123', '123456', '12345678', 'qwerty', 
        'abc123', 'monkey', 'master', 'dragon', 'letmein',
        'login', 'admin', 'welcome', 'password1', 'iloveyou',
        '123456789', '1234567890', 'password!', 'admin123', 'root',
        'toor', 'pass', 'test', 'guest', 'master123', 'changeme',
        'hello', 'shadow', 'sunshine', 'princess', 'football',
        'baseball', 'soccer', 'hockey', 'batman', 'superman',
        'trustno1', 'access', 'starwars', 'passw0rd', 'p@ssword'
    }
    
    MIN_LENGTH = 8
    MAX_LENGTH = 128
    
    @staticmethod
    def validate(password: str) -> dict:
        """
        Validate password against NIST guidelines
        
        Returns:
            dict with 'valid' (bool) and 'errors' (list of error messages)
        """
        errors = []
        
        # Check minimum length
        if len(password) < PasswordPolicy.MIN_LENGTH:
            errors.append(f'Password must be at least {PasswordPolicy.MIN_LENGTH} characters long')
        
        # Check maximum length
        if len(password) > PasswordPolicy.MAX_LENGTH:
            errors.append(f'Password must not exceed {PasswordPolicy.MAX_LENGTH} characters')
        
        # Check against common passwords
        if password.lower() in PasswordPolicy.COMMON_PASSWORDS:
            errors.append('This password is too common. Please choose a different password')
        
        # Check for sequential characters
        if PasswordPolicy._has_sequential_chars(password):
            errors.append('Password should not contain sequential characters (e.g., 12345, abcde)')
        
        # Check for repeated characters
        if PasswordPolicy._has_repeated_chars(password):
            errors.append('Password should not contain more than 3 repeated characters in a row')
        
        return {
            'valid': len(errors) == 0,
            'errors': errors
        }
    
    @staticmethod
    def _has_sequential_chars(password: str, length: int = 4) -> bool:
        """Check if password contains sequential characters"""
        password_lower = password.lower()
        
        # Check numeric sequences
        for i in range(len(password_lower) - length + 1):
            substring = password_lower[i:i + length]
            if substring.isdigit():
                nums = [int(c) for c in substring]
                if all(nums[j] + 1 == nums[j + 1] for j in range(len(nums) - 1)):
                    return True
                if all(nums[j] - 1 == nums[j + 1] for j in range(len(nums) - 1)):
                    return True
        
        # Check alphabetic sequences
        for i in range(len(password_lower) - length + 1):
            substring = password_lower[i:i + length]
            if substring.isalpha():
                chars = [ord(c) for c in substring]
                if all(chars[j] + 1 == chars[j + 1] for j in range(len(chars) - 1)):
                    return True
                if all(chars[j] - 1 == chars[j + 1] for j in range(len(chars) - 1)):
                    return True
        
        return False
    
    @staticmethod
    def _has_repeated_chars(password: str, max_repeat: int = 3) -> bool:
        """Check if password contains too many repeated characters"""
        if len(password) < max_repeat + 1:
            return False
        
        count = 1
        for i in range(1, len(password)):
            if password[i] == password[i - 1]:
                count += 1
                if count > max_repeat:
                    return True
            else:
                count = 1
        
        return False
    
    @staticmethod
    def get_strength(password: str) -> dict:
        """
        Get password strength for UI feedback
        
        Returns:
            dict with 'score' (0-4), 'label', and 'color'
        """
        if not password:
            return {'score': 0, 'label': 'Empty', 'color': '#dc2626'}
        
        score = 0
        
        # Length scoring
        if len(password) >= 8:
            score += 1
        if len(password) >= 12:
            score += 1
        if len(password) >= 16:
            score += 1
        
        # Character variety
        has_lower = bool(re.search(r'[a-z]', password))
        has_upper = bool(re.search(r'[A-Z]', password))
        has_digit = bool(re.search(r'\d', password))
        has_special = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
        
        variety = sum([has_lower, has_upper, has_digit, has_special])
        if variety >= 3:
            score += 1
        
        # Common password penalty
        if password.lower() in PasswordPolicy.COMMON_PASSWORDS:
            score = 0
        
        labels = [
            {'label': 'Very Weak', 'color': '#dc2626'},
            {'label': 'Weak', 'color': '#f97316'},
            {'label': 'Fair', 'color': '#eab308'},
            {'label': 'Strong', 'color': '#22c55e'},
            {'label': 'Very Strong', 'color': '#16a34a'}
        ]
        
        return {
            'score': score,
            **labels[min(score, 4)]
        }
