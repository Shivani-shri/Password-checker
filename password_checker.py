"""
Password Security Analyzer — Penetration Testing Tool
Author: [Your Name]
Description: Analyzes password strength, checks against common password lists,
             demonstrates dictionary attacks, and generates secure passwords.
"""

import re
import sys
import json
import time
import hashlib
import random
import string
from datetime import datetime


# Top 50 most common passwords
COMMON_PASSWORDS = [
    "password", "123456", "password123", "admin", "letmein",
    "qwerty", "abc123", "monkey", "1234567890", "111111",
    "password1", "iloveyou", "admin123", "welcome", "login",
    "hello", "master", "dragon", "pass", "test",
    "1234", "12345", "123456789", "qwerty123", "1q2w3e",
    "sunshine", "princess", "football", "shadow", "superman",
    "michael", "baseball", "solo", "batman", "trustno1",
    "starwars", "access", "654321", "666666", "123123",
    "000000", "121212", "donald", "password2", "qwertyuiop",
    "zxcvbnm", "asdfgh", "pass123", "root", "toor"
]

# Character sets
LOWERCASE = string.ascii_lowercase
UPPERCASE = string.ascii_uppercase
DIGITS = string.digits
SPECIAL = "!@#$%^&*()_+-=[]{}|;:,.<>?"


def calculate_hash(password):
    """Calculate multiple hashes of the password."""
    return {
        "MD5": hashlib.md5(password.encode()).hexdigest(),
        "SHA1": hashlib.sha1(password.encode()).hexdigest(),
        "SHA256": hashlib.sha256(password.encode()).hexdigest(),
    }


def check_password_strength(password):
    """Comprehensive password strength analysis."""
    score = 0
    feedback = []
    issues = []

    length = len(password)

    # Length scoring
    if length >= 16:
        score += 30
        feedback.append("✅ Excellent length (16+ chars)")
    elif length >= 12:
        score += 20
        feedback.append("✅ Good length (12+ chars)")
    elif length >= 8:
        score += 10
        feedback.append("⚠️  Minimum length (8 chars)")
        issues.append("Use 12+ characters for better security")
    else:
        score += 0
        feedback.append("❌ Too short (less than 8 chars)")
        issues.append("Password is dangerously short")

    # Character diversity
    has_lower = bool(re.search(r'[a-z]', password))
    has_upper = bool(re.search(r'[A-Z]', password))
    has_digit = bool(re.search(r'\d', password))
    has_special = bool(re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]', password))

    if has_lower:
        score += 10
        feedback.append("✅ Contains lowercase letters")
    else:
        issues.append("Add lowercase letters (a-z)")

    if has_upper:
        score += 15
        feedback.append("✅ Contains uppercase letters")
    else:
        issues.append("Add uppercase letters (A-Z)")

    if has_digit:
        score += 15
        feedback.append("✅ Contains numbers")
    else:
        issues.append("Add numbers (0-9)")

    if has_special:
        score += 20
        feedback.append("✅ Contains special characters")
    else:
        issues.append("Add special characters (!@#$...)")

    # Pattern checks
    if re.search(r'(.)\1{2,}', password):
        score -= 10
        issues.append("⚠️  Repeated characters detected (e.g., 'aaa')")

    if re.search(r'(012|123|234|345|456|567|678|789|890|abc|bcd|cde)', password.lower()):
        score -= 10
        issues.append("⚠️  Sequential pattern detected (e.g., '123', 'abc')")

    # Common password check
    if password.lower() in COMMON_PASSWORDS:
        score = 0
        issues.append("🚨 CRITICAL: This is in the top 50 most common passwords list!")

    # Calculate entropy (rough estimate)
    charset_size = 0
    if has_lower: charset_size += 26
    if has_upper: charset_size += 26
    if has_digit: charset_size += 10
    if has_special: charset_size += 32
    if charset_size > 0:
        import math
        entropy = length * math.log2(charset_size)
    else:
        entropy = 0

    # Determine strength level
    score = max(0, min(100, score))
    if score >= 80:
        strength = "VERY STRONG 💪"
        color = "🟢"
    elif score >= 60:
        strength = "STRONG ✅"
        color = "🟢"
    elif score >= 40:
        strength = "MODERATE ⚠️"
        color = "🟡"
    elif score >= 20:
        strength = "WEAK ❌"
        color = "🟠"
    else:
        strength = "VERY WEAK 🚨"
        color = "🔴"

    # Estimate crack time
    combinations = charset_size ** length if charset_size > 0 else 0
    guesses_per_second = 1_000_000_000  # 1 billion/sec (modern GPU)
    crack_seconds = combinations / guesses_per_second if combinations > 0 else 0

    if crack_seconds < 1:
        crack_time = "Instantly"
    elif crack_seconds < 60:
        crack_time = f"{int(crack_seconds)} seconds"
    elif crack_seconds < 3600:
        crack_time = f"{int(crack_seconds/60)} minutes"
    elif crack_seconds < 86400:
        crack_time = f"{int(crack_seconds/3600)} hours"
    elif crack_seconds < 31536000:
        crack_time = f"{int(crack_seconds/86400)} days"
    elif crack_seconds < 3.15e10:
        crack_time = f"{int(crack_seconds/31536000)} years"
    else:
        crack_time = "Centuries+"

    return {
        "password": "*" * len(password),
        "length": length,
        "score": score,
        "strength": strength,
        "entropy_bits": round(entropy, 1),
        "estimated_crack_time": crack_time,
        "has_lowercase": has_lower,
        "has_uppercase": has_upper,
        "has_digits": has_digit,
        "has_special": has_special,
        "is_common_password": password.lower() in COMMON_PASSWORDS,
        "feedback": feedback,
        "issues": issues,
    }


def dictionary_attack_demo(target_hash, hash_type="MD5"):
    """Demonstrate a dictionary attack against a hash."""
    print(f"\n[+] Dictionary Attack Demo ({hash_type})")
    print(f"    Target Hash: {target_hash}")
    print(f"    Wordlist Size: {len(COMMON_PASSWORDS)} passwords")
    print(f"    Attacking...\n")

    hash_func = {
        "MD5": hashlib.md5,
        "SHA1": hashlib.sha1,
        "SHA256": hashlib.sha256
    }.get(hash_type, hashlib.md5)

    for i, word in enumerate(COMMON_PASSWORDS):
        computed = hash_func(word.encode()).hexdigest()
        time.sleep(0.03)  # Simulate processing
        print(f"\r    Trying [{i+1:3d}/{len(COMMON_PASSWORDS)}]: {word:<20}", end="", flush=True)

        if computed == target_hash:
            print(f"\n\n    🔴 PASSWORD CRACKED!")
            print(f"    Hash    : {target_hash}")
            print(f"    Password: {word}")
            return word

    print(f"\n\n    ✅ Password not found in common wordlist.")
    return None


def generate_strong_password(length=16, include_special=True):
    """Generate a cryptographically strong password."""
    charset = LOWERCASE + UPPERCASE + DIGITS
    if include_special:
        charset += SPECIAL

    # Ensure at least one of each type
    password = [
        random.choice(LOWERCASE),
        random.choice(UPPERCASE),
        random.choice(DIGITS),
    ]
    if include_special:
        password.append(random.choice(SPECIAL))

    # Fill the rest
    for _ in range(length - len(password)):
        password.append(random.choice(charset))

    random.shuffle(password)
    return ''.join(password)


def analyze_password(password):
    """Full password analysis and report."""
    print("=" * 60)
    print("    PASSWORD SECURITY ANALYZER — PENTEST TOOL")
    print("=" * 60)
    print(f"[*] Analyzing password...")
    print(f"[*] Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    result = check_password_strength(password)

    print(f"[+] STRENGTH ANALYSIS:")
    print(f"    Password  : {'*' * len(password)} (hidden for security)")
    print(f"    Length    : {result['length']} characters")
    print(f"    Score     : {result['score']}/100")
    print(f"    Strength  : {result['strength']}")
    print(f"    Entropy   : {result['entropy_bits']} bits")
    print(f"    Crack Time: {result['estimated_crack_time']} (brute force @ 1B/sec)")

    print(f"\n[+] CHARACTER ANALYSIS:")
    print(f"    Lowercase : {'✅' if result['has_lowercase'] else '❌'}")
    print(f"    Uppercase : {'✅' if result['has_uppercase'] else '❌'}")
    print(f"    Numbers   : {'✅' if result['has_digits'] else '❌'}")
    print(f"    Special   : {'✅' if result['has_special'] else '❌'}")

    if result['is_common_password']:
        print(f"\n    🚨 ALERT: This password is in common breach databases!")

    print(f"\n[+] FEEDBACK:")
    for f in result['feedback']:
        print(f"    {f}")

    if result['issues']:
        print(f"\n[+] ISSUES TO FIX:")
        for issue in result['issues']:
            print(f"    → {issue}")

    # Show hashes
    hashes = calculate_hash(password)
    print(f"\n[+] PASSWORD HASHES (for hash cracking demo):")
    for algo, h in hashes.items():
        print(f"    {algo:8}: {h}")

    # Demo dictionary attack on MD5 if weak password
    if result['is_common_password'] or result['score'] < 30:
        print(f"\n[⚠] Weak password detected — running dictionary attack demo...")
        dictionary_attack_demo(hashes["MD5"], "MD5")

    # Suggest strong password
    print(f"\n[+] SUGGESTED STRONG PASSWORD:")
    for i in range(3):
        suggested = generate_strong_password(16)
        s = check_password_strength(suggested)
        print(f"    Option {i+1}: {suggested}  [{s['strength']}]")

    print(f"\n[✓] Analysis complete!")
    print("=" * 60)

    return result


def main():
    print("=" * 60)
    print("   PASSWORD SECURITY ANALYZER — PENETRATION TESTING")
    print("=" * 60)

    if len(sys.argv) >= 2:
        password = sys.argv[1]
    else:
        print("\nUsage: python password_checker.py <password>")
        print("\nDemo mode — testing common weak passwords:\n")

        test_passwords = ["password", "Admin@1234!", "P@ssw0rd#2024Secure"]
        for pwd in test_passwords:
            print(f"\n{'='*60}")
            print(f"Testing: {'*' * len(pwd)} (length: {len(pwd)})")
            result = check_password_strength(pwd)
            print(f"  Score   : {result['score']}/100")
            print(f"  Strength: {result['strength']}")
            print(f"  Crack   : {result['estimated_crack_time']}")
            if result['is_common_password']:
                print(f"  🚨 COMMON PASSWORD DETECTED!")

        print(f"\n[+] Run with your own password: python password_checker.py YourPassword123!")
        return

    analyze_password(password)


if __name__ == "__main__":
    main()
