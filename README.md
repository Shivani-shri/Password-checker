🔐 Password Security Analyzer — Penetration Testing Tool
A comprehensive Python tool that analyzes password strength, estimates crack time, detects common passwords, demonstrates dictionary attacks, and generates secure alternatives.
📌 Features
Strength Scoring — 0–100 score with detailed breakdown
Entropy Calculation — measures randomness in bits
Crack Time Estimation — calculates brute-force time at 1 billion guesses/sec
Common Password Detection — checks against known breach databases
Dictionary Attack Demo — simulates real-world hash cracking
Hash Generation — MD5, SHA1, SHA256 for each password
Strong Password Generator — generates cryptographically secure alternatives
Detailed Feedback — actionable improvement suggestions
🛠️ Tools & Technologies
Tool
Purpose
Python 3
Core language
hashlib
MD5, SHA1, SHA256 hashing
re
Pattern detection
string / random
Secure password generation
✅ No external libraries — pure Python!
🚀 How to Run
# Clone the repo
git clone https://github.com/YOUR_USERNAME/password-security-analyzer.git
cd password-security-analyzer

# Analyze a password
python password_checker.py MyPassword123

# Run demo mode
python password_checker.py
📸 Sample Output
============================================================
    PASSWORD SECURITY ANALYZER — PENTEST TOOL
============================================================
[+] STRENGTH ANALYSIS:
    Password  : *********** (hidden)
    Length    : 11 characters
    Score     : 35/100
    Strength  : WEAK ❌
    Crack Time: 3 hours (brute force @ 1B/sec)

[+] ISSUES TO FIX:
    → Add uppercase letters (A-Z)
    → Add special characters (!@#$...)

[+] SUGGESTED STRONG PASSWORD:
    Option 1: K#9mP@xL2nQ!rT5w  [VERY STRONG 💪]
🎯 Use Cases
Pre-pentest password policy auditing
Employee security awareness training
CTF password challenges
Security policy compliance checking
📁 Project Structure
password-security-analyzer/
├── password_checker.py    # Main script
└── README.md              # Documentation
📜 Disclaimer
For educational and authorized security testing only. Never test passwords you don't own.
👤 Author
Sivani Sri.N 
Btech cyber forensics and information security| Penetration Testing & Security|
LinkedIn: https://www.linkedin.com/in/sivani-sri-n-b135bb303?utm_source=share_via&utm_content=profile&utm_medium=member_android
