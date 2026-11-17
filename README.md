# Password Strength Checker

A Python command-line project that evaluates password policy compliance and estimates entropy.

## Requirements
- Python 3.10 or later (tested design target: Python 3.12)
- No third-party packages required

## Run on Windows PowerShell
```powershell
cd password_strength_checker
python main.py
```

## Run tests
```powershell
python -m unittest discover -s tests -v
```

## Features
- Checks length, uppercase, lowercase, digits and special characters.
- Estimates entropy in bits using an approximate character pool.
- Checks exact matches against a small built-in list of common passwords.
- Classifies strength as Weak, Moderate, Strong or Exceptional.
- Displays recommendations.
- Uses `getpass` so the password is not echoed in the terminal.

## Important limitations
- Entropy is a simplified estimate. Real password predictability depends on patterns, reused passwords, personal information and attacker strategy.
- The built-in common-password list is intentionally small and is not a comprehensive breach database.
- No password is sent to a server or checked against an online breach service.
- Do not use a real password in screenshots, demonstrations, or source control. Use a made-up test password.
