"""
Password Strength Checker
A command-line password assessment tool.

Note: Entropy is an estimate based on character-pool size and password length.
It is not a guarantee of real-world crack time or security.
"""
from getpass import getpass
import math
import re

COMMON_PASSWORDS = {
    "password", "password123", "123456", "123456789", "12345678",
    "qwerty", "qwerty123", "admin", "admin123", "letmein",
    "welcome", "iloveyou", "abc123", "111111", "000000",
    "passw0rd", "india123", "football", "monkey", "dragon",
}

def calculate_entropy(password: str) -> float:
    """Estimate entropy in bits using the size of the observed character pool."""
    if not password:
        return 0.0

    pool_size = 0
    if re.search(r"[a-z]", password):
        pool_size += 26
    if re.search(r"[A-Z]", password):
        pool_size += 26
    if re.search(r"\d", password):
        pool_size += 10
    if re.search(r"[^A-Za-z0-9]", password):
        pool_size +=  symbols_count()

    if pool_size == 0:
        return 0.0
    return len(password) * math.log2(pool_size)

def symbols_count() -> int:
    # Approximate number of commonly usable printable symbols.
    return 32

def check_policy(password: str) -> dict:
    """Return individual password policy checks."""
    return {
        "At least 12 characters": len(password) >= 12,
        "Contains lowercase letter": bool(re.search(r"[a-z]", password)),
        "Contains uppercase letter": bool(re.search(r"[A-Z]", password)),
        "Contains a digit": bool(re.search(r"\d", password)),
        "Contains a special character": bool(re.search(r"[^A-Za-z0-9]", password)),
    }

def check_common_password(password: str) -> bool:
    """Check exact match against a small built-in common-password list."""
    return password.casefold() in COMMON_PASSWORDS

def classify_strength(entropy: float, is_common: bool) -> str:
    if is_common or entropy < 40:
        return "Weak"
    if entropy < 60:
        return "Moderate"
    if entropy < 80:
        return "Strong"
    return "Exceptional"

def get_feedback(policy: dict, is_common: bool, strength: str) -> list[str]:
    suggestions = []
    if is_common:
        suggestions.append("This is a commonly used password. Choose a unique one.")
    for rule, passed in policy.items():
        if not passed:
            suggestions.append(f"Improve your password: {rule.lower()}.")
    if not suggestions and strength in ("Strong", "Exceptional"):
        suggestions.append("Good work. Keep this password unique and do not reuse it.")
    return suggestions

def assess_password(password: str) -> dict:
    policy = check_policy(password)
    common = check_common_password(password)
    entropy = calculate_entropy(password)
    strength = classify_strength(entropy, common)
    return {
        "length": len(password),
        "entropy": entropy,
        "policy": policy,
        "common": common,
        "strength": strength,
        "feedback": get_feedback(policy, common, strength),
    }

def display_report(result: dict) -> None:
    print("\n" + "=" * 48)
    print("           PASSWORD SECURITY REPORT")
    print("=" * 48)
    print(f"Password length : {result['length']} characters")
    print(f"Estimated entropy: {result['entropy']:.2f} bits")
    print(f"Strength        : {result['strength']}")
    print("\nPOLICY CHECKS")
    for rule, passed in result["policy"].items():
        print(f"  [{'PASS' if passed else 'FAIL'}] {rule}")

    print("\nCOMMON-PASSWORD CHECK")
    if result["common"]:
        print("  [WARNING] Found in the built-in common-password list.")
    else:
        print("  [PASS] No exact match in the built-in common-password list.")

    print("\nRECOMMENDATIONS")
    for item in result["feedback"]:
        print(f"  - {item}")
    print("\nNote: This is an educational estimate, not a breach-database lookup.")
    print("Your password is assessed locally and is not sent over the network.")
    print("=" * 48)

def main() -> None:
    print("=" * 48)
    print("             PASSWORD STRENGTH CHECKER")
    print("=" * 48)
    print("Enter a password to evaluate. Input is hidden.")
    print("Press Ctrl+C to exit.\n")

    try:
        password = input("Enter password: ")
        if not password:
            print("No password entered. Please run the program again.")
            return
        display_report(assess_password(password))
    except KeyboardInterrupt:
        print("\nExiting Password Strength Checker.")

if __name__ == "__main__":
    main()
