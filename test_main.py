import unittest
from main import (
    assess_password, calculate_entropy, check_policy,
    classify_strength, check_common_password
)

class PasswordCheckerTests(unittest.TestCase):
    def test_empty_entropy(self):
        self.assertEqual(calculate_entropy(""), 0.0)

    def test_policy_passes_for_compliant_password(self):
        policy = check_policy("Mango!River2026")
        self.assertTrue(all(policy.values()))

    def test_common_password_detected(self):
        self.assertTrue(check_common_password("password123"))

    def test_common_password_case_insensitive(self):
        self.assertTrue(check_common_password("PASSWORD123"))

    def test_common_password_is_weak(self):
        result = assess_password("password123")
        self.assertEqual(result["strength"], "Weak")

    def test_entropy_increases_with_length(self):
        self.assertGreater(calculate_entropy("Abc!123456789"), calculate_entropy("Abc!123"))

    def test_strength_thresholds(self):
        self.assertEqual(classify_strength(35, False), "Weak")
        self.assertEqual(classify_strength(50, False), "Moderate")
        self.assertEqual(classify_strength(70, False), "Strong")
        self.assertEqual(classify_strength(90, False), "Exceptional")

if __name__ == "__main__":
    unittest.main()
