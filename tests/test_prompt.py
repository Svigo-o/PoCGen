import unittest

from PoCGen.prompts.templates import build_prompt_command_injection_http


class TestPrompt(unittest.TestCase):
    def test_build_prompt(self):
        msgs = build_prompt_command_injection_http(
            description="Command injection via param 'cmd' in /run",
            code_files=["int main() { /* ... */ }"],
            target="http://192.168.0.1:80",
        )
        self.assertEqual(msgs[0].role, "system")
        self.assertEqual(msgs[1].role, "user")
        self.assertIn("Vulnerability Description:", msgs[1].content)
        self.assertIn("Target Hint:", msgs[1].content)


if __name__ == "__main__":
    unittest.main()
