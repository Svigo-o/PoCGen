import unittest

from PoCGen.core.models import HTTPMessage
from PoCGen.core.validators import validate_http_message


RAW = (
    "POST /do.cgi HTTP/1.1\r\n"
    "Host: TARGET\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n"
    "Content-Length: 10\r\n"
    "\r\n"
    "cmd=ls -la"
)


class TestHTTPParsing(unittest.TestCase):
    def test_parse_and_validate(self):
        msg = HTTPMessage.parse(RAW)
        self.assertEqual(msg.method, "POST")
        self.assertEqual(msg.path, "/do.cgi")
        self.assertEqual(msg.version, "HTTP/1.1")
        self.assertIn("Host", msg.headers)
        errs = validate_http_message(msg)
        self.assertEqual(errs, [])


if __name__ == "__main__":
    unittest.main()
