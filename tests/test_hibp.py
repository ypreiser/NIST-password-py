# tests\test_hibp.py
import unittest
from unittest.mock import patch, MagicMock
from src.hibp import PwnedPasswordChecker
import urllib.error

class TestPwnedPasswordChecker(unittest.TestCase):
    def setUp(self):
        self.checker = PwnedPasswordChecker(timeout=5)

    @patch("urllib.request.urlopen")
    def test_check_password_compromised(self, mock_urlopen):
        """Test when the password is found in the compromised list."""
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.read.return_value = b"ABCDEF123456:12345\n"
        mock_urlopen.return_value.__enter__.return_value = mock_response

        result = self.checker.check_password("password123")
        self.assertTrue(result)

    @patch("urllib.request.urlopen")
    def test_check_password_safe(self, mock_urlopen):
        """Test when the password is not found in the compromised list."""
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.read.return_value = b"1234567890ABCDEF:10"
        mock_urlopen.return_value.__enter__.return_value = mock_response

        result = self.checker.check_password("safe_password")
        self.assertFalse(result)

    @patch("urllib.request.urlopen", side_effect=urllib.error.URLError("Timeout"))
    def test_check_password_timeout(self, mock_urlopen):
        """Test when a timeout occurs during the request."""
        with self.assertRaises(TimeoutError):
            self.checker.check_password("password123")

    @patch("urllib.request.urlopen", side_effect=urllib.error.URLError("Network Error"))
    def test_check_password_network_error(self, mock_urlopen):
        """Test when a network error occurs."""
        with self.assertRaises(ConnectionError):
            self.checker.check_password("password123")

    def test_check_password_empty(self):
        """Test when the password is empty."""
        with self.assertRaises(ValueError):
            self.checker.check_password("")

if __name__ == "__main__":
    unittest.main()
