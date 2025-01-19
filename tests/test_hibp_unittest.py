import unittest
from unittest.mock import patch, Mock
from src.hibp import hibp_validator, generate_sha1, ValidationResult


class TestHIBPValidator(unittest.TestCase):
    def test_generate_sha1(self):
        """Test SHA-1 hash generation"""
        password = "test123"
        expected_hash = "CC03E747A6AFBBCBF8BE7668ACFEBEE5"
        self.assertEqual(generate_sha1(password)[:32], expected_hash)

    @patch("requests.get")
    def test_password_is_compromised(self, mock_get):
        """Test when password is found in breach database"""
        # Mock response for a compromised password
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "0123456789:42\r\nABCDEF:123"
        mock_get.return_value = mock_response

        result = hibp_validator("test_password")

        self.assertFalse(result.is_valid)
        self.assertEqual(
            result.errors, ["Password has been compromised in a data breach."]
        )

    @patch("requests.get")
    def test_password_is_safe(self, mock_get):
        """Test when password is not found in breach database"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "DIFFERENTHASH:42\r\nANOTHERHASH:123"
        mock_get.return_value = mock_response

        result = hibp_validator("safe_password123!")

        self.assertTrue(result.is_valid)
        self.assertEqual(result.errors, [])

    @patch("requests.get")
    def test_api_error(self, mock_get):
        """Test handling of API errors"""
        mock_response = Mock()
        mock_response.status_code = 500
        mock_response.text = "Internal Server Error"
        mock_get.return_value = mock_response

        with self.assertRaises(RuntimeError) as context:
            hibp_validator("test_password")

        self.assertIn("HaveIBeenPwned check failed", str(context.exception))

    @patch("requests.get")
    def test_network_error(self, mock_get):
        """Test handling of network errors"""
        mock_get.side_effect = Exception("Network error")

        with self.assertRaises(RuntimeError) as context:
            hibp_validator("test_password")

        self.assertIn("HaveIBeenPwned check failed", str(context.exception))

    @patch("requests.get")
    def test_empty_response(self, mock_get):
        """Test handling of empty API response"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = ""
        mock_get.return_value = mock_response

        result = hibp_validator("test_password")

        self.assertTrue(result.is_valid)
        self.assertEqual(result.errors, [])

    @patch("requests.get")
    def test_malformed_response(self, mock_get):
        """Test handling of malformed API response"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "malformed:data:format"  # Invalid format
        mock_get.return_value = mock_response

        result = hibp_validator("test_password")

        self.assertTrue(result.is_valid)
        self.assertEqual(result.errors, [])


if __name__ == "__main__":
    unittest.main()
