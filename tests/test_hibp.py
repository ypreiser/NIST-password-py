import unittest
from unittest.mock import patch, MagicMock
from urllib.error import URLError
from socket import timeout
from src.hibp import HIBPChecker

class TestHIBPChecker(unittest.TestCase):
    def test_empty_password(self):
        with self.assertRaises(ValueError):
            HIBPChecker.check_password("")

@patch("urllib.request.urlopen")
def test_compromised_password(self, mock_urlopen):
    # Mock response for a compromised password
    mock_response = MagicMock()
    mock_response.status = 200
    mock_response.reason = "OK"
    mock_response.read.return_value = b"ABCDEF12345:10\n1234567890:20\n"
    mock_urlopen.return_value = mock_response

    result = HIBPChecker.check_password("password123")
    self.assertTrue(result)

@patch("urllib.request.urlopen")
def test_safe_password(self, mock_urlopen):
    # Mock response for a safe password
    mock_response = MagicMock()
    mock_response.status = 200
    mock_response.reason = "OK"
    mock_response.read.return_value = b"FFFFF:1\nAAAAA:2\n"
    mock_urlopen.return_value = mock_response

    result = HIBPChecker.check_password("password123")
    self.assertFalse(result)

@patch("urllib.request.urlopen")
def test_api_error(self, mock_urlopen):
    # Mock API error response
    mock_response = MagicMock()
    mock_response.status = 500
    mock_response.reason = "Internal Server Error"
    mock_urlopen.return_value = mock_response

    with self.assertRaises(ConnectionError) as ctx:
        HIBPChecker.check_password("password123")
    self.assertIn("API error: 500 Internal Server Error", str(ctx.exception))


    @patch("urllib.request.urlopen")
    def test_timeout(self, mock_urlopen):
        # Mock timeout
        mock_urlopen.side_effect = timeout("Request timed out")

        with self.assertRaises(TimeoutError) as ctx:
            HIBPChecker.check_password("password123")
        self.assertIn("Request timed out", str(ctx.exception))

    @patch("urllib.request.urlopen")
    def test_network_error(self, mock_urlopen):
        # Mock network error
        mock_urlopen.side_effect = URLError("No internet connection")

        with self.assertRaises(ConnectionError) as ctx:
            HIBPChecker.check_password("password123")
        self.assertIn("Network error", str(ctx.exception))

    @patch("urllib.request.urlopen")
    def test_unexpected_error(self, mock_urlopen):
        # Mock an unexpected error
        mock_urlopen.side_effect = Exception("Something went wrong")

        with self.assertRaises(ConnectionError) as ctx:
            HIBPChecker.check_password("password123")
        self.assertIn("Unexpected error", str(ctx.exception))

    @patch("urllib.request.urlopen")
    def test_no_response_body(self, mock_urlopen):
    # Mock empty API response
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.reason = "OK"
        mock_response.read.return_value = b""
        mock_urlopen.return_value = mock_response

    result = HIBPChecker.check_password("password123")
    self.assertFalse(result)

@patch("urllib.request.urlopen")
def test_malformed_response(self, mock_urlopen):
    # Mock malformed API response
    mock_response = MagicMock()
    mock_response.status = 200
    mock_response.reason = "OK"
    mock_response.read.return_value = b"InvalidFormatHere"
    mock_urlopen.return_value = mock_response

    result = HIBPChecker.check_password("password123")
    self.assertFalse(result)


if __name__ == "__main__":
    unittest.main()
