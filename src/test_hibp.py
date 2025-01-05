# tests\test_hibp.py
import pytest
from unittest.mock import patch
from hibp import hibp_validator, ValidationResult

class MockResponse:
    def __init__(self, text, status_code):
        self.text = text
        self.status_code = status_code


@pytest.fixture
def valid_password_response():
    """Mocked response for a password not found in breaches."""
    return MockResponse(text="ABCDE12345:0\nFGHIJ67890:1", status_code=200)


@pytest.fixture
def compromised_password_response():
    """Mocked response for a compromised password."""
    return MockResponse(text="123456:5\nABCDE:100", status_code=200)


@pytest.fixture
def error_response():
    """Mocked response for an error from the API."""
    return MockResponse(text="Internal Server Error", status_code=500)


@patch("main.requests.get")
def test_hibp_validator_safe_password(mock_get, valid_password_response):
    """Test safe password validation."""
    mock_get.return_value = valid_password_response
    result = hibp_validator("safe_password")
    assert isinstance(result, ValidationResult)
    assert result.is_valid is True
    assert result.errors == []


@patch("main.requests.get")
def test_hibp_validator_compromised_password(mock_get, compromised_password_response):
    """Test compromised password validation."""
    mock_get.return_value = compromised_password_response
    result = hibp_validator("compromised_password")
    assert isinstance(result, ValidationResult)
    assert result.is_valid is False
    assert "Password has been compromised in a data breach." in result.errors


@patch("main.requests.get")
def test_hibp_validator_api_error(mock_get, error_response):
    """Test handling of API errors."""
    mock_get.return_value = error_response
    with pytest.raises(RuntimeError) as excinfo:
        hibp_validator("any_password")
    assert "HaveIBeenPwned check failed:" in str(excinfo.value)


@patch("main.requests.get")
def test_hibp_validator_invalid_status(mock_get):
    """Test unexpected API status codes."""
    mock_get.return_value = MockResponse(text="", status_code=404)
    with pytest.raises(RuntimeError) as excinfo:
        hibp_validator("another_password")
    assert "HaveIBeenPwned check failed:" in str(excinfo.value)


def test_generate_sha1():
    """Test SHA-1 generation for a given password."""
    from main import generate_sha1
    password = "test_password"
    expected_hash = "8BB5A5F36E849B3D751B25A4DC74A64F338CE97A"
    assert generate_sha1(password) == expected_hash
