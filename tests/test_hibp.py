# tests\test_hibp.py
# src\test_hibp.py
import pytest
import requests
from unittest.mock import patch, Mock

from hibp import (
    generate_sha1,
    hibp_validator,
    ValidationResult,
    API_URL
)

def test_generate_sha1():
    """Test SHA-1 hash generation"""
    # Test with a known password and its expected hash
    password = "test123"
    expected_hash = "7288EDD0FC3FFCBE93A0CF06E3568E28521687BC"
    assert generate_sha1(password) == expected_hash

    # Test with empty string
    assert generate_sha1("") == "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709"

    # Test with special characters
    password_special = "test@123!£$"
    assert len(generate_sha1(password_special)) == 40
    assert generate_sha1(password_special).isupper()

def test_validation_result_initialization():
    """Test ValidationResult class initialization"""
    # Test valid case
    result = ValidationResult(True, [])
    assert result.is_valid is True
    assert result.errors == []

    # Test invalid case with errors
    errors = ["Error 1", "Error 2"]
    result = ValidationResult(False, errors)
    assert result.is_valid is False
    assert result.errors == errors

@pytest.fixture
def mock_response():
    """Fixture for mocking requests response"""
    def _mock_response(status_code, text):
        response = Mock()
        response.status_code = status_code
        response.text = text
        return response
    return _mock_response

def test_hibp_validator_safe_password(mock_response):
    """Test validation of a safe password"""
    password = "SafePassword123"
    sha1 = generate_sha1(password)
    prefix, suffix = sha1[:5], sha1[5:]
    
    # Mock response with no matches
    mock_resp = mock_response(200, f"1234567890:0\nABCDEF123:1")
    
    with patch('requests.get', return_value=mock_resp) as mock_get:
        result = hibp_validator(password)
        
        mock_get.assert_called_once_with(
            f"{API_URL}{prefix}",
            headers={
                "User-Agent": "NIST-password-validator-py",
                "Add-Padding": "true"
            }
        )
        
        assert result.is_valid is True
        assert result.errors == []

def test_hibp_validator_compromised_password(mock_response):
    """Test validation of a compromised password"""
    password = "CompromisedPass123"
    sha1 = generate_sha1(password)
    prefix, suffix = sha1[:5], sha1[5:]
    
    # Mock response with a match
    mock_resp = mock_response(200, f"{suffix}:123\nABCDEF123:1")
    
    with patch('requests.get', return_value=mock_resp) as mock_get:
        result = hibp_validator(password)
        
        assert result.is_valid is False
        assert result.errors == ["Password has been compromised in a data breach."]

def test_hibp_validator_api_error(mock_response):
    """Test handling of API errors"""
    password = "TestPassword123"
    
    # Mock failed response
    mock_resp = mock_response(500, "Internal Server Error")
    
    with patch('requests.get', return_value=mock_resp) as mock_get:
        with pytest.raises(RuntimeError) as exc_info:
            hibp_validator(password)
        
        assert "HaveIBeenPwned check failed" in str(exc_info.value)

def test_hibp_validator_network_error():
    """Test handling of network errors"""
    password = "TestPassword123"
    
    with patch('requests.get', side_effect=requests.ConnectionError("Network Error")):
        with pytest.raises(RuntimeError) as exc_info:
            hibp_validator(password)
        
        assert "HaveIBeenPwned check failed" in str(exc_info.value)

def test_hibp_validator_malformed_response(mock_response):
    """Test handling of malformed API responses"""
    password = "TestPassword123"
    
    # Mock response with malformed data
    mock_resp = mock_response(200, "Invalid:Format:Extra\nAlsoInvalid")
    
    with patch('requests.get', return_value=mock_resp) as mock_get:
        result = hibp_validator(password)
        assert result.is_valid is True
        assert result.errors == []