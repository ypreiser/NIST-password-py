# tests\test_blocklist_validator.py
import pytest
from blocklist_validator import blocklist_validator
from unittest.mock import patch

# Test setup
standard_blocklist = ["password", "123456", "qwerty"]


# Helper: Mock function for Levenshtein distance
def mock_levenshtein_distance(str1: str, str2: str) -> int:
    # Return an arbitrary mock Levenshtein distance (to be replaced by real function)
    return abs(len(str1) - len(str2))


# Happy Path
def test_valid_passwords_not_in_blocklist():
    valid_passwords = ["secureP@ssphrase123!", "ComplexP@ss2024", "UniqueStr0ng"]
    for password in valid_passwords:
        result = blocklist_validator(password, standard_blocklist)
        assert result == {"isValid": True, "errors": []}


def test_handle_empty_inputs():
    cases = [
        {"password": "", "blocklist": standard_blocklist},
        {"password": "securepass", "blocklist": []},
        {"password": "securepass", "blocklist": [""]},
        {"password": "securepass", "blocklist": None},
        {"password": "securepass", "blocklist": ["b"]},
    ]
    for case in cases:
        result = blocklist_validator(case["password"], case["blocklist"])
        assert result == {"isValid": True, "errors": []}


def test_custom_distance_calculator():
    # Modify lambda to accept both term and password
    custom_distance_calculator = lambda term, password: len(term) // 6
    result = blocklist_validator(
        "ComplexPass",
        ["Complete"],
        {"customDistanceCalculator": custom_distance_calculator},
    )
    assert result["isValid"] is True


# Sad Path
def test_reject_exact_blocklist_terms():
    cases = [
        {
            "password": "myp@ssword123",
            "blocklist": ["password"],
            "expected_error": "password",
        },
        {
            "password": "secure_pass",
            "blocklist": ["secure_pass"],
            "expected_error": "secure_pass",
        },
        {
            "password": "mypassword😊",
            "blocklist": ["password😊"],
            "expected_error": "password😊",
        },
    ]
    for case in cases:
        result = blocklist_validator(case["password"], case["blocklist"])
        assert result["isValid"] is False
        # Strip both strings before comparison to remove extra spaces
        assert f'Password contains a substring too similar to: "{case["expected_error"]}".'.strip() in [
            error.strip() for error in result["errors"]
        ]


def test_multiple_violations_with_error_limit():
    password = "mypassword123"
    blocklist = ["password", "123", "myp"]

    # Default error limit (infinity)
    full_result = blocklist_validator(password, blocklist)
    assert full_result["isValid"] is False
    assert len(full_result["errors"]) == 3

    # Custom error limit
    limited_result = blocklist_validator(password, blocklist, {"errorLimit": 2})
    assert limited_result["isValid"] is False
    assert len(limited_result["errors"]) == 2


def test_fuzzy_matching():
    cases = [
        {"password": "password123", "blocklist": ["password"]},
        {"password": "mypassword", "blocklist": ["password"]},
        {"password": "p@ssword", "blocklist": ["password"]},
    ]
    for case in cases:
        result = blocklist_validator(
            case["password"], case["blocklist"], {"matchingSensitivity": 0.5}
        )
        assert result["isValid"] is False
        assert "password" in result["errors"][0]


def test_whitespace_handling():
    password = "mypassword"
    blocklist_term = "   password   "

    # With trimWhitespace enabled (default)
    trimmed_result = blocklist_validator(
        password, [blocklist_term], {"trimWhitespace": True}
    )
    assert trimmed_result["isValid"] is False

    # With trimWhitespace disabled
    untrimmed_result = blocklist_validator(
        password, [blocklist_term], {"trimWhitespace": False}
    )
    assert untrimmed_result["isValid"] is True


# Edge Cases
def test_bypass_fuzzy_for_short_terms():
    password = "testab"
    short_term = "ab"

    # Mock Levenshtein to ensure it's not called for short terms
    result = blocklist_validator(password, [short_term], {"matchingSensitivity": 1})
    assert "levenshtein_distance" not in result["errors"]


def test_utf8_characters():
    cases = [
        {"password": "パスワード123", "blocklist": ["パスワード"]},
        {"password": "пароль123", "blocklist": ["пароль"]},
        {"password": "password🔑", "blocklist": ["password🔑"]},
    ]
    for case in cases:
        result = blocklist_validator(case["password"], case["blocklist"])
        assert result["isValid"] is False
        assert len(result["errors"]) == 1


def test_long_password_and_blocklist():
    long_password = "a" * 1000
    long_blocklist_term = "a" * 500
    result = blocklist_validator(long_password, [long_blocklist_term])
    assert result["isValid"] is False


def test_special_characters_in_blocklist_terms():
    special_chars_blocklist = ["pass!@#$%", "pass^&*()", "pass<>?{}"]
    for term in special_chars_blocklist:
        result = blocklist_validator(term, [term])
        assert result["isValid"] is False
        assert term in result["errors"][0]
