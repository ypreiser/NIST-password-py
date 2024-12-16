# nist_password_validator/config.py

from typing import List, Optional

class ValidationOptions:
    def __init__(self, minLength: Optional[int] = None,
                 maxLength: Optional[int] = None,
                 allowedCharacterSet: Optional[str] = None,
                 blocklist: Optional[List[str]] = None,
                 fuzzyToleranceValue: Optional[int] = 3,
                 hibpCheck: Optional[bool] = False):
        self.minLength = minLength
        self.maxLength = maxLength
        self.allowedCharacterSet = allowedCharacterSet
        self.blocklist = blocklist or []
        self.fuzzyToleranceValue = fuzzyToleranceValue
        self.hibpCheck = hibpCheck

class ValidationResult:
    def __init__(self, isValid: bool, errors: List[str]):
        self.isValid = isValid
        self.errors = errors