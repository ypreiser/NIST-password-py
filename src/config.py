# nist_password_validator/config.py

from typing import List, Optional

class ValidationOptions:
    def __init__(self, minLength: Optional[int] = None,
                 maxLength: Optional[int] = None,
                 blocklist: Optional[List[str]] = None,
                 matchingSensitivity: Optional[float] = 0.25,
                 maxEditDistance: Optional[int] = 5,
                 hibpCheck: Optional[bool] = False
                  errorLimit:Optional[int] ):
        self.minLength = minLength
        self.maxLength = maxLength
        self.blocklist = blocklist or []
        self.matchingSensitivity = matchingSensitivity
        self.maxEditDistance = maxEditDistance
        self.hibpCheck = hibpCheck

        

class ValidationResult:
    def __init__(self, isValid: bool, errors: List[str]):
        self.isValid = isValid
        self.errors = errors