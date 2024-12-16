# nist_password_validator/validator.py

from .utils import levenshtein_distance
from .config import ValidationOptions, ValidationResult
from .hibp import HIBPChecker

class PasswordValidator:
    def __init__(self, options: ValidationOptions):
        self.options = options

    def validate(self, password: str) -> ValidationResult:
        errors = []

        # Check minimum length
        if self.options.minLength and len(password) < self.options.minLength:
            errors.append(f"Password must be at least {self.options.minLength} characters long.")

        # Check maximum length
        if self.options.maxLength and len(password) > self.options.maxLength:
            errors.append(f"Password must be no more than {self.options.maxLength} characters long.")

        # Check blocklist
        if self.options.blocklist:
            for blocked in self.options.blocklist:
                if levenshtein_distance(password, blocked) <= self.options.fuzzyToleranceValue:
                    errors.append(f"Password is too similar to the blocked password: {blocked}")

        # Check HIBP
        if self.options.hibpCheck:
            if HIBPChecker.check_password(password):
                errors.append("Password has been compromised in a data breach.")

        return ValidationResult(isValid=len(errors) == 0, errors=errors)