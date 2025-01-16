# nist_password_validator/validator.py

from .utils.levenshteinDistance import levenshtein_distance
from .config import ValidationOptions, ValidationResult
from .hibp import HIBPChecker

def validate_password(password: str, options: ValidationOptions) -> ValidationResult:
    errors = []

    # Check minimum length
    if options.minLength and len(password) < options.minLength:
        errors.append(f"Password must be at least {options.minLength} characters long.")

    # Check maximum length
    if options.maxLength and len(password) > options.maxLength:
        errors.append(f"Password must be no more than {options.maxLength} characters long.")

    # Check blocklist
    if options.blocklist:
        errors.extend(check_blocklist(password, options.blocklist, options.fuzzyToleranceValue))

    # Check HIBP
    if options.hibpCheck and HIBPChecker.check_password(password):
        errors.append("Password has been compromised in a data breach.")

    return ValidationResult(isValid=len(errors) == 0, errors=errors)

def check_blocklist(password: str, blocklist: list, fuzzy_tolerance: int) -> list:
    return [
        f"Password is too similar to the blocked password: {blocked}"
        for blocked in blocklist
        if levenshtein_distance(password, blocked) <= fuzzy_tolerance
    ]