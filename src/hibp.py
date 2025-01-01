import hashlib
import requests

API_URL = "https://api.pwnedpasswords.com/range/"


class ValidationResult:
    def __init__(self, is_valid: bool, errors: list[str]):
        self.is_valid = is_valid
        self.errors = errors


def generate_sha1(password: str) -> str:
    """
    Generates a SHA-1 hash for the given password.

    :param password: The password to hash.
    :return: The SHA-1 hash of the password.
    """
    sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest()
    return sha1_hash.upper()


def hibp_validator(password: str) -> ValidationResult:
    """
    Checks if the given password has been exposed in a data breach.

    :param password: The password to check.
    :return: ValidationResult indicating if the password has been compromised.
    """
    try:
        sha1 = generate_sha1(password)
        prefix = sha1[:5]
        suffix = sha1[5:]

        headers = {
            "User-Agent": "NIST-password-validator-py",
            "Add-Padding": "true"
        }

        response = requests.get(f"{API_URL}{prefix}", headers=headers)

        if response.status_code != 200:
            raise Exception(
                f"Failed to check password against HaveIBeenPwned API. "
                f"Status: {response.status_code}, Details: {response.text}"
            )

        lines = response.text.splitlines()

        found = any(
            line.split(":")[0].strip() == suffix and int(line.split(":")[1].strip()) > 0
            for line in lines
        )

        if found:
            return ValidationResult(
                is_valid=False,
                errors=["Password has been compromised in a data breach."]
            )

        return ValidationResult(is_valid=True, errors=[])

    except Exception as error:
        error_message = str(error)
        print(f"Error during password breach check: {error_message}")
        raise RuntimeError(f"HaveIBeenPwned check failed: {error_message}")


# Example usage:
if __name__ == "__main__":
    password_to_check = "example_password"
    result = hibp_validator(password_to_check)
    if result.is_valid:
        print("Password is safe to use.")
    else:
        print(f"Password compromised: {result.errors}")
