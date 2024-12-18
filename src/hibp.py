# src\hibp.py

import hashlib
import urllib.request
import urllib.error
import ssl

API_HOST = "https://api.pwnedpasswords.com/range/"
TIMEOUT = 10


class PwnedPasswordChecker:
    """
    A class to check if a password has been compromised using the Have I Been Pwned (HIBP) API.
    """

    def __init__(self, timeout: int = TIMEOUT):
        self.timeout = timeout
        self.api_host = API_HOST
        self.ctx = ssl.create_default_context()

    def check_password(self, password: str) -> bool:
        """
        Check if the password has been compromised.

        Args:
            password (str): The password to check.

        Returns:
            bool: True if compromised, False otherwise.

        Raises:
            ValueError: If the password is empty.
            ConnectionError: For network or API errors.
            TimeoutError: If the request times out.
        """
        if not password:
            raise ValueError("Password cannot be empty")

        sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix, suffix = sha1_hash[:5], sha1_hash[5:]

        try:
            body = self._make_request(prefix)
            return self.check_password_suffix(body, suffix)
        except urllib.error.URLError as e:
            self._handle_url_error(e)
        except TimeoutError as e:
            raise TimeoutError("Request timed out") from e
        except Exception as e:
            raise ConnectionError(f"Unexpected error: {str(e)}") from e

    def _make_request(self, prefix: str) -> str:
        """
        Make the request to the HIBP API.

        Args:
            prefix (str): The first 5 characters of the SHA-1 hash.

        Returns:
            str: The response body from the API.

        Raises:
            ConnectionError: For API or connection-related errors.
        """
        url = f"{self.api_host}{prefix}"
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "Python-HIBP-Checker",
                "Add-Padding": "true",
            },
        )

        with urllib.request.urlopen(
            req, timeout=self.timeout, context=self.ctx
        ) as response:
            if response.status != 200:
                raise ConnectionError(f"API error: {response.status} {response.reason}")

            return response.read().decode("utf-8")

    def check_password_suffix(self, body: str, suffix: str) -> bool:
        """
        Check if the password suffix is present in the response body
        and has a count greater than 0.

        Args:
            body (str): The response body from the API.
            suffix (str): The remaining characters of the SHA-1 hash.

        Returns:
            bool: True if the password hash is found with count > 0, False otherwise.
        """
        for line in body.splitlines():
            parts = line.split(":")
            if len(parts) == 2:  # Ensure the line has both suffix and count
                hash_suffix, count = parts
                if hash_suffix.strip() == suffix and int(count.strip()) > 0:
                    return True
        return False

    def _handle_url_error(self, e: urllib.error.URLError):
        """
        Handle URL errors and raise appropriate exceptions.

        Args:
            e (urllib.error.URLError): The error object to handle.

        Raises:
            TimeoutError: If the request timed out.
            ConnectionError: For network-related errors.
        """
        if isinstance(e.reason, TimeoutError) or "timeout" in str(e).lower():
            raise TimeoutError("Request timed out") from e
        raise ConnectionError(f"Network error: {str(e)}") from e


if __name__ == "__main__":
    password = input("Enter a password to check: ")
    checker = PwnedPasswordChecker()

    try:
        sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        body = checker._make_request(
            sha1_hash[:5]
        )  # Get the response body for the prefix
        compromised = checker.check_password(password)
        print(f"hash: {sha1_hash}")
        print(f"API Response: {body}")
        print(f"Password compromised: {compromised}")
    except Exception as e:
        print(f"Error: {str(e)}")
