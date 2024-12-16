# nist_password_validator/hibp.py

import http.client
import hashlib

class HIBPChecker:
    @staticmethod
    def check_password(password: str) -> bool:
        """Check if the password has been compromised using the HIBP API."""
        # Hash the password using SHA-1
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]

        # Connect to the HIBP API
        conn = http.client.HTTPSConnection("api.pwnedpasswords.com")
        conn.request("GET", f"/range/{prefix}")

        response = conn.getresponse()
        if response.status != 200:
            raise Exception("Error querying HIBP API")

        # Read the response and check if the password hash is in the response
        hashes = response.read().decode('utf-8').splitlines()
        for line in hashes:
            hash_suffix, count = line.split(':')
            if hash_suffix == suffix:
                return True  # Password has been compromised

        return False  # Password is safe