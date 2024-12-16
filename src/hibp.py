import hashlib
import urllib.request
import urllib.error
import ssl

class HIBPChecker:
    """Password checker using HIBP API with zero dependencies."""
    
    TIMEOUT = 10
    API_HOST = "https://api.pwnedpasswords.com"
    
    @staticmethod
    def check_password(password: str, timeout: int = TIMEOUT) -> bool:
        """
        Check if password has been compromised using the HIBP API.
        
        Args:
            password: The password to check
            timeout: Request timeout in seconds
            
        Returns:
            bool: True if password is compromised, False if safe
            
        Raises:
            ValueError: If password is empty
            ConnectionError: For network/SSL issues
            TimeoutError: If request times out
        """
        if not password:
            raise ValueError("Password cannot be empty")

        # Hash password with SHA-1 (as required by HIBP API)
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix, suffix = sha1_hash[:5], sha1_hash[5:]
        
        # Create SSL context with secure defaults
        ctx = ssl.create_default_context()
        
        try:
            # Make request to HIBP API
            url = f"{HIBPChecker.API_HOST}/range/{prefix}"
            req = urllib.request.Request(
                url,
                headers={
                    'User-Agent': 'Python-HIBP-Checker',
                    'Add-Padding': 'true'  # HIBP padding for enhanced security
                }
            )
            
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as response:
                if response.status != 200:
                    raise ConnectionError(f"API error: {response.status} {response.reason}")
                
                # Search for hash suffix in response
                body = response.read().decode('utf-8')
                return any(
                    line.split(':')[0] == suffix 
                    for line in body.splitlines()
                )
                
        except urllib.error.URLError as e:
            if isinstance(e.reason, TimeoutError):
                raise TimeoutError("Request timed out") from e
            raise ConnectionError(f"Network error: {str(e)}") from e
        except TimeoutError as e:
            raise TimeoutError("Request timed out") from e
        except Exception as e:
            raise ConnectionError(f"Unexpected error: {str(e)}") from e