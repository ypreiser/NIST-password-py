# nist_password_validator/blocklist.py

from .utils.levenshteinDistance import levenshtein_distance


class Blocklist:
    def __init__(self, blocklist: list):
        self.blocklist = blocklist

    def is_blocked(self, password: str, fuzzy_tolerance: int) -> bool:
        """Check if the password is blocked or too similar to a blocked password."""
        for blocked in self.blocklist:
            if levenshtein_distance(password, blocked) <= fuzzy_tolerance:
                return True
        return False

    @classmethod
    def from_file(cls, file_path: str) -> 'Blocklist':
        """Load blocklist from a file."""
        with open(file_path, 'r') as file:
            blocklist = [line.strip() for line in file if line.strip()]
        return cls(blocklist)