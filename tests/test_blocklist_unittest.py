# tests\test_blocklist_unittest.py
import unittest
import tempfile
import os
from src.blocklist import Blocklist


class TestBlocklist(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """Set up any necessary test fixtures that are shared across all tests."""
        cls.default_blocked_words = ['password123', 'admin1234', 'qwerty']
        
        # Create a temporary file for file-based tests
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write('password123\nadmin1234\nqwerty\n\n')  # Include empty line to test stripping
            cls.temp_file_path = f.name

    @classmethod
    def tearDownClass(cls):
        """Clean up any resources created in setUpClass."""
        if hasattr(cls, 'temp_file_path'):
            os.unlink(cls.temp_file_path)

    def setUp(self):
        """Set up test fixtures before each test method."""
        self.blocklist = Blocklist(self.default_blocked_words)

    def test_blocklist_initialization(self):
        """Test that the Blocklist is properly initialized with a list of words."""
        self.assertEqual(self.blocklist.blocklist, self.default_blocked_words)
        
        # Test initialization with empty list
        empty_blocklist = Blocklist([])
        self.assertEqual(empty_blocklist.blocklist, [])

    def test_exact_match_blocking(self):
        """Test exact password matching (fuzzy_tolerance = 0)."""
        # Test blocked password
        self.assertTrue(
            self.blocklist.is_blocked('password123', fuzzy_tolerance=0),
            "Should block exact match of blocked password"
        )
        
        # Test non-blocked password
        self.assertFalse(
            self.blocklist.is_blocked('secure_password', fuzzy_tolerance=0),
            "Should not block non-matching password"
        )

    def test_case_sensitivity(self):
        """Test that blocking is case-sensitive."""
        self.assertFalse(
            self.blocklist.is_blocked('PASSWORD123', fuzzy_tolerance=0),
            "Blocking should be case-sensitive"
        )
        self.assertFalse(
            self.blocklist.is_blocked('QWERTY', fuzzy_tolerance=0),
            "Blocking should be case-sensitive"
        )

    def test_fuzzy_matching(self):
        """Test fuzzy matching with different tolerance levels."""
        # Test with tolerance 1
        self.assertTrue(
            self.blocklist.is_blocked('password124', fuzzy_tolerance=1),
            "Should block password with one character different"
        )
        self.assertTrue(
            self.blocklist.is_blocked('password1234', fuzzy_tolerance=1),
            "Should block password with one extra character"
        )
        self.assertTrue(
            self.blocklist.is_blocked('password12', fuzzy_tolerance=1),
            "Should block password with one character removed"
        )
        
        # Test with tolerance 0
        self.assertFalse(
            self.blocklist.is_blocked('password124', fuzzy_tolerance=0),
            "Should not block similar password with tolerance 0"
        )
        
        # Test with higher tolerance
        self.assertTrue(
            self.blocklist.is_blocked('password12345', fuzzy_tolerance=2),
            "Should block password with two characters different"
        )

    def test_empty_blocklist(self):
        """Test behavior with empty blocklist."""
        empty_blocklist = Blocklist([])
        self.assertFalse(
            empty_blocklist.is_blocked('anypassword', fuzzy_tolerance=0),
            "Empty blocklist should not block any password"
        )
        self.assertFalse(
            empty_blocklist.is_blocked('anypassword', fuzzy_tolerance=1),
            "Empty blocklist should not block any password even with fuzzy matching"
        )

    def test_file_loading(self):
        """Test loading blocklist from file."""
        # Test successful file loading
        blocklist = Blocklist.from_file(self.temp_file_path)
        self.assertEqual(len(blocklist.blocklist), 3)
        self.assertIn('password123', blocklist.blocklist)
        self.assertIn('admin1234', blocklist.blocklist)
        self.assertIn('qwerty', blocklist.blocklist)

        # Test loading non-existent file
        with self.assertRaises(FileNotFoundError):
            Blocklist.from_file('nonexistent_file.txt')

    def test_edge_cases(self):
        """Test edge cases and boundary conditions."""
        # Test with very large fuzzy tolerance
        self.assertTrue(
            self.blocklist.is_blocked('completely_different', fuzzy_tolerance=1000),
            "Should block any password with very large tolerance"
        )
        
        # Test with negative fuzzy tolerance
        self.assertFalse(
            self.blocklist.is_blocked('password123', fuzzy_tolerance=-1),
            "Should not block even exact matches with negative tolerance"
        )

    def test_main_execution(self):
        """Test the main execution block."""
        import sys
        import io
        
        # Redirect stdout to capture the output
        captured_output = io.StringIO()
        sys.stdout = captured_output
        
        # Run the main block
        if __name__ == '__main__':
            unittest.main(argv=['dummy'], exit=False)
        
        # Restore stdout
        sys.stdout = sys.__stdout__


if __name__ == '__main__':
    unittest.main() 