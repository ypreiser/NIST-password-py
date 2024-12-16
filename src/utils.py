# nist_password_validator/utils.py

def levenshtein_distance(a: str, b: str) -> int:
    """Calculate the Levenshtein distance between two strings."""
    matrix = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]

    for i in range(len(a) + 1):
        for j in range(len(b) + 1):
            if i == 0:
                matrix[i][j] = j  # Deletion
            elif j == 0:
                matrix[i][j] = i  # Insertion
            else:
                cost = 0 if a[i - 1] == b[j - 1] else 1
                matrix[i][j] = min(matrix[i - 1][j] + 1,      # Deletion
                                   matrix[i][j - 1] + 1,      # Insertion
                                   matrix[i - 1][j - 1] + cost)  # Substitution

    return matrix[len(a)][len(b)]