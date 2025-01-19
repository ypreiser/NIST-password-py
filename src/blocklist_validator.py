from utils.levenshtein_distance import levenshtein_distance

def blocklist_validator(
    password: str,
    blocklist: list[str] | None = None,
    options: dict = None
) -> dict:
    """
    Validates a password against a blocklist, allowing for fuzzy matching.

    Args:
        password (str): The password to validate.
        blocklist (list[str] | None): The list of blocked terms.
        options (dict, optional): Optional settings to customize validation. Defaults to None.
            matchingSensitivity (float): Controls matching strictness based on term length. Default is 0.25 (25%).
            maxEditDistance (int): Maximum character differences allowed for fuzzy matches. Default is 5.
            customDistanceCalculator (callable): Custom function to calculate edit distance.
            trimWhitespace (bool): Whether to trim leading/trailing whitespace from blocklist terms. Default is True.
            errorLimit (int): Maximum number of errors to report. Default is float('inf').

    Returns:
        dict: Contains a boolean indicating validity and a list of error messages.
    """
    if options is None:
        options = {}

    matching_sensitivity = options.get('matchingSensitivity', 0.25)
    max_edit_distance = options.get('maxEditDistance', 5)
    custom_distance_calculator = options.get('customDistanceCalculator')
    trim_whitespace = options.get('trimWhitespace', True)
    error_limit = options.get('errorLimit', float('inf'))

    errors = []

    if not blocklist or all(not term.strip() for term in blocklist):
        return {"isValid": True, "errors": errors}

    # Preprocess blocklist into a set for fast lookups
    processed_blocklist_set = {
        (term.strip().lower() if trim_whitespace else term.lower())
        for term in blocklist
        if term.strip()
    }

    # Helper: Calculate fuzzy tolerance
    def calculate_fuzzy_tolerance(term: str) -> int:
        if custom_distance_calculator:
            return custom_distance_calculator(term, password)
        return max(
            min(
                int(len(term) * matching_sensitivity),
                max_edit_distance
            ),
            0
        )

    # Helper: Check if a password substring matches a blocklist term
    def is_term_blocked(blocked_word: str) -> bool:
        fuzzy_tolerance = calculate_fuzzy_tolerance(blocked_word)
        if len(blocked_word) <= fuzzy_tolerance:
            return blocked_word.lower() in processed_blocklist_set

        for i in range(len(password) - len(blocked_word) + 1):
            substring = password[i:i + len(blocked_word)].lower()
            distance = levenshtein_distance(substring, blocked_word)
            if distance <= fuzzy_tolerance:
                return True
        return False

    # Validate against blocklist with early exit on error limit
    for term in processed_blocklist_set:
        if is_term_blocked(term):
            errors.append(f'Password contains a substring too similar to: "{term}".')
            if len(errors) >= error_limit:
                break  # Stop further checks when error limit is reached

    return {"isValid": len(errors) == 0, "errors": errors}
