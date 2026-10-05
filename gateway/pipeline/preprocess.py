"""Stage 3: Preprocessing - URL decoding, unescaping, and normalization."""

import html
import re
import urllib.parse
from typing import Optional

# Regex pattern for null bytes and hazardous control characters
# Strips ASCII 0-8, 11-12, 14-31, 127, and zero-width unicode spaces
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\u200b-\u200d\ufeff]")
_NULL_BYTE_ENCODED_RE = re.compile(r"%00|\\0|\\x00|\\u0000", re.IGNORECASE)


def recursive_url_decode(text: str, max_rounds: int = 10) -> str:
    """
    Recursively decode URL-encoded strings to defeat multi-layer URL encoding evasion.

    Example:
        '%2527' -> '%27' -> "'"
    """
    if not text:
        return ""
    current = text
    for _ in range(max_rounds):
        try:
            decoded = urllib.parse.unquote_plus(current)
        except Exception:
            break
        if decoded == current:
            break
        current = decoded
    return current


def recursive_html_unescape(text: str, max_rounds: int = 5) -> str:
    """
    Recursively unescape HTML entities to defeat nested entity obfuscation.

    Example:
        '&amp;lt;script&amp;gt;' -> '&lt;script&gt;' -> '<script>'
    """
    if not text:
        return ""
    current = text
    for _ in range(max_rounds):
        unescaped = html.unescape(current)
        if unescaped == current:
            break
        current = unescaped
    return current


def strip_null_and_control_chars(text: str) -> str:
    """
    Remove null bytes and invisible control characters used in filter bypassing.

    Handles literal null bytes (\\x00), URL-encoded nulls (%00), and zero-width spaces.
    """
    if not text:
        return ""
    # Strip literal encoded null forms
    cleaned = _NULL_BYTE_ENCODED_RE.sub("", text)
    # Strip control and zero-width chars
    cleaned = _CONTROL_CHAR_RE.sub("", cleaned)
    return cleaned


def normalize_whitespace(text: str) -> str:
    """Collapse contiguous whitespace characters into single spaces and strip outer padding."""
    if not text:
        return ""
    return " ".join(text.split())


def preprocess_payload(text: Optional[str]) -> str:
    """
    Complete multi-pass preprocessing pipeline for incoming payloads.

    Pipeline Stages:
    1. Null-byte & control character sanitization.
    2. Recursive URL decoding (resolves nested %25.. sequences).
    3. Recursive HTML entity unescaping (resolves &#x.. and &entity; sequences).
    4. Second-pass null/control character strip (in case decoding unmasked null bytes).
    5. Whitespace canonicalization.

    Args:
        text: Raw payload string.

    Returns:
        Cleaned, canonicalized payload string ready for tokenization and model inference.
    """
    if not text:
        return ""

    if not isinstance(text, str):
        text = str(text)

    # Pass 1: Null and control characters
    step1 = strip_null_and_control_chars(text)

    # Pass 2: Recursive URL decode
    step2 = recursive_url_decode(step1)

    # Pass 3: Recursive HTML unescape
    step3 = recursive_html_unescape(step2)

    # Pass 4: Secondary null/control strip
    step4 = strip_null_and_control_chars(step3)

    # Pass 5: Whitespace normalization
    step5 = normalize_whitespace(step4)

    return step5

