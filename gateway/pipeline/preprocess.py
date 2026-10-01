"""Stage 3: Preprocessing - URL decoding, unescaping, and normalization."""

import urllib.parse
import html


def preprocess_payload(text: str) -> str:
    """
    Decode URL-encoded, HTML-entity-encoded payloads and normalize whitespace.

    Args:
        text: Raw payload string.

    Returns:
        Cleaned, normalized payload string.
    """
    if not text:
        return ""

    decoded = urllib.parse.unquote_plus(text)
    decoded = html.unescape(decoded)
    # Remove redundant whitespace
    normalized = " ".join(decoded.split())
    return normalized
