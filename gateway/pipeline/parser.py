"""Stage 2: Request Ingress & Parser - Normalizes incoming HTTP request."""

from typing import Any, Dict


def parse_request(request_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract and normalize method, path, headers, query params, and body from raw request.

    Args:
        request_data: Raw dictionary containing HTTP attributes.

    Returns:
        Normalized dictionary representing the request context.
    """
    method = request_data.get("method", "GET").upper()
    path = request_data.get("path", "/")
    headers = {str(k).lower(): str(v) for k, v in request_data.get("headers", {}).items()}
    query_params = request_data.get("query_params", {})
    body = request_data.get("body", "")
    ip = request_data.get("ip", "127.0.0.1")

    # Combine extracted textual targets that could contain malicious payloads
    payload_targets = []
    if isinstance(body, str) and body:
        payload_targets.append(body)
    for k, v in query_params.items():
        payload_targets.append(f"{k}={v}")

    full_payload = " ".join(payload_targets)

    return {
        "method": method,
        "path": path,
        "headers": headers,
        "query_params": query_params,
        "body": body,
        "ip": ip,
        "raw_payload": full_payload,
    }
