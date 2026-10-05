"""Stage 2: Request Ingress & Parser - Normalizes incoming HTTP request."""

import json
import urllib.parse
from typing import Any, Dict, List, Optional


def _extract_all_strings(val: Any) -> List[str]:
    """Recursively extract all string values from nested dicts, lists, or primitives."""
    strings = []
    if isinstance(val, str):
        if val.strip():
            strings.append(val)
    elif isinstance(val, dict):
        for k, v in val.items():
            if isinstance(k, str) and k.strip():
                strings.append(k)
            strings.extend(_extract_all_strings(v))
    elif isinstance(val, (list, tuple, set)):
        for item in val:
            strings.extend(_extract_all_strings(item))
    elif val is not None and not isinstance(val, (bool, int, float)):
        s = str(val)
        if s.strip():
            strings.append(s)
    return strings


def extract_client_ip(headers: Dict[str, str], fallback_ip: Optional[str] = None) -> str:
    """
    Extract client IP address with proxy header awareness.

    Checks in priority order:
    1. X-Forwarded-For (first IP in comma-separated list)
    2. X-Real-IP
    3. CF-Connecting-IP
    4. True-Client-IP
    5. Provided fallback IP or 127.0.0.1
    """
    proxy_headers = [
        "x-forwarded-for",
        "x-real-ip",
        "cf-connecting-ip",
        "true-client-ip",
    ]
    for h in proxy_headers:
        if h in headers and headers[h]:
            ip_val = headers[h].strip()
            # If comma-separated, take the first hop (original client IP)
            if "," in ip_val:
                first_ip = ip_val.split(",")[0].strip()
                if first_ip:
                    return first_ip
            elif ip_val:
                return ip_val

    if fallback_ip and str(fallback_ip).strip():
        return str(fallback_ip).strip()

    return "127.0.0.1"


def parse_request(request_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract and normalize method, path, headers, query params, form data, and body.

    Args:
        request_data: Raw dictionary containing HTTP attributes.

    Returns:
        Normalized dictionary representing the request context with:
        - method: str (uppercase, e.g. GET, POST)
        - path: str
        - headers: Dict[str, str] (lowercased keys)
        - query_params: Dict[str, Any]
        - form_data: Dict[str, Any]
        - body: Any
        - ip: str (proxy-aware client IP)
        - client_ip: str (alias for ip)
        - security_headers: Dict[str, str]
        - payload_targets: List[str]
        - raw_payload: str (combined representation of all inspectable payload targets)
    """
    method = str(request_data.get("method", "GET")).upper()
    path = str(request_data.get("path", "/"))

    # Normalize headers to lowercase keys and string values
    raw_headers = request_data.get("headers", {})
    if isinstance(raw_headers, dict):
        headers = {str(k).lower().strip(): str(v).strip() for k, v in raw_headers.items()}
    else:
        headers = {}

    # Extract client IP with proxy header awareness
    fallback_ip = request_data.get("ip") or request_data.get("client_ip") or request_data.get("remote_addr")
    ip = extract_client_ip(headers, fallback_ip=fallback_ip)

    # Normalize query parameters
    raw_query = request_data.get("query_params", {})
    query_params: Dict[str, Any] = {}
    if isinstance(raw_query, str):
        qs_parsed = urllib.parse.parse_qs(raw_query, keep_blank_values=True)
        query_params = {k: v[0] if len(v) == 1 else v for k, v in qs_parsed.items()}
    elif isinstance(raw_query, dict):
        query_params = dict(raw_query)

    # Form data
    raw_form = request_data.get("form_data", {})
    form_data: Dict[str, Any] = {}
    if isinstance(raw_form, str):
        form_parsed = urllib.parse.parse_qs(raw_form, keep_blank_values=True)
        form_data = {k: v[0] if len(v) == 1 else v for k, v in form_parsed.items()}
    elif isinstance(raw_form, dict):
        form_data = dict(raw_form)

    # Body (with payload / text / query key fallback for direct inspection requests)
    body = request_data.get("body")
    if body is None:
        body = request_data.get("payload") or request_data.get("text") or request_data.get("query") or ""


    # Security-relevant headers
    sec_header_keys = [
        "user-agent",
        "referer",
        "cookie",
        "origin",
        "authorization",
        "x-requested-with",
        "accept",
    ]
    security_headers = {k: headers[k] for k in sec_header_keys if k in headers}

    # Extract all inspectable payload targets
    payload_targets: List[str] = []

    # 1. Query parameters (extract both key=value and value targets)
    for k, v in query_params.items():
        if isinstance(v, (list, tuple)):
            for sub_v in v:
                payload_targets.append(f"{k}={sub_v}")
                if str(sub_v).strip():
                    payload_targets.append(str(sub_v))
        elif isinstance(v, dict):
            for sub_k, sub_v in v.items():
                payload_targets.append(f"{k}[{sub_k}]={sub_v}")
                if str(sub_v).strip():
                    payload_targets.append(str(sub_v))
        else:
            payload_targets.append(f"{k}={v}")
            if str(v).strip():
                payload_targets.append(str(v))

    # 2. Form data (extract both key=value and value targets)
    for k, v in form_data.items():
        if isinstance(v, (list, tuple)):
            for sub_v in v:
                payload_targets.append(f"{k}={sub_v}")
                if str(sub_v).strip():
                    payload_targets.append(str(sub_v))
        else:
            payload_targets.append(f"{k}={v}")
            if str(v).strip():
                payload_targets.append(str(v))



    # 3. Body (supports dict, list, string, or json-string)
    if isinstance(body, dict):
        payload_targets.extend(_extract_all_strings(body))
    elif isinstance(body, list):
        payload_targets.extend(_extract_all_strings(body))
    elif isinstance(body, str) and body:
        stripped_body = body.strip()
        if (stripped_body.startswith("{") and stripped_body.endswith("}")) or (
            stripped_body.startswith("[") and stripped_body.endswith("]")
        ):
            try:
                parsed_json = json.loads(stripped_body)
                payload_targets.extend(_extract_all_strings(parsed_json))
            except Exception:
                payload_targets.append(body)
        else:
            payload_targets.append(body)

    # 4. Check for attack vectors embedded in security headers
    for h_name in ("cookie", "referer", "user-agent"):
        if h_name in headers and headers[h_name]:
            h_val = headers[h_name]
            if any(char in h_val for char in ("<", ">", "'", '"', ";", "--", "/*", "*/")):
                payload_targets.append(h_val)

    # Fallback to path if no targets found and path has indicators
    if not payload_targets and ("?" in path or any(c in path for c in ("'", "<", ">"))):
        payload_targets.append(path)

    full_payload = " ".join(payload_targets).strip()

    return {
        "method": method,
        "path": path,
        "headers": headers,
        "query_params": query_params,
        "form_data": form_data,
        "body": body,
        "ip": ip,
        "client_ip": ip,
        "security_headers": security_headers,
        "payload_targets": payload_targets,
        "raw_payload": full_payload,
    }
