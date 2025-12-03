"""
Utility functions for JumpServer MCP Server.

This module contains shared HTTP client and request handling functions.
"""

from __future__ import annotations

import os
from fastmcp.server.dependencies import get_http_headers
from typing import Any, Dict, Optional

import httpx
import dotenv

dotenv.load_dotenv()


def _build_headers(token: str | None) -> Dict[str, str]:
    """Build HTTP headers with authorization if token is provided."""
    headers: Dict[str, str] = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Token {token}"
    return headers


# Initialize HTTP client
host = os.getenv("JUMPSERVER_HOST", "http://localhost:8080").rstrip("/")
token = os.getenv("JUMPSERVER_TOKEN", "")

client = httpx.AsyncClient(
    base_url=host,
    headers=_build_headers(token),
    timeout=httpx.Timeout(30.0, connect=10.0),
)


def _extract_response_data(response: httpx.Response) -> Any:
    """Extract data from HTTP response, trying JSON first, then text."""
    if not response.content:
        return None
    try:
        return response.json()
    except Exception:
        return response.text


def _extract_error_detail(exc: httpx.HTTPStatusError) -> Any:
    """Extract error details from HTTP error response."""
    if not exc.response.content:
        return None
    try:
        return exc.response.json()
    except Exception:
        return exc.response.text


async def safe_request(
    method: str,
    url: str,
    *,
    params: Optional[Dict[str, Any]] = None,
    json: Optional[Dict[str, Any]] = None,
    **kwargs: Any,
) -> Dict[str, Any]:
    """
    Make a safe HTTP request with comprehensive error handling.
    
    This function handles all errors internally and returns a consistent
    result dictionary, eliminating the need for try-catch blocks in callers.
    
    Args:
        method: HTTP method (GET, POST, PATCH, OPTIONS, etc.)
        url: URL path (relative to base_url)
        params: Query parameters
        json: JSON payload for POST/PATCH requests
        **kwargs: Additional arguments to pass to httpx.request
        
    Returns:
        Dict with:
            - "status": HTTP status code (if successful)
            - "result": Response data (JSON parsed or text)
            - "error": Error message (if failed)
            - "error_detail": Detailed error information (if available)
    """
    headers = get_http_headers()

    token = headers.get('authorization', '').replace('Bearer', '').strip()
    if token.startswith('jms'):
        headers.pop('authorization')

    if kwargs.get('headers', None):
        headers.update(kwargs['headers'])

    try:
        response = await client.request(method, url, params=params, json=json, headers=headers, **kwargs)
        response.raise_for_status()
        
        return {
            "status": response.status_code,
            "result": _extract_response_data(response),
        }
    except httpx.HTTPStatusError as exc:
        return {
            "status": exc.response.status_code,
            "error": f"HTTP {exc.response.status_code}",
            "error_detail": _extract_error_detail(exc),
        }
    except Exception as exc:
        return {
            "error": str(exc),
            "error_type": type(exc).__name__,
        }


async def request_resource(
    method: str,
    resource: str,
    *,
    resource_id: Optional[str] = None,
    params: Optional[Dict[str, Any]] = None,
    payload: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Make a request to the JumpServer resource API.
    
    This function builds the correct URL and handles the request/response,
    returning a consistent result dictionary.
    
    Args:
        method: HTTP method
        resource: Resource name (e.g., "users", "user-groups")
        resource_id: Optional resource ID for detail operations
        params: Query parameters (supports search, limit, offset, etc.)
        payload: Request body for POST/PATCH
        
    Returns:
        Dict with resource, resource_id, status, result/error
    """
    # Build URL: /api/v1/resources/{resource}/ or /api/v1/resources/{resource}/{id}/
    url = f"/api/v1/resources/{resource}/"
    if resource_id:
        url = f"/api/v1/resources/{resource}/{resource_id}/"
    
    result = await safe_request(method, url, params=params, json=payload)
    
    # Add resource context to the result
    result["resource"] = resource
    if resource_id:
        result["resource_id"] = resource_id
    
    return result

