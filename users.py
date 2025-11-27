"""
User-specific MCP tools for JumpServer.

Provides helpers to list users and toggle their login/active status via the
dedicated `/api/v1/users/users/` endpoints.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from app import mcp
from utils import safe_request

USERS_ENDPOINT = "/api/v1/users/users/"


def _build_user_url(user_id: Optional[str] = None) -> str:
    """
    Build the JumpServer user API URL.
    """
    if user_id:
        return f"{USERS_ENDPOINT}{user_id}/"
    return USERS_ENDPOINT


@mcp.tool("tools://list-users")
async def list_users(
    limit: int = 20,
    offset: int = 0,
    search: Optional[str] = None,
    is_login_blocked: Optional[bool] = None,
    is_active: Optional[bool] = None,
) -> Dict[str, Any]:
    """
    List JumpServer users with optional filters.

    Args:
        limit: Maximum number of users to return (default: 20)
        offset: Number of users to skip (default: 0)
        search: Optional search keyword (username, name, etc.)
        is_login_blocked: Filter by login-blocked users (True -> 1, False -> 0)
        is_active: Filter by active users (True -> 1, False -> 0)
    """
    params: Dict[str, Any] = {
        "limit": limit,
        "offset": offset,
    }
    if search is not None and search.strip():
        params["search"] = search.strip()
    if is_login_blocked is not None:
        params["is_login_blocked"] = 1 if is_login_blocked else 0
    if is_active is not None:
        params["is_active"] = 1 if is_active else 0

    return await safe_request("GET", USERS_ENDPOINT, params=params)


@mcp.tool("tools://update-user-status")
async def update_user_status(
    user_id: str,
    set_is_login_blocked: Optional[bool] = None,
    set_is_active: Optional[bool] = None,
) -> Dict[str, Any]:
    """
    Update user status flags such as login lock or active state.

    Args:
        user_id: JumpServer user ID to update
        set_is_login_blocked: If provided, set `is_login_blocked` to this value
        set_is_active: If provided, set `is_active` to this value
    """
    payload: Dict[str, Any] = {}
    if set_is_login_blocked is not None:
        payload["is_login_blocked"] = bool(set_is_login_blocked)
    if set_is_active is not None:
        payload["is_active"] = bool(set_is_active)

    if not payload:
        return {
            "error": "At least one of set_is_login_blocked or set_is_active must be provided.",
            "user_id": user_id,
        }

    return await safe_request(
        "PATCH",
        _build_user_url(user_id),
        json=payload,
    )

