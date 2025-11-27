from __future__ import annotations

from typing import Any, Dict, List, Literal

from app import mcp
from utils import safe_request

SUPPORTED_RESOURCES_FALLBACK: List[str] = [
    "users",
    "user-groups",
]


@mcp.resource("data://resources/names/")
def get_resource_names() -> List[str]:
    """
    Return the supported resource names.
    """
    return SUPPORTED_RESOURCES_FALLBACK


@mcp.resource("data://resources")
async def get_resources() -> Dict[str, Any]:
    """
    Provides the supported resources by querying JumpServer.
    Falls back to the static list if the API is unavailable.
    """
    result = await safe_request("GET", "/api/v1/resources/")
    
    if "error" in result:
        return {
            "resources": SUPPORTED_RESOURCES_FALLBACK,
            "source": "fallback",
            "error": result.get("error"),
        }
    
    return {
        "resources": result.get("result", []),
        "source": "jumpserver",
    }


ActionLiteral = Literal["GET", "POST", "PATCH", "PUT"]


@mcp.resource("data://resources/{resource}/schema/{action}")
async def get_resource_schema(
    resource: str, action: ActionLiteral | str = "POST"
) -> Dict[str, Any]:
    """
    Fetch the field schema for a given action (GET/POST/PATCH/PUT).
    """
    upper_action = action.upper()
    if upper_action not in {"GET", "POST", "PATCH", "PUT"}:
        return {
            "resource": resource,
            "error": f"Unsupported action '{action}'. Valid actions: GET, POST, PATCH, PUT.",
        }

    result = await safe_request(
        "OPTIONS",
        f"/api/v1/resources/{resource}/",
        params={"action": upper_action},
    )
    
    if "error" in result:
        return {
            "resource": resource,
            "action": upper_action,
            "error": result.get("error"),
            "error_detail": result.get("error_detail"),
        }
    
    return {
        "resource": resource,
        "schema": result.get("result"),
        "action": upper_action,
    }

