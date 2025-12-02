from __future__ import annotations

from typing import Any, Dict, Optional

from app import mcp
from utils import request_resource, safe_request
from permissions import require_role, require_superuser, PermissionDenied


@mcp.tool("/admin/get-supported-resources")
@require_superuser  # Only superusers can access this tool
async def get_supported_resources() -> Dict[str, Any]:
    """
    Return the JumpServer-supported resource metadata list.
    
    Requires superuser role.
    """
    return await safe_request("GET", "/api/v1/resources/")


@mcp.tool("list-resource")
async def list_resource(
    resource: str,
    limit: int = 20,
    offset: int = 0,
    search: Optional[str] = None,
) -> Dict[str, Any]:
    """
    List a resource collection with optional pagination / search.
    
    Args:
        resource: Resource name (e.g., "users", "user-groups")
        limit: Maximum number of items to return (default: 20)
        offset: Number of items to skip (default: 0)
        search: Search query string (optional). If provided, filters results by this query.
    """
    params: Dict[str, Any] = {
        "limit": limit,
        "offset": offset,
    }
    # Only add search parameter if it's provided and not empty
    if search is not None and search.strip():
        params["search"] = search.strip()
    
    return await request_resource("GET", resource, params=params)


@mcp.tool("get-resource")
async def get_resource(
    resource: str,
    resource_id: str,
) -> Dict[str, Any]:
    """
    Get a single resource item by ID.
    
    Args:
        resource: Resource name (e.g., "users", "user-groups")
        resource_id: Unique identifier of the resource item
    """
    return await request_resource("GET", resource, resource_id=resource_id)


def _extract_resource_id(result: Dict[str, Any]) -> Optional[str]:
    """
    Extract resource ID from create/update response.
    
    Common ID field names: id, pk, uuid, etc.
    """
    if "error" in result:
        return None
    
    result_data = result.get("result")
    if not isinstance(result_data, dict):
        return None
    
    # Try common ID field names
    for id_field in ["id", "pk", "uuid", "key"]:
        if id_field in result_data:
            return str(result_data[id_field])
    
    return None


@mcp.tool("create-resource")
@require_role("superuser", "admin")  # Only superuser or admin can create resources
async def create_resource(
    resource: str,
    data: Dict[str, Any],
    show_latest: bool = True,
) -> Dict[str, Any]:
    """
    Create a new resource item and optionally return the latest information.
    
    Requires superuser or admin role.
    
    Args:
        resource: Resource name (e.g., "users", "user-groups")
        data: Resource data dictionary. Use the schema resource to discover required fields.
        show_latest: If True, fetch and return the latest resource information after creation (default: True)
    """
    result = await request_resource("POST", resource, payload=data)
    
    # If creation was successful and show_latest is True, fetch the latest information
    if show_latest and "error" not in result:
        resource_id = _extract_resource_id(result)
        if resource_id:
            latest_result = await request_resource("GET", resource, resource_id=resource_id)
            result["latest"] = latest_result.get("result")
        else:
            # If we can't extract ID, include the creation result
            result["latest"] = result.get("result")
    
    return result


@mcp.tool("update-resource")
@require_role("superuser", "admin")  # Only superuser or admin can update resources
async def update_resource(
    resource: str,
    resource_id: str,
    data: Dict[str, Any],
    show_latest: bool = True,
) -> Dict[str, Any]:
    """
    Update an existing resource item and optionally return the latest information.
    
    Requires superuser or admin role.
    
    Args:
        resource: Resource name (e.g., "users", "user-groups")
        resource_id: Unique identifier of the resource item to update
        data: Resource data dictionary with fields to update. Use the schema resource
              to discover which fields can be updated. The resource_id should NOT be included in data.
        show_latest: If True, fetch and return the latest resource information after update (default: True)
    """
    # PATCH /api/v1/resources/{resource}/{id}/
    result = await request_resource("PATCH", resource, resource_id=resource_id, payload=data)
    
    # If update was successful and show_latest is True, fetch the latest information
    if show_latest and "error" not in result:
        latest_result = await request_resource("GET", resource, resource_id=resource_id)
        result["latest"] = latest_result.get("result")
    
    return result