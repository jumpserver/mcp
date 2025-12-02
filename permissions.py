"""Permission control for MCP tools based on user roles."""

from __future__ import annotations

from typing import Callable, Any
from functools import wraps

from fastmcp.server.dependencies import get_access_token
from fastmcp.utilities.logging import get_logger

logger = get_logger(__name__)


class PermissionDenied(Exception):
    """Raised when a user doesn't have permission to access a resource."""
    pass


def _extract_user_roles(claims: dict[str, Any]) -> list[str]:
    """Extract role names from user claims.
    
    Args:
        claims: User claims dictionary
        
    Returns:
        List of role names
    """
    role_names = []
    
    # Try to get roles from claims first
    if claims.get("is_org_admin", False):
        role_names.append("admin")
    if claims.get("is_superuser", False):
        role_names.append("superuser")
    return role_names


def _check_user_permission(claims: dict[str, Any], allowed_roles: tuple[str, ...]) -> tuple[bool, list[str]]:
    """Check if user has permission based on roles.
    
    Args:
        claims: User claims dictionary
        allowed_roles: Tuple of allowed role names
        
    Returns:
        Tuple of (has_permission, role_names)
    """
    username = claims.get("username", "unknown")
    
    # Check if user is superuser
    is_superuser = claims.get("is_superuser", False)
    if is_superuser and "superuser" in allowed_roles:
        logger.debug(f"User {username} granted access (superuser)")
        return True, ["superuser"]
    
    # Extract user roles
    role_names = _extract_user_roles(claims)
    
    # Check if user has any of the allowed roles
    has_permission = any(role in allowed_roles for role in role_names)
    
    return has_permission, role_names


def require_role(*allowed_roles: str):
    """Decorator to require specific roles for a tool.
    
    Args:
        *allowed_roles: One or more role names that are allowed to access the tool.
                       Special roles:
                       - "superuser": Users with is_superuser=True
                       - "admin": Users with admin role (you can customize this)
                       - Any custom role from JumpServer
    
    Example:
        @mcp.tool("admin-tool")
        @require_role("superuser", "admin")
        async def admin_only_tool():
            ...
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            # Get access token
            access_token = get_access_token()
            if not access_token:
                raise PermissionDenied("Authentication required")
            
            claims = access_token.claims or {}
            username = claims.get("username", "unknown")
            
            # Check permission
            has_permission, role_names = _check_user_permission(claims, allowed_roles)
            
            if not has_permission:
                logger.warning(
                    f"User {username} denied access to {func.__name__}. "
                    f"Required roles: {allowed_roles}, User roles: {role_names}"
                )
                raise PermissionDenied(
                    f"Access denied. Required roles: {', '.join(allowed_roles)}. "
                    f"Your roles: {', '.join(role_names) if role_names else 'none'}"
                )
            
            logger.debug(f"User {username} granted access with roles: {role_names}")
            return await func(*args, **kwargs)
        
        return wrapper
    return decorator


def require_superuser(func: Callable) -> Callable:
    """Convenience decorator to require superuser role."""
    return require_role("superuser")(func)


def get_current_user() -> dict[str, Any] | None:
    """Get current user information from access token.
    
    Returns:
        Dict with user information, or None if not authenticated.
    """
    access_token = get_access_token()
    if not access_token:
        return None
    
    claims = access_token.claims or {}
    return {
        "username": claims.get("username"),
        "id": claims.get("sub"),
        "name": claims.get("name"),
        "email": claims.get("email"),
        "is_superuser": claims.get("is_superuser", False),
        "is_active": claims.get("is_active", True),
        "jumpserver_user_data": claims.get("jumpserver_user_data", {}),
    }

