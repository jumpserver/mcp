"""
MCP Prompts Module

This module provides pre-defined prompt templates for common JumpServer operations.
Prompts help users construct requests more easily by providing templates.
"""

from __future__ import annotations

from app import mcp


@mcp.prompt()
def create_and_show_resource() -> str:
    """
    Template for creating a resource and showing its details.
    
    This prompt helps users create a resource and immediately view the created resource's information.
    """
    return """Create a new resource in JumpServer and display its complete information.

Steps:
1. First, discover available resources using: data://resources
2. Check the schema for the resource you want to create using: data://resources/{resource}/schema/POST
3. Create the resource using: tools://create-resource with show_latest=true
4. The tool will automatically fetch and display the latest resource information after creation

Example workflow:
- List available resources: tools://get-supported-resources
- Get create schema: data://resources/users/schema/POST
- Create user: tools://create-resource with resource="users", data={...}, show_latest=true
"""


@mcp.prompt()
def update_and_show_resource() -> str:
    """
    Template for updating a resource and showing its latest details.
    
    This prompt helps users update a resource and immediately view the updated resource's information.
    """
    return """Update an existing resource in JumpServer and display its complete information.

Steps:
1. Find the resource you want to update (use tools://list-resource or tools://get-resource)
2. Check the update schema using: data://resources/{resource}/schema/PATCH
3. Update the resource using: tools://update-resource with resource_id and data, show_latest=true
4. The tool will automatically fetch and display the latest resource information after update

Example workflow:
- List resources: tools://list-resource with resource="users"
- Get update schema: data://resources/users/schema/PATCH
- Update user: tools://update-resource with resource="users", resource_id="11111111111111111", data={name: "...", email: "..."}, show_latest=true
"""


@mcp.prompt()
def create_user_workflow() -> str:
    """
    Template for creating a user with all necessary steps.
    """
    return """Create a new user in JumpServer.

Complete workflow:
1. Check available fields: data://resources/users/schema/POST
2. Create the user: tools://create-resource with:
   - resource="users"
   - data={username: "...", name: "...", email: "...", ...}
   - show_latest=true (to see the created user details)
3. The response will include the created user's complete information in the "latest" field
"""


@mcp.prompt()
def update_user_workflow() -> str:
    """
    Template for updating a user with all necessary steps.
    """
    return """Update an existing user in JumpServer.

Complete workflow:
1. Find the user: tools://list-resource with resource="users" and search="username"
   OR
   tools://get-resource with resource="users" and resource_id="..."
2. Check updateable fields: data://resources/users/schema/PATCH
3. Update the user: tools://update-resource with:
   - resource="users"
   - resource_id="11111111111111111" (the user's ID)
   - data={name: "...", email: "...", ...} (fields to update, do NOT include id)
   - show_latest=true (to see the updated user details)
4. The response will include the updated user's complete information in the "latest" field
"""
