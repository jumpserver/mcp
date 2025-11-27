"""
JumpServer MCP Server Application

This module initializes the FastMCP server instance.
"""

from __future__ import annotations

from fastmcp import FastMCP


mcp = FastMCP(
    name="JumpServer MCP Server",
    instructions="""
        Interact with JumpServer's generic resource API.
        Use `data://resources` to discover resource names, inspect schemas
        via `data://resources/{resource}/schema/{action}`, then run the tools
        to list, create, update, or get resource entries.
    """,
)