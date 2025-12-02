"""
JumpServer MCP Server Entry Point

This module initializes and runs the MCP server, registering all resources,
tools, and prompts from their respective modules.
"""

from app import mcp
import dotenv
import resources  # noqa: F401  (register MCP resources)
import tools  # noqa: F401  (register MCP tools)
import users  # noqa: F401  (register user-specific MCP tools)
import prompts  # noqa: F401  (register MCP prompts)
import profile  # noqa: F401  (register MCP profile)

dotenv.load_dotenv()

if __name__ == "__main__":
    mcp.run(transport="http", port=8000, host="0.0.0.0")