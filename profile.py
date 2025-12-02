from app import mcp


@mcp.tool
async def get_user_info() -> dict:
    """Returns information about the authenticated user."""
    from fastmcp.server.dependencies import get_access_token

    token = get_access_token()
    # The GitHubProvider stores user data in token claims
    return token.claims