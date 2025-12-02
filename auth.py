"""JumpServer authentication provider for FastMCP.

Simple bearer token authentication using JumpServer session IDs.
"""

from __future__ import annotations

import os

from fastmcp.server.dependencies import get_http_headers
import httpx
import dotenv
from pydantic import AnyHttpUrl

from fastmcp.server.auth import TokenVerifier
from fastmcp.server.auth.auth import AccessToken
from fastmcp.utilities.logging import get_logger
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.requests import Request

logger = get_logger(__name__)
dotenv.load_dotenv()


class JumpServerAuthProvider(TokenVerifier):
    """Simple JumpServer session token authentication.
    
    Validates bearer tokens in format `jms-<sessionid>` by calling
    JumpServer's profile API with the session cookie.
    """

    def __init__(
        self,
        *,
        jumpserver_host: str | None = None,
        timeout_seconds: int = 10,
        base_url: AnyHttpUrl | str | None = None,
    ):
        """Initialize JumpServer authentication provider.

        Args:
            jumpserver_host: JumpServer host URL (defaults to JUMPSERVER_HOST env var)
            timeout_seconds: HTTP request timeout (default: 10)
            base_url: Base URL of this server (optional)
        """
        super().__init__(base_url=base_url)
        
        jumpserver_host_final = jumpserver_host or os.getenv("JUMPSERVER_HOST")
        if jumpserver_host_final:
            jumpserver_host_final = jumpserver_host_final.rstrip("/")
        
        if not jumpserver_host_final:
            raise ValueError(
                "jumpserver_host is required - set via parameter or JUMPSERVER_HOST env var"
            )
        
        self.jumpserver_host = jumpserver_host_final
        self.timeout_seconds = timeout_seconds
        
        logger.info(f"Initialized JumpServer auth provider for {jumpserver_host_final}")

    async def verify_token(self, token: str) -> AccessToken | None:
        """Verify JumpServer session token."""
        # Check token format: jms-<sessionid>
        if not token.startswith("jms-"):
            logger.debug(f"Token does not start with 'jms-': {token[:20]}...")
            return None

        session_id = token[4:]  # Remove "jms-" prefix
        if not session_id:
            logger.debug("Empty session ID")
            return None
        
        headers = get_http_headers() 
        headers['Accept'] = 'application/json'
        headers.pop('authorization', None)

        try:
            # Request user profile with session cookie
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                response = await client.get(
                    f"{self.jumpserver_host}/api/v1/users/profile/",
                    headers=headers,
                )
                if response.status_code != 200:
                    logger.debug(f"Profile API failed: {response.status_code}")
                    return None
                
                user_data = response.json()
                logger.info(f"Authenticated user: {user_data.get('username', 'unknown')}")
                
                return AccessToken(
                    token=token,
                    client_id="jumpserver",
                    scopes=[],
                    expires_at=None,
                    claims={
                        "sub": str(user_data.get("id", "unknown")),
                        "username": user_data.get("username"),
                        "name": user_data.get("name"),
                        "email": user_data.get("email"),
                        "is_active": user_data.get("is_active"),
                        "is_org_admin": user_data.get("is_org_admin", False),
                        "is_superuser": user_data.get("is_superuser", False),
                        "jumpserver_user_data": user_data,  # Contains full user data including roles
                        "session_id": session_id,
                    },
                )
        
        except Exception as e:
            logger.debug(f"Token verification error: {e}")
            return None

    def get_routes(self, mcp_path: str | None = None) -> list[Route]:
        """Handle /register requests (MCP clients may try to register)."""
        async def handle_register(request: Request):
            return JSONResponse(
                status_code=400,
                content={
                    "error": "client_registration_not_supported",
                    "error_description": (
                        "This server uses simple bearer token authentication. "
                        "No client registration needed. Use: Authorization: Bearer jms-<sessionid>"
                    ),
                },
            )
        
        return [Route("/register", handle_register, methods=["POST"])]
