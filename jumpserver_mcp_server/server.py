"""This module implements the JumpServer MCP server.

It includes:
- A custom implementation of FastApiMCP for JumpServer.
- Middleware for API key validation.
- Utility classes and functions for OpenAPI schema handling.
"""

import typing
from logging import getLogger
from typing import Any

import httpx
from fastapi import FastAPI, Request, Response
from fastapi_mcp import FastApiMCP
from fastapi_mcp.openapi.convert import convert_openapi_to_mcp_tools
from mcp import types
from mcp.server.lowlevel.server import Server

from .config import settings
from .setup import setup_logging

setup_logging(settings.log_level, debug=settings.debug)

logger = getLogger(__name__)


class JumpServerOpenapiMCP(FastApiMCP):
    """A custom implementation of FastApiMCP for JumpServer.

    This class extends FastApiMCP to integrate with JumpServer's API,
    providing functionality to convert OpenAPI schemas to MCP tools,
    filter tools, and handle tool calls.

    Attributes:
        api_token: The API token used for authentication.
        swagger_json: The OpenAPI schema in JSON format.
    """

    def __init__(self, app: FastAPI, **kwargs: Any) -> None:
        api_token = kwargs.pop("api_token")
        self.api_token = api_token
        self.swagger_json = kwargs.pop("swagger_json")
        super().__init__(app, **kwargs)

    def setup_server(self) -> None:
        """Set up the MCP server by converting OpenAPI schema to tools.

        Filter tools and register handlers for tool listing and tool calls.
        """
        # Get OpenAPI schema from FastAPI app
        openapi_schema = self.swagger_json

        # Convert OpenAPI schema to MCP tools
        all_tools, self.operation_map = convert_openapi_to_mcp_tools(
            openapi_schema,
            describe_all_responses=self._describe_all_responses,
            describe_full_response_schema=self._describe_full_response_schema,
        )
        logger.info("Loaded %d tools from OpenAPI schema.", len(all_tools))

        # Filter tools based on operation IDs and tags
        self.tools = self._filter_tools(all_tools, openapi_schema)
        logger.info("Filtered to %d tools after applying filters.", len(self.tools))

        # Normalize base URL
        self._base_url = self._base_url.removesuffix("/")

        # Create the MCP lowlevel server
        mcp_server: Server = Server(self.name, self.description)

        # Register handlers for tools
        @mcp_server.list_tools()
        async def handle_list_tools() -> list[types.Tool]:
            return self.tools

        # Register the tool call handler
        @mcp_server.call_tool()
        async def handle_call_tool(
            name: str, arguments: dict[str, Any]
        ) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
            return await self._execute_api_tool(
                client=self._http_client,
                base_url=self._base_url or "",
                tool_name=name,
                arguments=arguments,
                operation_map=self.operation_map,
            )

        self.server = mcp_server


class BearerAuth(httpx.Auth):
    """Allows the 'auth' argument to be passed as a token string or bytes.

    and uses HTTP Bearer authentication.
    """

    def __init__(self, token: str | bytes) -> None:
        """Initialize the BearerAuth instance with a token.

        Args:
            token (str | bytes): The token to be used for Bearer authentication.
        """
        self._auth_header = self._build_auth_header(token)

    def auth_flow(
        self, request: httpx.Request
    ) -> typing.Generator[httpx.Request, httpx.Response, None]:
        request.headers["Authorization"] = self._auth_header
        yield request

    def _build_auth_header(self, token: str | bytes) -> str:
        return f"Bearer {token}"


HTTP_OK = 200

def get_swagger_json(url: str = settings.swagger_url) -> dict[str, Any]:
    """Fetch the OpenAPI schema from the given URL.

    Args:
        url (str): The URL to fetch the OpenAPI schema from. Defaults to settings.swagger_url.

    Returns:
        dict[str, Any]: The OpenAPI schema in JSON format.

    Raises:
        OpenAPISchemaFetchError: If the schema cannot be fetched or the response status is not HTTP_OK.
    """
    auth = BearerAuth(settings.api_token)
    http_sync_client = httpx.get(url, auth=auth, verify=False, timeout=120)
    class OpenAPISchemaFetchError(Exception):
        """Custom exception for OpenAPI schema fetch errors."""

    if http_sync_client.status_code != HTTP_OK:
        error_message = (
            f"Failed to fetch OpenAPI schema: {http_sync_client.status_code} - "
            f"{http_sync_client.text}"
        )
        raise OpenAPISchemaFetchError(error_message)
    return http_sync_client.json()

app = FastAPI()

@app.middleware("http")
async def check_api_key(request: Request, call_next) -> Response:
    """Middleware to check the Bearer API key in the request headers.

    This middleware validates the Bearer API key provided in the request headers.
    """
    if settings.api_key:
        api_key = request.headers.get("Authorization")
        if (
            not api_key
            or not api_key.startswith("Bearer ")
            or api_key != f"Bearer {settings.api_key}"
        ):
            logger.error("Unauthorized access attempt detected: Authorization %s", api_key)
            return Response(status_code=401, content="Unauthorized: Invalid API token")
    return await call_next(request)

jumpserver_url = settings.jumpserver_url
base_url = settings.api_base_url
if not base_url and jumpserver_url:
    base_url = f"{jumpserver_url}/api/v1"
    logger.info("Base API URL set to: %s", base_url)
swagger_url = settings.swagger_url
if not swagger_url and jumpserver_url:
    swagger_url = f"{jumpserver_url}/api/docs/?format=openapi"
    logger.info("Swagger URL set to: %s", swagger_url)
logger.info("Fetching OpenAPI schema from API URL: %s", swagger_url)
swagger_json = get_swagger_json(swagger_url)
auth = BearerAuth(settings.api_token)
http_client = httpx.AsyncClient(auth=auth, verify=False)
mcp = JumpServerOpenapiMCP(
    app,
    name="JumpServer API MCP",
    base_url=base_url,
    describe_all_responses=True,  # Include all possible response schemas in tool descriptions
    describe_full_response_schema=True,  # Include full JSON schema in tool descriptions
    api_token=settings.api_token,
    http_client=http_client,
    swagger_json=swagger_json,
)
mount_path = settings.base_path
mount_path = mount_path.strip('"').strip("'")
if not mount_path.startswith("/"):
    mount_path = "/" + mount_path
mcp.mount(mount_path=mount_path)
mcp_path = f"{app.root_path}{mount_path}"
logger.info("Mounting MCP at path: %s", mcp_path)
