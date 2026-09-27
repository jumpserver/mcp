"""This module implements the JumpServer MCP server.

It includes:
- A custom implementation of FastApiMCP for JumpServer.
- Middleware for API key validation.
- Utility classes and functions for OpenAPI schema handling.
"""

import base64
import datetime
import hashlib
import hmac
import typing
from logging import getLogger
from typing import Any, Optional
from uuid import UUID

import httpx
from fastapi import APIRouter, FastAPI, Request, Response
from fastapi_mcp import FastApiMCP
from fastapi_mcp.openapi.convert import convert_openapi_to_mcp_tools
from fastapi_mcp.transport.sse import FastApiSseTransport
import mcp.types as types
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
        self.base_url = kwargs.pop("base_url", None)
        self.sse_transport = None
        super().__init__(app, **kwargs)

    def is_auth_session(self, session_id: str) -> bool:
        if not self.sse_transport:
            return False
        if not session_id:
            return False
        try:
            session_id = UUID(session_id)
        except ValueError:
            return False
        sse_transport = self.sse_transport
        return session_id in sse_transport._read_stream_writers

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

        # `FastApiMCP.__init__` (fastapi-mcp==0.3.3) hardcodes `self._base_url`
        # to a placeholder ("http://apiserver") meant only for its own
        # in-process ASGI-transport introspection, which never makes a real
        # network call. Our own configured base_url (stored as
        # `self.base_url` above) is what actual outbound tool calls need to
        # use, so it must win here — otherwise every real call resolves
        # "apiserver" and fails with a DNS error.
        self._base_url = (self.base_url or self._base_url).removesuffix("/")

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
            try:
                ctx = mcp_server.request_context
                session = ctx.session
                experimental = session._init_options.capabilities.experimental
                session_token = experimental.get("session_token", {})
                authorization = session_token.get("authorization", "")
                access_key_id = session_token.get("access_key_id", "")
                access_key_secret = session_token.get("access_key_secret", "")
                logger.debug("Session token authorization: %s", authorization)
            except Exception as e:
                logger.error("Error getting session token: %s", e)
                authorization = ""
                access_key_id = ""
                access_key_secret = ""
            if access_key_id and access_key_secret:
                # Each developer's own Access Key: the server signs every
                # request on their behalf, so no bearer token needs to be
                # kept around or refreshed.
                http_client = httpx.AsyncClient(
                    verify=False,
                    auth=AccessKeyAuth(access_key_id, access_key_secret),
                    timeout=60,
                    base_url=self._base_url or "",
                )
            else:
                http_client = httpx.AsyncClient(
                    verify=False,
                    headers={"Authorization": authorization},
                    timeout=60,
                    base_url=self._base_url or "",
                )
            # NOTE: base_url must live on the http_client, not as a kwarg to
            # _execute_api_tool — the pinned fastapi-mcp version doesn't
            # accept one there and raises a TypeError on every tool call.
            return await self._execute_api_tool(
                client=http_client,
                tool_name=name,
                arguments=arguments,
                operation_map=self.operation_map,
            )

        self.server = mcp_server

    def mount(self, router: Optional[FastAPI | APIRouter] = None, mount_path: str = "/mcp") -> None:
        """
        Mount the MCP server to **any** FastAPI app or APIRouter.
        There is no requirement that the FastAPI app or APIRouter is the same as the one that the MCP
        server was created from.

        Args:
            router: The FastAPI app or APIRouter to mount the MCP server to. If not provided, the MCP
                    server will be mounted to the FastAPI app.
            mount_path: Path where the MCP server will be mounted
        """
        # Normalize mount path
        if not mount_path.startswith("/"):
            mount_path = f"/{mount_path}"
        if mount_path.endswith("/"):
            mount_path = mount_path[:-1]

        if not router:
            router = self.fastapi

        # Build the base path correctly for the SSE transport
        if isinstance(router, FastAPI):
            base_path = router.root_path
        elif isinstance(router, APIRouter):
            base_path = self.fastapi.root_path + router.prefix
        else:
            raise ValueError(f"Invalid router type: {type(router)}")

        messages_path = f"{base_path}{mount_path}/messages/"

        sse_transport = FastApiSseTransport(messages_path)
        self.sse_transport = sse_transport

        # Route for MCP connection
        @router.get(mount_path, include_in_schema=False, operation_id="mcp_connection")
        async def handle_mcp_connection(request: Request):
            async with sse_transport.connect_sse(request.scope, request.receive, request._send) as (
                reader,
                writer,
            ):
                authorization = request.headers.get("authorization", "")
                access_key_id = request.headers.get("x-jumpserver-access-key-id", "")
                access_key_secret = request.headers.get("x-jumpserver-access-key-secret", "")
                await self.server.run(
                    reader,
                    writer,
                    self.server.create_initialization_options(
                        notification_options=None,
                        experimental_capabilities={
                            "session_token": {
                                "authorization": authorization,
                                "access_key_id": access_key_id,
                                "access_key_secret": access_key_secret,
                            },
                        },
                    ),
                )

        # Route for MCP messages
        @router.post(
            f"{mount_path}/messages/", include_in_schema=False, operation_id="mcp_messages"
        )
        async def handle_post_message(request: Request):
            return await sse_transport.handle_fastapi_post_message(request)

        # HACK: If we got a router and not a FastAPI instance, we need to re-include the router so that
        # FastAPI will pick up the new routes we added. The problem with this approach is that we assume
        # that the router is a sub-router of self.fastapi, which may not always be the case.
        #
        # TODO: Find a better way to do this.
        if isinstance(router, APIRouter):
            self.fastapi.include_router(router)

        logger.info(f"MCP server listening at {mount_path}")


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


class AccessKeyAuth(httpx.Auth):
    """JumpServer Access Key authentication using HTTP Signature (hmac-sha256).

    Signs each request with the `(request-target)`, `accept` and `date`
    headers, matching JumpServer's Access Key auth scheme. Unlike a Bearer
    token, an Access Key is permanent and generated by JumpServer's own
    password/MFA login, so it can be handed to a client once and forwarded
    per-session without ever needing to be refreshed.
    """

    def __init__(self, access_key_id: str, access_key_secret: str) -> None:
        self.access_key_id = access_key_id
        self.access_key_secret = access_key_secret

    def auth_flow(
        self, request: httpx.Request
    ) -> typing.Generator[httpx.Request, httpx.Response, None]:
        date = datetime.datetime.now(datetime.timezone.utc).strftime(
            "%a, %d %b %Y %H:%M:%S GMT"
        )
        accept = "application/json"
        request.headers["Date"] = date
        request.headers["Accept"] = accept

        path = request.url.path
        if request.url.query:
            # httpx.URL.query is bytes, not str — an f-string embeds its
            # repr (`b'limit=100'`) rather than the actual query text,
            # which silently signs the wrong request-target and gets
            # rejected as an invalid signature on any request that has
            # query parameters (anything without one signs fine by
            # accident, since empty bytes is falsy).
            path = f"{path}?{request.url.query.decode()}"
        request_target = f"{request.method.lower()} {path}"
        signing_string = "\n".join(
            [
                f"(request-target): {request_target}",
                f"accept: {accept}",
                f"date: {date}",
            ]
        )
        signature = base64.b64encode(
            hmac.new(
                self.access_key_secret.encode(),
                signing_string.encode(),
                hashlib.sha256,
            ).digest()
        ).decode()
        request.headers["Authorization"] = (
            f'Signature keyId="{self.access_key_id}",algorithm="hmac-sha256",'
            f'headers="(request-target) accept date",signature="{signature}"'
        )
        yield request


HTTP_OK = 200


class OpenAPISchemaFetchError(Exception):
    """Custom exception for OpenAPI schema fetch errors."""

    pass


def get_swagger_json(url: str = settings.swagger_url) -> dict[str, Any]:
    """Fetch the OpenAPI schema from the given URL.

    Args:
        url (str): The URL to fetch the OpenAPI schema from. Defaults to settings.swagger_url.

    Returns:
        dict[str, Any]: The OpenAPI schema in JSON format.

    Raises:
        OpenAPISchemaFetchError: If the schema cannot be fetched or the response status is not HTTP_OK.
    """
    kwargs = {"verify": False, "timeout": 120}

    if settings.access_key_id and settings.access_key_secret:
        # Access Key auth is permanent, so it's preferred for this one-time
        # startup call over a Bearer token that can silently expire between
        # container restarts.
        kwargs["auth"] = AccessKeyAuth(settings.access_key_id, settings.access_key_secret)
    elif settings.api_token:
        # If an API token is provided, use BearerAuth for authentication
        auth = BearerAuth(settings.api_token)
        kwargs["auth"] = auth
    resp = httpx.get(url, **kwargs)
    if resp.status_code != HTTP_OK:
        error_message = f"Failed to fetch OpenAPI schema: {resp.status_code} - {resp.text}"
        raise OpenAPISchemaFetchError(error_message)
    return resp.json()


app = FastAPI()
jumpserver_url = settings.jumpserver_url
base_url = settings.api_base_url
if not base_url and jumpserver_url:
    # No `/api/v1` suffix here: JumpServer's own OpenAPI schema already
    # declares each operation's path with that prefix included (e.g.
    # `/api/v1/users/profile/`), and httpx's base_url + path merging is a
    # plain concatenation rather than RFC 3986 absolute-path replacement —
    # so appending it here doubles it into `/api/v1/api/v1/...` on every
    # real tool call.
    base_url = jumpserver_url
    logger.info("Base API URL set to: %s", base_url)
swagger_url = settings.swagger_url
if not swagger_url and jumpserver_url:
    # swagger_url = f"{jumpserver_url}/api/docs/?format=openapi"
    swagger_url = f"{jumpserver_url}/api/swagger.json"
    logger.info("Swagger URL set to: %s", swagger_url)
logger.info("Fetching OpenAPI schema from API URL: %s", swagger_url)
swagger_json = get_swagger_json(swagger_url)
if settings.access_key_id and settings.access_key_secret:
    auth = AccessKeyAuth(settings.access_key_id, settings.access_key_secret)
else:
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


@app.middleware("http")
async def check_api_key(request: Request, call_next) -> Response:
    """Middleware to gate access to the MCP server.

    The `Authorization` header is reserved for each caller's own JumpServer
    credentials, which are forwarded per-session so that every JumpServer API
    call is attributed to that individual user. Gating access to the MCP
    server itself is done separately via `gateway_key` / `X-MCP-Gateway-Key`,
    so the two concerns don't collide on the same header.

    `api_key` (checked against `Authorization`) is kept only for backward
    compatibility with existing deployments that don't need per-user
    attribution; it is ignored once `gateway_key` is configured.
    """
    session_id_param = request.query_params.get("session_id")
    if session_id_param:
        if mcp.is_auth_session(session_id_param):
            return await call_next(request)
        else:
            logger.error("Unauthorized access attempt detected: session_id %s", session_id_param)
            return Response(status_code=401, content="Unauthorized: Invalid session ID")
    if settings.gateway_key:
        gateway_key = request.headers.get("x-mcp-gateway-key")
        if gateway_key != settings.gateway_key:
            logger.error("Unauthorized access attempt detected: X-MCP-Gateway-Key missing or invalid")
            return Response(status_code=401, content="Unauthorized: Invalid gateway key")
    elif settings.api_key:
        api_key = request.headers.get("Authorization")
        if (
            not api_key
            or not api_key.startswith("Bearer ")
            or api_key != f"Bearer {settings.api_key}"
        ):
            logger.error("Unauthorized access attempt detected: Authorization %s", api_key)
            return Response(status_code=401, content="Unauthorized: Invalid API token")
    return await call_next(request)
