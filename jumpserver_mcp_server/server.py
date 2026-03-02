"""This module implements the JumpServer MCP server.

It includes:
- A custom implementation of FastApiMCP for JumpServer.
- Middleware for API key validation.
- Utility classes and functions for OpenAPI schema handling.
- Bearer token and AK/SK (Access Key / Secret Key) authentication for JumpServer API.
"""

import base64
import hashlib
import hmac
import re
import typing
from datetime import datetime, timezone
from logging import getLogger
from typing import Any, Optional, Union
from uuid import UUID

import httpx
from fastapi import APIRouter, FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from fastapi import BackgroundTasks
from fastapi_mcp import FastApiMCP
from fastapi_mcp.openapi.convert import convert_openapi_to_mcp_tools
from fastapi_mcp.transport.sse import FastApiSseTransport
from fastapi_mcp.types import HTTPRequestInfo
import mcp.types as types
from mcp.server.lowlevel.server import Server
from mcp.shared.message import ServerMessageMetadata, SessionMessage
from mcp.types import ErrorData, JSONRPCMessage, JSONRPCError
from pydantic import ValidationError
from anyio.streams.memory import MemoryObjectSendStream

from .config import settings
from .setup import setup_logging

setup_logging(settings.log_level, debug=settings.debug)

logger = getLogger(__name__)

# MCP 客户端（如 Cursor）要求「服务器名 + 工具名」总长不超过 60 字符
# 前缀 "jumpserver:" 为 11 字符，故工具名最多 49 字符
MAX_COMBINED_NAME_LEN = 60
JUMPSERVER_PREFIX_LEN = 11
MAX_TOOL_NAME_LEN = MAX_COMBINED_NAME_LEN - JUMPSERVER_PREFIX_LEN

# path 占位符未在 OpenAPI 声明时，从 arguments 中尝试的别名（如 perms_asset-permissions_read 的 id）
PATH_PLACEHOLDER_ALIASES: dict[str, list[str]] = {
    "id": ["pk", "asset_permission_id"],
    "user_id": ["user"],
    "node_id": ["node"],
    "asset_id": ["asset"],
}


class SessionMessageSseTransport(FastApiSseTransport):
    """SSE Transport 在写入 stream 前将 JSONRPCMessage 包装为 SessionMessage。

    与官方 mcp.server.sse 行为一致，避免 session 端出现
    'JSONRPCMessage' object has no attribute 'message'。
    """

    async def handle_fastapi_post_message(self, request: Request) -> Response:
        """处理 POST：解析 body 后包装为 SessionMessage 再交给 writer。"""
        session_id_param = request.query_params.get("session_id")
        if session_id_param is None:
            logger.warning("Received request without session_id")
            raise HTTPException(status_code=400, detail="session_id is required")

        try:
            session_id = UUID(hex=session_id_param)
        except ValueError:
            logger.warning("Received invalid session ID: %s", session_id_param)
            raise HTTPException(status_code=400, detail="Invalid session ID")

        writer = self._read_stream_writers.get(session_id)
        if not writer:
            logger.warning("Could not find session for ID: %s", session_id)
            raise HTTPException(status_code=404, detail="Could not find session")

        body = await request.body()
        logger.debug("Received JSON: %s", body.decode())

        try:
            message = types.JSONRPCMessage.model_validate_json(body)
            if hasattr(message.root, "params") and message.root.params is not None:
                message.root.params["_http_request_info"] = HTTPRequestInfo(
                    method=request.method,
                    path=request.url.path,
                    headers=dict(request.headers),
                    cookies=request.cookies,
                    query_params=dict(request.query_params),
                    body=body.decode(),
                ).model_dump(mode="json")
        except ValidationError as err:
            logger.error("Failed to parse message: %s", err)
            background_tasks = BackgroundTasks()
            background_tasks.add_task(self._send_message_safely, writer, err)
            response = JSONResponse(
                content={"error": "Could not parse message"}, status_code=400
            )
            response.background = background_tasks
            return response
        except Exception as e:
            logger.error("Error processing request body: %s", e)
            raise HTTPException(status_code=400, detail="Invalid request body")

        metadata = ServerMessageMetadata(request_context=request)
        session_message = SessionMessage(message, metadata=metadata)
        background_tasks = BackgroundTasks()
        background_tasks.add_task(self._send_message_safely, writer, session_message)
        response = JSONResponse(content={"message": "Accepted"}, status_code=202)
        response.background = background_tasks
        return response

    async def _send_message_safely(
        self,
        writer: MemoryObjectSendStream[Union[SessionMessage, Exception]],
        message: Union[SessionMessage, ValidationError],
    ) -> None:
        """向 writer 发送 SessionMessage，与 mcp session 期望类型一致。"""
        try:
            if isinstance(message, ValidationError):
                error_data = ErrorData(
                    code=-32700,
                    message="Parse error",
                    data={"validation_error": str(message)},
                )
                json_rpc_error = JSONRPCError(
                    jsonrpc="2.0", id="unknown", error=error_data
                )
                error_message = JSONRPCMessage(root=json_rpc_error)
                session_message = SessionMessage(error_message, metadata=None)
                await writer.send(session_message)
            else:
                await writer.send(message)
        except Exception as e:
            logger.error("Error sending message to writer: %s", e)


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
        self._tool_name_to_operation_id: dict[str, str] = {}
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

        # 缩短超长工具名，避免「服务器名+工具名」超过 60 字符被客户端过滤
        self._shorten_tool_names()

        # 使用 JumpServer API 的 base_url，否则父类默认 "http://apiserver" 会无法解析导致 ConnectError
        self._base_url = (self.base_url or self._base_url or "").rstrip("/")

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
            base_url = (self._base_url or "").rstrip("/")
            if settings.use_ak_sk():
                auth = JmsSignatureAuth(
                    settings.access_key, settings.secret_key, settings.jms_org
                )
                http_client = httpx.AsyncClient(
                    base_url=base_url, auth=auth, verify=False, timeout=60
                )
            else:
                try:
                    ctx = mcp_server.request_context
                    session = ctx.session
                    experimental = session._init_options.capabilities.experimental
                    authorization = experimental.get("session_token", {}).get("authorization")
                    logger.debug("Session token authorization: %s", authorization)
                except Exception as e:
                    logger.error("Error getting session token: %s", e)
                    authorization = ""
                http_client = httpx.AsyncClient(
                    base_url=base_url,
                    verify=False,
                    headers={"Authorization": authorization or ""},
                    timeout=60,
                )
            operation_id = self._tool_name_to_operation_id.get(name, name)
            args = dict(arguments)
            operation_map = self.operation_map
            # JumpServer 的 perms_users_my_assets_list 的 path 含 {user}，但 OpenAPI 可能未声明该 path 参数
            if operation_id == "perms_users_my_assets_list":
                op = operation_map.get(operation_id)
                if op and "{user}" in (op.get("path") or ""):
                    op = dict(op)
                    op["path"] = (op["path"] or "").replace("{user}", "my")
                    operation_map = {**operation_map, operation_id: op}
            # 通用：path 中的 {id}、{user} 等占位符若 OpenAPI 未声明，用 arguments 中同名参数替换
            op = operation_map.get(operation_id)
            if op:
                path = op.get("path") or ""
                replaced_keys = set()
                for key, value in list(args.items()):
                    if value is not None and f"{{{key}}}" in path:
                        path = path.replace(f"{{{key}}}", str(value))
                        replaced_keys.add(key)
                for key in replaced_keys:
                    args.pop(key, None)
                # 若 path 仍含占位符（如 {id}），OpenAPI 可能未声明 path 参数，尝试常见别名
                for placeholder_name in re.findall(r"\{(\w+)\}", path):
                    if placeholder_name in replaced_keys:
                        continue
                    value = args.get(placeholder_name)
                    key_used = placeholder_name if value is not None else None
                    if value is None:
                        for alt in PATH_PLACEHOLDER_ALIASES.get(placeholder_name, []):
                            value = args.get(alt)
                            if value is not None:
                                key_used = alt
                                break
                    if value is not None:
                        path = path.replace(f"{{{placeholder_name}}}", str(value))
                        if key_used:
                            args.pop(key_used, None)
                if path != (op.get("path") or ""):
                    op = dict(op)
                    op["path"] = path
                    operation_map = {**operation_map, operation_id: op}
            return await self._execute_api_tool(
                client=http_client,
                tool_name=operation_id,
                arguments=args,
                operation_map=operation_map,
            )

        self.server = mcp_server

    def _shorten_tool_names(self) -> None:
        """将超过 MAX_TOOL_NAME_LEN 的工具名缩短为 49 字符以内，并维护短名到 operation_id 的映射。"""
        self._tool_name_to_operation_id.clear()
        used_short_names: set[str] = set()

        for tool in self.tools:
            original = tool.name
            if len(original) <= MAX_TOOL_NAME_LEN:
                continue
            suffix = hashlib.sha256(original.encode()).hexdigest()[:8]
            base_short = original[:40] + "_" + suffix
            short_name = base_short[:MAX_TOOL_NAME_LEN]
            counter = 0
            while short_name in used_short_names:
                counter += 1
                short_name = (base_short[: MAX_TOOL_NAME_LEN - len(str(counter)) - 1] + "_" + str(counter))[:MAX_TOOL_NAME_LEN]
            used_short_names.add(short_name)
            self._tool_name_to_operation_id[short_name] = original
            tool.name = short_name
            logger.debug(
                "Shortened tool name %r -> %r",
                original,
                short_name,
            )

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

        sse_transport = SessionMessageSseTransport(messages_path)
        self.sse_transport = sse_transport

        # Route for MCP connection
        @router.get(mount_path, include_in_schema=False, operation_id="mcp_connection")
        async def handle_mcp_connection(request: Request):
            async with sse_transport.connect_sse(request.scope, request.receive, request._send) as (
                reader,
                writer,
            ):
                authorization = request.headers.get("authorization", "")
                await self.server.run(
                    reader,
                    writer,
                    self.server.create_initialization_options(
                        notification_options=None,
                        experimental_capabilities={
                            "session_token": {"authorization": authorization},
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
    """Uses HTTP Bearer authentication with a token string or bytes."""

    def __init__(self, token: str | bytes) -> None:
        self._auth_header = f"Bearer {token}" if isinstance(token, str) else f"Bearer {token.decode()}"

    def auth_flow(
        self, request: httpx.Request
    ) -> typing.Generator[httpx.Request, httpx.Response, None]:
        request.headers["Authorization"] = self._auth_header
        yield request


# GMT 日期格式，与 JumpServer / drf-httpsig 一致
_JMS_DATE_FMT = "%a, %d %b %Y %H:%M:%S GMT"


class JmsSignatureAuth(httpx.Auth):
    """JumpServer Access Key 签名认证：对 (request-target)、accept、date 做 HMAC-SHA256 签名。

    需在 Web 页面「API Key」中创建并获取 Access Key ID 与 Access Key Secret，
    配置为 access_key / secret_key（或环境变量 ACCESS_KEY / SECRET_KEY）。
    """

    def __init__(self, accessKey: str, secretKey: str, jmsOrg: str = "00000000-0000-0000-0000-000000000002") -> None:
        self._accessKey = accessKey
        self._secretKey = secretKey
        self._jmsOrg = jmsOrg

    def auth_flow(
        self, request: httpx.Request
    ) -> typing.Generator[httpx.Request, httpx.Response, None]:
        dateStr = datetime.now(timezone.utc).strftime(_JMS_DATE_FMT)
        request.headers["Date"] = dateStr
        request.headers.setdefault("Accept", "application/json")
        request.headers["X-JMS-ORG"] = self._jmsOrg

        # (request-target) = method.lower() + " " + path（不含 query，与 JumpServer 一致）
        path = request.url.raw_path.decode("utf-8") if request.url.raw_path else request.url.path
        if not path.startswith("/"):
            path = "/" + path
        requestTarget = f"{request.method.lower()} {path}"

        signingLines = [
            "(request-target): " + requestTarget,
            "accept: " + request.headers.get("Accept", "application/json"),
            "date: " + dateStr,
        ]
        signingString = "\n".join(signingLines)
        signature = base64.b64encode(
            hmac.new(
                self._secretKey.encode("utf-8"),
                signingString.encode("utf-8"),
                hashlib.sha256,
            ).digest()
        ).decode("ascii")
        request.headers["Authorization"] = (
            f'Signature keyId="{self._accessKey}",algorithm="hmac-sha256",'
            f'headers="(request-target) accept date",signature="{signature}"'
        )
        yield request


HTTP_OK = 200


class OpenAPISchemaFetchError(Exception):
    """Custom exception for OpenAPI schema fetch errors."""

    pass


def get_swagger_json(url: str = settings.swagger_url) -> dict[str, Any]:
    """Fetch the OpenAPI schema from the given URL.

    Uses Bearer api_token or AK/SK (access_key + secret_key) for authentication.
    """
    kwargs = {"verify": False, "timeout": 120}
    if settings.use_ak_sk():
        kwargs["auth"] = JmsSignatureAuth(
            settings.access_key, settings.secret_key, settings.jms_org
        )
    elif settings.api_token:
        kwargs["auth"] = BearerAuth(settings.api_token)
    resp = httpx.get(url, **kwargs)
    if resp.status_code != HTTP_OK:
        error_message = f"Failed to fetch OpenAPI schema: {resp.status_code} - {resp.text}"
        raise OpenAPISchemaFetchError(error_message)
    return resp.json()


app = FastAPI()
jumpserver_url = settings.jumpserver_url
base_url = settings.api_base_url
if not base_url and jumpserver_url:
    base_url = f"{jumpserver_url}/api/v1"
    logger.info("Base API URL set to: %s", base_url)
swagger_url = settings.swagger_url
if not swagger_url and jumpserver_url:
    # swagger_url = f"{jumpserver_url}/api/docs/?format=openapi"
    swagger_url = f"{jumpserver_url}/api/swagger.json"
    logger.info("Swagger URL set to: %s", swagger_url)
logger.info("Fetching OpenAPI schema from API URL: %s", swagger_url)
swagger_json = get_swagger_json(swagger_url)
if settings.use_ak_sk():
    auth = JmsSignatureAuth(
        settings.access_key, settings.secret_key, settings.jms_org
    )
    logger.info("Using JumpServer AK/SK (Access Key) authentication")
else:
    auth = BearerAuth(settings.api_token)
    logger.info("Using JumpServer Bearer token authentication")
http_client = httpx.AsyncClient(auth=auth, verify=False)
mcp = JumpServerOpenapiMCP(
    app,
    name="JumpServer API MCP",
    base_url=base_url,
    describe_all_responses=True,
    describe_full_response_schema=True,
    api_token=settings.api_token or "",  # 使用 AK/SK 时可留空
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


def _get_query_param(scope: dict, name: str) -> str | None:
    """从 ASGI scope 的 query_string 解析指定参数。"""
    from urllib.parse import parse_qs

    qs = scope.get("query_string", b"").decode()
    params = parse_qs(qs)
    values = params.get(name, [])
    return values[0] if values else None


def _get_header(scope: dict, key: str) -> str | None:
    """从 ASGI scope 的 headers 取指定 header（不区分大小写）。"""
    key_lower = key.lower().encode()
    for k, v in scope.get("headers", []):
        if k.lower() == key_lower:
            return v.decode() if isinstance(v, bytes) else v
    return None


async def _send_unauthorized(send: typing.Callable, message: str) -> None:
    """发送 401 响应：先 start 再 body，符合 ASGI 顺序，并带 Content-Length。"""
    body = message.encode("utf-8")
    headers = [
        (b"content-type", b"text/plain; charset=utf-8"),
        (b"content-length", str(len(body)).encode("ascii")),
    ]
    await send({"type": "http.response.start", "status": 401, "headers": headers})
    await send({"type": "http.response.body", "body": body, "more_body": False})


async def _check_api_key_impl(
    scope: dict, receive: typing.Callable, send: typing.Callable, next_app: typing.Callable
) -> None:
    """校验 Bearer/session；纯 ASGI，不包装响应流，避免与 SSE 流式响应冲突。"""
    if scope.get("type") != "http":
        await next_app(scope, receive, send)
        return

    session_id_param = _get_query_param(scope, "session_id")
    if session_id_param:
        if mcp.is_auth_session(session_id_param):
            await next_app(scope, receive, send)
            return
        logger.error("Unauthorized access attempt detected: session_id %s", session_id_param)
        await _send_unauthorized(send, "Unauthorized: Invalid session ID")
        return

    if settings.api_key:
        api_key = _get_header(scope, "authorization")
        if not api_key or not api_key.startswith("Bearer ") or api_key != f"Bearer {settings.api_key}":
            logger.error("Unauthorized access attempt detected: Authorization %s", api_key)
            await _send_unauthorized(send, "Unauthorized: Invalid API token")
            return

    await next_app(scope, receive, send)


class CheckApiKeyASGIMiddleware:
    """纯 ASGI 中间件，不包装响应流，避免 BaseHTTPMiddleware 与 SSE 冲突。"""

    def __init__(self, app: typing.Callable, **kwargs: typing.Any) -> None:
        self.app = app

    async def __call__(self, scope: dict, receive: typing.Callable, send: typing.Callable) -> None:
        await _check_api_key_impl(scope, receive, send, self.app)


app.add_middleware(CheckApiKeyASGIMiddleware)
