from fastapi import FastAPI, Body
from fastapi.middleware.cors import CORSMiddleware
from pydantic import create_model


from mcp import ClientSession, StdioServerParameters, types
from mcp.client.stdio import stdio_client

import argparse
import sys
from typing import Dict, Any

import asyncio
import uvicorn
import json
import os


async def create_dynamic_endpoints(app: FastAPI, session: ClientSession):
    tools_result = await session.list_tools()
    tools = tools_result.tools

    for tool in tools:
        print(tool)
        endpoint_name = tool.name
        endpoint_description = tool.description
        schema = tool.inputSchema

        # Dynamically creating a Pydantic model for validation and openAPI coverage
        model_fields = {}
        required_fields = schema.get("required", [])

        for param_name, param_schema in schema["properties"].items():
            param_type = param_schema["type"]
            param_desc = param_schema.get("description", "")
            python_type = str  # default

            if param_type == "string":
                python_type = str
            elif param_type == "integer":
                python_type = int
            elif param_type == "boolean":
                python_type = bool
            elif param_type == "number":
                python_type = float
            elif param_type == "object":
                python_type = Dict[str, Any]
            elif param_type == "array":
                python_type = list
            # Expand as needed. PRs welcome!

            default_value = ... if param_name in required_fields else None
            model_fields[param_name] = (
                python_type,
                Body(default_value, description=param_desc),
            )

        FormModel = create_model(f"{endpoint_name}_form_model", **model_fields)

        def make_endpoint_func(endpoint_name: str, FormModel):
            async def tool(form_data: FormModel):
                args = form_data.model_dump()
                print(f"Calling {endpoint_name} with arguments:", args)

                tool_call_result = await session.call_tool(
                    endpoint_name, arguments=args
                )

                response = []
                for content in tool_call_result.content:

                    text = content.text
                    if isinstance(text, str):
                        try:
                            text = json.loads(text)
                        except json.JSONDecodeError:
                            pass
                    response.append(text)

                return response

            return tool

        tool = make_endpoint_func(endpoint_name, FormModel)

        # Add endpoint to FastAPI with tool descriptions
        app.post(
            f"/{endpoint_name}",
            summary=endpoint_name.replace("_", " ").title(),
            description=endpoint_description,
        )(tool)


async def run(host: str, port: int, server_cmd: list[str]):
    server_params = StdioServerParameters(
        command=server_cmd[0],
        args=server_cmd[1:],
        env={**os.environ},
    )

    # Open connection to MCP first:
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            result = await session.initialize()

            server_name = (
                result.serverInfo.name
                if hasattr(result, "serverInfo") and hasattr(result.serverInfo, "name")
                else None
            )

            server_description = (
                f"{server_name.capitalize()} MCP OpenAPI Proxy"
                if server_name
                else "Automatically generated API endpoints based on MCP tool schemas."
            )

            server_version = (
                result.serverInfo.version
                if hasattr(result, "serverInfo")
                and hasattr(result.serverInfo, "version")
                else "1.0"
            )

            app = FastAPI(
                title=server_name if server_name else "MCP OpenAPI Proxy",
                description=server_description,
                version=server_version,
            )

            origins = ["*"]

            app.add_middleware(
                CORSMiddleware,
                allow_origins=origins,
                allow_credentials=True,
                allow_methods=["*"],
                allow_headers=["*"],
            )

            # Dynamic endpoint creation
            await create_dynamic_endpoints(app, session)

            config = uvicorn.Config(app=app, host=host, port=port, log_level="info")
            server = uvicorn.Server(config)
            await server.serve()


def parse_args():
    # Separate user args before and after "--"
    if "--" not in sys.argv:
        print("Usage: python main.py --host 0.0.0.0 --port 8000 -- your_mcp_command")
        sys.exit(1)

    split_index = sys.argv.index("--")
    proxy_args = sys.argv[1:split_index]
    mcp_args = sys.argv[split_index + 1 :]

    parser = argparse.ArgumentParser(description="FastAPI MCP OpenAPI Proxy")
    parser.add_argument("--host", type=str, default="0.0.0.0", help="Host to listen on")
    parser.add_argument("--port", type=int, default=8000, help="Port to listen on")

    args = parser.parse_args(proxy_args)

    if not mcp_args:
        print("Error: You must specify the MCP server command after '--'")
        sys.exit(1)

    return args.host, args.port, mcp_args


if __name__ == "__main__":
    host, port, server_cmd = parse_args()
    asyncio.run(run(host, port, server_cmd))