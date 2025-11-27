import httpx
from fastmcp import FastMCP
import os
import dotenv

dotenv.load_dotenv()

# Create an HTTP client for your API
host = "http://localhost:8080"
token = os.getenv("JUMPSERVER_TOKEN", "")
client = httpx.AsyncClient(
    base_url=host,
    headers={"Authorization": f"Token {token}"}
)

# Load your OpenAPI spec 
openapi_spec = httpx.get(f"{host}/api/swagger.json?mcp=1").json()

# Create the MCP server
mcp = FastMCP(
    client=client,
    name="JumpServer MCP Server",
    instructions="""
        This server provides tools to interact with the JumpServer API.
        Use the data://resources resource to discover available resource types
        and data://resources/{resource}/create-schema to inspect create fields.
    """,
)

SUPPORTED_RESOURCES_FALLBACK = [
    # User
    'users', 'user-groups', 'users-groups-relations',  
    # Asset
    'assets', 'hosts', 'devices', 'databases', 'webs', 'clouds', 'gpts',
    'ds', 'platforms', 'nodes', 'zones', 'gateways',
    # Account
    'virtual-accounts', 'account-templates',  'account-backups',
    # Automation
    'change-secret-automations', 'gather-account-automations', 
    'push-account-automations', 'check-account-automations',
    'account-risks',
    # Permission
    'asset-permissions',
    # Terminal
    'terminals', 'replay-storages', 'command-storages',  'asset-sessions', 'sessions',
    # Applet
    'applets', 'applet-hosts', 'virtual-apps', 
    # Ops
    'playbooks', 'jobs',
    # Audit
    'ftp-logs', 'login-logs', 'operate-logs', 'password-change-logs', 'job-logs',
    # Tickets
    'tickets', 'comments',   
    # Acls
    'login-acls', 'login-asset-acls', 'command-filter-acls',
    'command-groups', 'connect-method-acls', 'data-masking-rules',  
    # RBAC
    'roles', 'role-bindings',
    'system-roles', 'org-roles', 
    # Label
    'labeled-resources',
    'labels', 
]


@mcp.resource("data://resources")
async def get_resources() -> dict:
    """
    Provides the supported resources by querying JumpServer.
    Falls back to the static list if the API is unavailable.
    """
    try:
        response = await client.get("/api/v1/resources/")
        response.raise_for_status()
        return {
            "resources": response.json(),
            "source": "jumpserver",
        }
    except Exception:
        return {
            "resources": SUPPORTED_RESOURCES_FALLBACK,
            "source": "fallback",
        }


@mcp.resource("data://resources/{resource}/create-schema")
async def get_resource_create_schema(resource: str) -> dict:
    """
    Fetches the field schema for creating a resource.
    """
    try:
        response = await client.options(
            f"/api/v1/resources/{resource}/",
            params={"action": "create"},
        )
        response.raise_for_status()
        return {"resource": resource, "schema": response.json()}
    except httpx.HTTPStatusError as exc:
        return {
            "resource": resource,
            "error": f"JumpServer responded with status {exc.response.status_code}",
            "details": exc.response.text,
        }
    except Exception as exc:
        return {
            "resource": resource,
            "error": f"Failed to fetch create schema: {exc}",
        }


if __name__ == "__main__":
    mcp.run(transport="http", port=8000, )