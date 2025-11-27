## JumpServer FastMCP Server

This project exposes a JumpServer-compatible MCP server using the generic `/api/v1/resources/` endpoints. It relies on [fastmcp](https://github.com/modelcontextprotocol/fastmcp) and `httpx`.

### Configuration

Set the following environment variables (or create a `.env` file):

- `JUMPSERVER_HOST` – Base URL of your API server (default: `http://localhost:8080`)
- `JUMPSERVER_TOKEN` – JumpServer API token (optional but recommended)

### Installation

```bash
# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Running

```bash
python server.py  # exposes MCP over HTTP on port 8000
```

### Available MCP Interfaces

#### Resources (Data URIs)

- `data://resources` – Discover supported resource names (with fallback list)
- `data://resources/names/` – Get static list of supported resource names
- `data://resources/{resource}/schema/{action}` – Inspect field definitions for `GET`, `POST`, `PATCH`, or `PUT` via the JumpServer `OPTIONS` metadata

#### Tools

- `tools://get-supported-resources` – Get the list of supported resources from JumpServer
- `tools://list-resource` – List entries within a resource, supports `limit`, `offset`, `search`
- `tools://get-resource` – Get a single resource item by ID
- `tools://create-resource` – Create new resource entries with arbitrary payloads
- `tools://update-resource` – Update existing entries (identifier fields must be provided in the payload)
- `tools://list-users` – List JumpServer users via `/api/v1/users/users/` with login/active filters
- `tools://update-user-status` – Toggle `is_login_blocked` / `is_active` flags for a user

### API Endpoints

The server aggregates JumpServer's REST API into a unified interface:

- `GET /api/v1/resources/` – Returns supported resources
- `GET /api/v1/resources/{resource}/` – Get list with `search`, `offset`, `limit` pagination
- `GET /api/v1/resources/{resource}/{id}/` – Get resource details
- `OPTIONS /api/v1/resources/{resource}/?action=POST|PUT|PATCH` – Get schema for create/update operations
- `POST /api/v1/resources/{resource}/` – Create resource
- `PATCH /api/v1/resources/{resource}/` – Update resource
- `GET /api/v1/users/users/` – List users with `is_login_blocked` / `is_active` filters
- `PATCH /api/v1/users/users/{id}/` – Update user status flags (login lock / active state)

### Usage Tips

1. First, use `data://resources` to discover available resource types
2. Use `data://resources/{resource}/schema/{action}` to understand required fields before creating or updating
3. Leverage the schema resource to understand which fields are required before invoking the creation or update tools


