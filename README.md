# JumpServer MCP Server

## Configure JumpServer Environment File (.env)

```txt
# Bearer token
api_token=xxxxxxx 
jumpserver_url=http://jumpserverhost
```

## Start Docker Container

```bash
docker run -d -it -p 8099:8099 --env-file .env --name jms_mcp ghcr.io/leeeirc/jumpserver-mcp-server:latest
```

## MCP Server Configuration

```json
{
    "type": "sse",
    "url": "http://127.0.0.1:8099/mcp",
}
```
