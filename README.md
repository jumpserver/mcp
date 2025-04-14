# JumpServer MCP Server

## Configure JumpServer Environment File (.env)

```txt
# Bearer token to access the JumpServer SWAGGER JSON API, optional
api_token=xxxxxxx 
jumpserver_url=http://jumpserverhost
```

## Start Docker Container

```bash
docker run -d -it -p 8099:8099 --env-file .env --name jms_mcp ghcr.io/leeeirc/jumpserver-mcp-server:latest
```

## Create JumpServer API Bearer Token for MCP Server

```shell

TOKEN=$(curl -s -X POST http://jumpserver_host/api/v1/authentication/auth/ \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "xxxx"
  }' \
  --insecure | jq -r '.token')

echo "Your Bearer token: $TOKEN"

```


## MCP Server Configuration

```json
{
    "type": "sse",
    "url": "http://127.0.0.1:8099/mcp",
    "headers": {
        "Authorization": "Bearer xxxxxxxx"
    }
}
```
