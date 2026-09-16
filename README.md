# JumpServer MCP Server

## Configure JumpServer Environment File (.env)

```txt
# Bearer token to access the JumpServer Swagger Json API, optional
api_token=xxxxxxx 
jumpserver_url=http://jumpserverhost
```

Authentication with JumpServer supports two modes:

- **Bearer token** (default): set `api_token` to a token obtained from the login
  API (see below).
- **Access Key** (alternative): set `access_key_id` and `access_key_secret`
  from a JumpServer Access Key. The MCP server signs every request with an
  HTTP Signature (hmac-sha256), so no short-lived Bearer token is needed.

```txt
# Access Key auth (alternative to api_token)
access_key_id=xxxx-xxxx-xxxx
access_key_secret=xxxxxxxxxxxxxxxx
jumpserver_url=http://jumpserverhost
```

When both `api_token` and `access_key_id`/`access_key_secret` are set, Access
Key auth takes precedence.

## Start Docker Container

```bash
docker run -d -it -p 8099:8099 --env-file .env --name jms_mcp ghcr.io/jumpserver/mcp:latest
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

## Create JumpServer Access Key for MCP Server

1. Log into JumpServer.
2. Go to **个人中心 / Profile** → **访问密钥 / Access Keys** → **生成访问密钥**.
3. Copy the generated `AccessKeyID` and `AccessKeySecret` into the `.env`
   (`access_key_id` / `access_key_secret`).
4. Restart the MCP container.

The Access Key grants the same API permissions as the user who created it.

## MCP Server Configuration

```json
{
    "type": "sse",
    "url": "http://127.0.0.1:8099/sse",
    "headers": {
        "Authorization": "Bearer xxxxxxxx"
    }
}
```
