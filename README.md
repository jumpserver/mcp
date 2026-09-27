# JumpServer MCP Server

Expose JumpServer's API to any MCP-compatible AI client (Claude Code, Claude Desktop, Cursor,
and others) as a set of callable tools — so an assistant can look up assets, check permissions,
or investigate an incident directly against your JumpServer instance.

Every developer connects with their own JumpServer **Access Key**, so every action taken through
this server is attributed to their own account in JumpServer's audit/operation logs — not a
shared service credential. Each developer's access is exactly whatever their own JumpServer role
already permits: nothing more, nothing less.

## Contents

1. [Generate an Access Key](#1-generate-an-access-key-each-developer-does-this-themselves)
2. [Use it in your MCP client](#2-use-it-in-your-mcp-client)
3. [Configure and start the server](#3-configure-and-start-the-server-once-by-whoever-runs-it)
4. [Gate the MCP server itself (optional)](#4-optional-gate-the-mcp-server-itself)
5. [Bearer login token (alternative)](#bearer-login-token-alternative-not-recommended-if-mfa-is-enabled)

## 1. Generate an Access Key (each developer does this themselves)

1. Log into JumpServer with your own account.
2. Go to **Profile → Access Keys → Generate Access Key**.
3. Copy the `AccessKeyID` and `AccessKeySecret` immediately — JumpServer only shows the secret
   once, and there's no way to view it again afterward. If you lose it, generate a new one.

This is entirely self-service: no admin has to create anything, and it works whether or not MFA
is enabled on your account (MFA only gates the username/password login flow used to mint a
Bearer token — see [Bearer login token](#bearer-login-token-alternative-not-recommended-if-mfa-is-enabled)
for why that matters).

## 2. Use it in your MCP client

Add your key as two headers in your MCP client config:

```json
{
    "type": "sse",
    "url": "https://<your-mcp-host>/mcp",
    "headers": {
        "X-JumpServer-Access-Key-Id": "<your-own-key-id>",
        "X-JumpServer-Access-Key-Secret": "<your-own-key-secret>"
    }
}
```

The server signs every JumpServer API request on your behalf using this key. There's no token
to refresh, nothing that expires, and nothing to redo after the server restarts — your key stays
valid until you revoke it.

Every developer repeats steps 1 and 2 with their own account — that's the whole setup for
multi-developer use. Each person's actions show up under their own name in JumpServer, and their
JumpServer role/permissions are exactly what their MCP session can do, nothing more.

## 3. Configure and start the server (once, by whoever runs it)

The server itself needs one credential of its own, used only once at startup to fetch the API
schema (which tools exist). This is a single service-account credential, unrelated to any
developer's own key from step 1:

```txt
# .env
jumpserver_url=http://jumpserverhost
access_key_id=xxxx-xxxx-xxxx
access_key_secret=xxxxxxxxxxxxxxxx
```

Generate this the same way as step 1, but from a low-privilege (e.g. read-only/auditor) account
rather than an admin — it only needs to read schema metadata, not perform real actions, and it
sits in a config file on disk. Access Key is preferred here over a Bearer token (see below)
specifically because it doesn't expire: an expiring token in `.env` will eventually cause the
container to fail to start again after some future restart, once it silently expires.

```bash
docker run -d -it -p 8099:8099 --env-file .env --name jms_mcp ghcr.io/jumpserver/mcp:latest
```

## 4. (Optional) Gate the MCP server itself

Headers `X-JumpServer-Access-Key-Id`/`X-JumpServer-Access-Key-Secret` are reserved for each
developer's own credential. To also control who can reach the MCP server at all — separate from
whether their JumpServer credential is valid — set a shared secret with `gateway_key` in `.env`,
and have every client send it as a distinct header:

```txt
gateway_key=some-shared-secret
```

```json
{
    "type": "sse",
    "url": "https://<your-mcp-host>/mcp",
    "headers": {
        "X-JumpServer-Access-Key-Id": "<your-own-key-id>",
        "X-JumpServer-Access-Key-Secret": "<your-own-key-secret>",
        "X-MCP-Gateway-Key": "some-shared-secret"
    }
}
```

`api_key` still works as a simpler front-door gate for deployments that don't need per-developer
attribution at all, but it checks the same `Authorization` header a Bearer token would use, so it
can't be combined with per-developer Access Keys — use `gateway_key` instead when you need both.

## Bearer login token (alternative, not recommended if MFA is enabled)

JumpServer also supports a plain Bearer token, minted from your username and password:

```shell
TOKEN=$(curl -s -X POST http://jumpserver_host/api/v1/authentication/auth/ \
  -H "Content-Type: application/json" \
  -d '{
    "username": "alice",
    "password": "xxxx"
  }' \
  --insecure | jq -r '.token')

echo "Your Bearer token: $TOKEN"
```

```json
{
    "type": "sse",
    "url": "https://<your-mcp-host>/mcp",
    "headers": {
        "Authorization": "Bearer <your-own-token>"
    }
}
```

Two reasons Access Key is preferred over this:

- **It expires.** This token is temporary and needs to be regenerated periodically — every
  developer would need to repeat this manually and update their client config each time.
- **It doesn't work with MFA.** If MFA is enabled on the account, this login endpoint returns
  `{"error": "mfa_required"}` instead of a token, and completing the OTP challenge from a script
  is awkward to automate reliably. Access Key sidesteps this entirely, since it's verified by
  request signature rather than by re-running the password/MFA login flow.

`api_token` in `.env` (instead of `access_key_id`/`access_key_secret`) uses this same Bearer flow
for the server's own one-time startup schema fetch — same tradeoffs apply there too. When both
are set, Access Key takes precedence.
