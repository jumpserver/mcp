# JumpServer MCP Server

将 JumpServer API 暴露为 MCP 工具，供 Cursor 等客户端查询用户、资产、权限等。通过 SSE 传输，支持 Bearer Token 或 AK/SK 认证 JumpServer。

## 环境配置（.env）

在 `mcp/` 目录下创建或编辑 `.env`，支持两种认证方式（二选一）。

### 方式一：Bearer Token

适用于用户名密码换取的 token 或管理后台生成的 Private Token。

```txt
api_token=xxxxxxx
jumpserver_url=https://jms.example.com
```

`api_token` 获取方式见下文「获取 JumpServer API Bearer Token」。

### 方式二：AK/SK（Access Key 签名）

在 JumpServer Web「API Key」中创建后配置：

```txt
access_key=你的AccessKeyID
secret_key=你的AccessKeySecret
jumpserver_url=https://jms.example.com
```

可选（默认根组织）：

```txt
jms_org=00000000-0000-0000-0000-000000000002
```

使用 AK/SK 时可不配置 `api_token`。

### 其他可选项

| 变量 | 说明 | 默认 |
|------|------|------|
| `server_port` | MCP 服务端口 | 8099 |
| `base_path` | MCP SSE 路径 | /sse |
| `api_key` | 若设置，校验 MCP 客户端请求头 `Authorization: Bearer <api_key>`，未通过则 401 | 空 |
| `api_base_url` | JumpServer API 根地址，不设则用 `jumpserver_url` + `/api/v1` | 空 |
| `swagger_url` | OpenAPI 地址，不设则用 `jumpserver_url` + `/api/swagger.json` | 空 |
| `log_level` | 日志级别 | INFO |

## 启动服务

### 方式 A：Docker

```bash
docker run -d -it -p 8099:8099 --env-file .env --name jms_mcp ghcr.io/jumpserver/mcp:latest
```

### 方式 B：本地运行

**前置**：Python 3.11+，在 `mcp/` 下已配置 `.env`。

**使用 uv（推荐）：**

```bash
cd mcp
uv sync
uv run main.py
```

**使用 pip：**

```bash
cd mcp
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e .
python main.py
```

服务默认监听 `0.0.0.0:8099`。MCP SSE 地址：`http://<本机IP或localhost>:8099/sse`。

## 获取 JumpServer API Bearer Token

### 无 MFA

```bash
TOKEN=$(curl -s -X POST "https://<jumpserver_host>/api/v1/authentication/auth/" \
  -H "Content-Type: application/json" \
  -d '{"username": "your_username", "password": "your_password"}' \
  --insecure | jq -r '.token')
echo "Your Bearer token: $TOKEN"
```

若返回 `{"error":"mfa_required",...}`，按下面「含 MFA」操作。

### 含 MFA

**Step 1：登录并保存 Cookie**

```bash
curl -v -X POST "https://<jumpserver_host>/api/v1/authentication/auth/" \
  -H "Content-Type: application/json" \
  -d '{"username": "your_username", "password": "your_password"}' \
  --insecure -c cookies.txt
```

**Step 2：提交 OTP**

将 `123456` 换成当前 6 位动态码：

```bash
curl -s -X POST "https://<jumpserver_host>/api/v1/authentication/mfa/challenge/" \
  -H "Content-Type: application/json" \
  -d '{"type": "otp", "code": "123456"}' \
  --insecure -b cookies.txt -c cookies.txt
```

**Step 3：再次登录取 token**

```bash
TOKEN=$(curl -s -X POST "https://<jumpserver_host>/api/v1/authentication/auth/" \
  -H "Content-Type: application/json" \
  -d '{"username": "your_username", "password": "your_password"}' \
  --insecure -b cookies.txt | jq -r '.token')
echo "Your Bearer token: $TOKEN"
```

也可在 Web 后台为该用户生成 **Private Token** 或使用 **AK/SK** 免 MFA。

## MCP 客户端配置（Cursor）

将上面获取的 Bearer token 替换为实际值。

**项目内**：在项目根目录 `.cursor/mcp.json` 中配置；**全局**：使用 `~/.cursor/mcp.json`。

```json
{
  "mcpServers": {
    "jumpserver": {
      "type": "sse",
      "url": "http://127.0.0.1:8099/sse",
      "headers": {
        "Authorization": "Bearer <你的 token>",
        "x-jumpserver-org": "00000000-0000-0000-0000-000000000002"
      }
    }
  }
}
```

`x-jumpserver-org` 可选，与 JumpServer 组织 ID 一致时可显式传入。修改后重启 Cursor 使 MCP 生效。

## 常见 MCP 用法

- **查用户**：工具 `users_users_list`，参数如 `username=wn`、`limit=10`。
- **查当前用户可管理资产（服务器）**：工具 `perms_users_my_assets_list`，参数如 `limit=50`、`offset=0`。返回的 Token 对应用户的资产列表；可据此筛选协议（如仅含 RDP 无 SSH 的机器）。
- **其他**：JumpServer OpenAPI 暴露的接口会转为 MCP 工具，名称过长时会被自动缩短以符合客户端 60 字符限制，调用时用短名即可。

## 注意事项

- 工具名「服务器名 + 工具名」总长超过 60 字符时会被自动缩短并映射回原始 operationId，无需改调用方式。
- 「我的资产」接口 path 中的 `{user}` 已在本服务内自动替换为 `my`，无需传 path 参数。
- 若 MCP 请求需校验，在 `.env` 中设置 `api_key`，客户端请求头需为 `Authorization: Bearer <api_key>`（可与 JumpServer token 相同或不同）。
