# JumpServer MCP Server

## Configure JumpServer Environment File (.env)

```txt
# Bearer token to access the JumpServer Swagger Json API, optional
api_token=xxxxxxx 
jumpserver_url=http://jumpserverhost
```

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

## Related Projects / 相关项目

Community projects that extend JumpServer with MCP capabilities, complementary to this official management-plane server:

- [jumpserver-exec](https://github.com/yi-nology/jumpserver-exec) — 社区执行面 MCP 服务：经堡垒机 koko(2222) 在受管机器上执行命令、传输文件（18 个工具：批量执行 / 后台任务 / 跨机直传 / 危险命令确认 / 审计留痕），与本项目（管理面）互补。
- [jumpserver-mgmt](https://github.com/yi-nology/jumpserver-mgmt) — 社区管理面 MCP 服务。
- [jumpserver-kit](https://github.com/yi-nology/jumpserver-kit) — 上述社区项目的共用底座（协议层 / 门禁 / 输出契约 / 留痕 / 脱敏 / 风险分类）。
