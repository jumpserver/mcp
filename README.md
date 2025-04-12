# JumpServer mcp server

## 获取创建 JumpServer 相关配置文件 env

```
# Bearer token
api_token=xxxxxxx 
jumpserver_url=http://jumpserverhost
```

## 启动容器

```

docker run -d  -it  -p 8099:8099  --env-file .env  --name jms_mcp  jumpserver-mcp-server

```

## mcp server 配置

```json
{
    "type": "sse",
    "url": "http://127.0.0.1:8099/mcp",
}
```
