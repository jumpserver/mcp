from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file='.env',
    )
    server_port: int = 8099
    api_key: str = ''
    api_base_url: str = ''
    api_token: str = ''
    # AK/SK：与 api_token 二选一，用于 JumpServer Access Key 签名认证
    access_key: str = ''
    secret_key: str = ''
    # 组织 ID，AK/SK 请求需带 X-JMS-ORG，默认根组织
    jms_org: str = '00000000-0000-0000-0000-000000000002'
    base_path: str = '/sse'
    swagger_url: str = ''
    log_level: str = 'INFO'
    debug: bool = False
    jumpserver_url: str = ''

    def use_ak_sk(self) -> bool:
        """是否使用 AK/SK 认证（同时配置了 access_key 与 secret_key）。"""
        return bool(self.access_key.strip() and self.secret_key.strip())


settings = Settings()
