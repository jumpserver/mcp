from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file='.env',
    )
    server_port: int = 8099
    api_key: str = ''
    api_base_url:str = ''
    api_token:str=  ''
    base_path: str = '/mcp'
    swagger_url: str = ''
    log_level: str = 'INFO'
    debug: bool = False
    jumpserver_url: str = ''


settings = Settings()
