from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


def _strip_quotes(value: str) -> str:
    """Strip one layer of matching quotes.

    `docker run --env-file` (unlike python-dotenv) passes .env values through
    verbatim, so a quoted value like `access_key_id='abc'` ends up with the
    quote characters baked into the actual credential.
    """
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        return value[1:-1]
    return value


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file='.env',
    )
    server_port: int = 8099
    api_key: str = ''
    gateway_key: str = ''
    api_base_url:str = ''
    api_token:str=  ''
    access_key_id: str = ''
    access_key_secret: str = ''
    base_path: str = '/sse'
    swagger_url: str = ''
    log_level: str = 'INFO'
    debug: bool = False
    jumpserver_url: str = ''

    @field_validator(
        "api_key",
        "gateway_key",
        "api_token",
        "access_key_id",
        "access_key_secret",
        "jumpserver_url",
        "api_base_url",
        "swagger_url",
        mode="before",
    )
    @classmethod
    def _strip_wrapping_quotes(cls, value: str) -> str:
        return _strip_quotes(value) if isinstance(value, str) else value


settings = Settings()
