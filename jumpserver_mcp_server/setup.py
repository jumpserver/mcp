import logging

from pydantic import BaseModel


class LoggingConfig(BaseModel):
    LOGGER_NAME: str = "jumpserver_mcp_server"
    LOG_FORMAT: str = "%(levelprefix)s %(asctime)s\t[%(name)s] %(message)s"
    LOG_LEVEL: str = logging.getLevelName(logging.DEBUG)

    version: int = 1
    disable_existing_loggers: bool = False
    formatters: dict = {
        "default": {
            "()": "uvicorn.logging.DefaultFormatter",
            "fmt": LOG_FORMAT,
            "datefmt": "%Y-%m-%d %H:%M:%S",
        },
    }
    handlers: dict = {
        "default": {
            "formatter": "default",
            "class": "logging.StreamHandler",
        },
    }

    loggers: dict = {
        "": {"handlers": ["default"], "level": LOG_LEVEL},  # Root logger
        "uvicorn": {"handlers": ["default"], "level": LOG_LEVEL},
        LOGGER_NAME: {"handlers": ["default"], "level": LOG_LEVEL},
    }


def setup_logging(level, debug=False):
    level = level.upper()
    loggers = {
        "root": {"handlers": ["default"], "level": level},  # Root logger
        "uvicorn": {"level": level},
        "mcp": {"level": level},
        "jumpserver_mcp_server": { "level": level},
        "fastapi_mcp": {"level": "ERROR"},
    }
    if debug:
        loggers["fastapi_mcp"] = {"level": level}

    logging_config = LoggingConfig(loggers=loggers, LOG_LEVEL=level)
    from logging.config import dictConfig

    dictConfig(logging_config.model_dump())

