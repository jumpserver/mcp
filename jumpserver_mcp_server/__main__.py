import uvicorn
from .config import settings
from .server import app


def main():
    host = "0.0.0.0"
    port = settings.server_port
    uvicorn.run(host=host, port=port, app=app)


if __name__ == "__main__":
    main()
