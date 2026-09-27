# Build stage with explicit platform specification
#
# Debian-slim (glibc), not Alpine: Alpine's musl libc DNS resolver serializes
# lookups and has weak retry behavior under concurrency, which surfaces as
# intermittent `[Errno -3] Try again` (EAI_AGAIN) once real traffic starts —
# a fresh httpx.AsyncClient() per tool call means a fresh DNS lookup each
# time. glibc's resolver doesn't share this limitation.
FROM ghcr.io/astral-sh/uv:python3.11-bookworm-slim

# Install the project into /app
WORKDIR /app

# Enable bytecode compilation
ENV UV_COMPILE_BYTECODE=1

# Copy from the cache instead of linking since it's a mounted volume
ENV UV_LINK_MODE=copy

# Install the project's dependencies using the lockfile and settings
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    uv sync --frozen --no-install-project --no-dev --no-editable

# Then, add the rest of the project source code and install it
# Installing separately from its dependencies allows optimal layer caching
ADD . /app
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-editable


# Place executables in the environment at the front of the path
ENV PATH="/app/.venv/bin:$PATH"


CMD ["uv", "run", "main.py"]