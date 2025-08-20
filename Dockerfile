# syntax=docker/dockerfile:1
#
# sentinel — defensive SOC console.
# Builds the pipeline, generates detection artifacts, and serves the Streamlit
# SOC console. Strictly detective: no offensive capability is shipped.

FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim

WORKDIR /app

# Install dependencies first (cached layer) using the lockfile.
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-install-project --no-dev

# Copy the project source and install the package itself.
COPY src ./src
COPY README.md ./
RUN uv sync --frozen --no-dev

ENV PATH="/app/.venv/bin:$PATH"

# Pre-compute detection artifacts at build time so the console has data on start.
RUN sentinel detect --out artifacts

EXPOSE 8501

# Serve the SOC console. Regenerate artifacts on boot, then launch Streamlit
# bound to all interfaces for container access.
CMD ["sh", "-c", "sentinel detect --out artifacts && \
    streamlit run src/sentinel/dashboard.py \
    --server.address 0.0.0.0 --server.port 8501 --server.headless true \
    -- --artifacts artifacts"]
