# Saboss Scan - production image
# Build:  docker build -t saboss-scan .
# Run:    see docker-compose.yml and docs/DEPLOYMENT.md
FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    SABOSS_ENV=production \
    SABOSS_HOST=0.0.0.0 \
    SABOSS_PORT=8000

WORKDIR /app

# Dependencies first (better layer caching)
COPY requirements.txt requirements-postgres.txt ./
RUN pip install -r requirements-postgres.txt

# Application code
COPY saboss_scan ./saboss_scan
COPY saboss_platform ./saboss_platform
COPY migrations ./migrations
COPY alembic.ini main.py ./

# Run as an unprivileged user
RUN useradd --create-home --uid 10001 saboss && mkdir -p /app/data && chown saboss:saboss /app/data
USER saboss

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=4).status == 200 else 1)"

CMD ["python", "-m", "saboss_platform", "serve"]
