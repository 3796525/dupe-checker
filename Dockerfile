# dupe-checker: read-only duplicate-file review tool.
# The container is deliberately minimal: no shell tooling needed at runtime,
# non-root by default, and the only writable path is the /data volume.
FROM python:3.11-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY main.py ./
# Build contexts from Windows/SMB shares often lose the executable/read bits;
# normalize so the non-root runtime user can always read the code.
RUN chmod -R a+rX /app

# Non-root runtime user. Compose may override it with user: APP_UID:APP_GID so
# the container identity matches the NAS account that holds the read grant.
RUN useradd --uid 1000 --create-home --shell /usr/sbin/nologin app \
    && mkdir -p /data \
    && chown app:app /data

USER app
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import sys,urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=3).status == 200 else 1)"

CMD ["python", "main.py"]
