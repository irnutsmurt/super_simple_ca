# SuperSimpleCA web UI + ACME server.
# Single-process by design (the CA-unlock vault lives in memory), so this image
# runs one app process. All state lives on the /data volume.
FROM python:3.12-slim

# openssl: the CA signs/revokes/CRLs via the openssl binary.
# tini: proper PID 1 / signal handling.  gosu: drop root to the runtime user.
RUN apt-get update && apt-get install -y --no-install-recommends \
        openssl tini gosu ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Dedicated non-login runtime user; the entrypoint chowns /data to it.
RUN useradd --system --create-home --uid 1000 --shell /usr/sbin/nologin ssca

WORKDIR /app/webca

# Install Python deps first for better layer caching.
COPY webca/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# App code + entrypoint.
COPY webca/ /app/webca/
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# Config + all CA state live on the volume.
ENV SUPERSIMPLECA_CONFIG=/data/config.yaml \
    SSCA_CA_ROOT=/data \
    PYTHONUNBUFFERED=1

VOLUME ["/data"]
EXPOSE 8443

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/entrypoint.sh"]
CMD ["python", "app.py"]
