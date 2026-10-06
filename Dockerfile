FROM python:3.11-slim

WORKDIR /app

ARG AGENT_GATEWAY_ROOT_CERTIFICATES
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && \
    if [ -n "$AGENT_GATEWAY_ROOT_CERTIFICATES" ]; then \
      printf "%b" "$AGENT_GATEWAY_ROOT_CERTIFICATES" | awk 'BEGIN {c=0} /BEGIN CERTIFICATE/ {c++} c > 0 { print > "/usr/local/share/ca-certificates/agw-" c ".crt" }' && \
      update-ca-certificates; \
    fi && rm -rf /var/lib/apt/lists/*

ENV GRPC_DEFAULT_SSL_ROOTS_FILE_PATH=/etc/ssl/certs/ca-certificates.crt
ENV REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
ENV SSL_CERT_DIR=/etc/ssl/certs
ENV AGENT_GATEWAY_ROOT_CERT_302034098528=${AGENT_GATEWAY_ROOT_CERTIFICATES:+/etc/ssl/certs/ca-certificates.crt}

ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

RUN useradd -m -u 8888 aether && chown -R aether:aether /app
COPY --chown=aether:aether app/ app/
COPY --chown=aether:aether generate_mtls_certs.py .
COPY --chown=aether:aether certs/ certs/
RUN chmod -R 777 /app/certs

USER aether

ARG APP_ROLE=ops
ENV APP_ROLE=${APP_ROLE}

# EXPOSE is kept as a best practice; Cloud Run and Agent Runtime use dynamic PORT / AIP_HTTP_PORT env variables
EXPOSE 8080

# 🚀 Ensure mTLS certs exist and bind dynamically using AIP_HTTP_PORT or PORT environment variable
CMD ["sh", "-c", "python3 generate_mtls_certs.py >/dev/null && if [ \"$APP_ROLE\" = \"deployer\" ]; then if [ -z \"$K_SERVICE\" ] && [ \"${ENABLE_SOCKET_MTLS:-true}\" = \"true\" ]; then uvicorn app.deployer:app --host 0.0.0.0 --port ${PORT:-8081} --ssl-keyfile /app/certs/deployer-server.key --ssl-certfile /app/certs/deployer-server.crt --ssl-ca-certs /app/certs/ca.crt --ssl-cert-reqs 2; else uvicorn app.deployer:app --host 0.0.0.0 --port ${PORT:-8081}; fi; else uvicorn app.main:app --host 0.0.0.0 --port ${AIP_HTTP_PORT:-${PORT:-8080}}; fi"]


