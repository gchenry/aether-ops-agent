FROM python:3.11-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

RUN useradd -m -u 8888 aether && chown -R aether:aether /app
COPY --chown=aether:aether app/ app/
COPY --chown=aether:aether generate_mtls_certs.py .
COPY --chown=aether:aether certs/ certs/

USER aether

# EXPOSE is kept as a best practice but Cloud Run ignores it in favor of the dynamic PORT env variable
EXPOSE 8080

# 🚀 Ensure mTLS certs exist and bind dynamically using the $PORT environment variable
CMD ["sh", "-c", "python3 generate_mtls_certs.py >/dev/null && uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8080}"]
