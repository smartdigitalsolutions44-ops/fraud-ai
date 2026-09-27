# syntax=docker/dockerfile:1
# fraud-ai service image (Stage 9). Development/staging research build, not certified.
#
# What the image contains:
# * the installed package, its dependencies (CPU-only PyTorch) and the migrations;
# * no secrets, .env files, databases, trained models, LLM weights, tests or git
#   metadata (see .dockerignore).
#
# At runtime:
# * secrets come from the environment or a secret manager;
# * the database is external (PostgreSQL);
# * models are mounted read-only.
#
# The container runs as a non-root user and works with a read-only root filesystem
# (writable /tmp only). It serves plain HTTP on 8080: terminate TLS in front of it
# (see DEPLOYMENT.md).

FROM python:3.11-slim AS build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /src
COPY pyproject.toml README.md ./
COPY fraud_ai ./fraud_ai
# CPU-only PyTorch keeps the image small; the models run on CPU. Behind a TLS-intercepting
# proxy, pass its CA as a BuildKit secret (never baked into a layer):
#   docker build --secret id=ca_bundle,src=/path/ca.crt .
RUN --mount=type=secret,id=ca_bundle,required=false \
    if [ -f /run/secrets/ca_bundle ]; then export PIP_CERT=/run/secrets/ca_bundle; fi; \
    pip wheel --wheel-dir /wheels \
        --extra-index-url https://download.pytorch.org/whl/cpu \
        ".[postgres]"

FROM python:3.11-slim
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    FRAUD_AI_MIGRATIONS_DIR=/app/migrations \
    SERVICE_HOST=0.0.0.0 \
    SERVICE_PORT=8080 \
    DATA_DIRECTORY=/tmp/fraud-ai \
    MODEL_DIRECTORY=/models
RUN groupadd --system --gid 10001 fraud \
    && useradd --system --uid 10001 --gid fraud --home-dir /nonexistent --no-create-home \
       --shell /usr/sbin/nologin fraud
COPY --from=build /wheels /wheels
RUN pip install --no-index --find-links /wheels fraud-ai[postgres] \
    && rm -rf /wheels /root/.cache
WORKDIR /app
COPY migrations ./migrations
USER 10001:10001
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=30s --retries=3 \
    CMD ["python", "-c", "import os, sys, urllib.request; url = 'http://127.0.0.1:%s/v1/health' % os.environ.get('SERVICE_PORT', '8080'); sys.exit(0 if urllib.request.urlopen(url, timeout=2).status == 200 else 1)"]
ENTRYPOINT ["fraud-ai"]
CMD ["service", "run"]
