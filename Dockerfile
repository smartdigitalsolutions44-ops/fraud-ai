# syntax=docker/dockerfile:1
# fraud-ai service image (Stage 9, build args added in Stage 10). Development/staging
# research build, not certified.
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
#
# Build arguments:
# * TORCH_INDEX_URL: where CPU-only PyTorch wheels come from (a mirror, if needed).
# * WITH_TORCH=0: a VERIFICATION variant without PyTorch, for build environments that
#   cannot reach a CPU PyTorch index. It can serve only the scikit-learn models
#   (gradient boosting, logistic regression); a neural active model fails readiness.
#   Never deploy it as the real image.
ARG WITH_TORCH=1
ARG TORCH_INDEX_URL=https://download.pytorch.org/whl/cpu
RUN --mount=type=secret,id=ca_bundle,required=false \
    if [ -f /run/secrets/ca_bundle ]; then export PIP_CERT=/run/secrets/ca_bundle; fi; \
    if [ "$WITH_TORCH" = "1" ]; then \
        pip wheel --wheel-dir /wheels --extra-index-url "$TORCH_INDEX_URL" ".[postgres,stripe]"; \
    else \
        python -c "import tomllib; p = tomllib.load(open('pyproject.toml', 'rb'))['project']; \
reqs = p['dependencies'] + p['optional-dependencies']['postgres'] + p['optional-dependencies']['stripe']; \
print('\n'.join(r for r in reqs if not r.startswith('torch')))" > /tmp/requirements.txt \
        && pip wheel --wheel-dir /wheels --no-deps . \
        && pip wheel --wheel-dir /wheels -r /tmp/requirements.txt; \
    fi

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
ARG WITH_TORCH=1
# Exactly the wheels resolved in the build stage, offline, bind-mounted so they never
# become an image layer; `pip check` proves the set is complete (skipped only for the
# torch-less verification variant). The installers themselves (pip, setuptools, wheel)
# are then removed: nothing installs packages at runtime, and they carried the image's
# only Python-level HIGH findings (see HARDENING.md, container scan).
RUN --mount=type=bind,from=build,source=/wheels,target=/wheels \
    pip install --no-index --no-deps /wheels/*.whl \
    && if [ "$WITH_TORCH" = "1" ]; then pip check; fi \
    && python -m pip uninstall --yes setuptools wheel pip \
    && rm -rf /root/.cache
WORKDIR /app
COPY migrations ./migrations
USER 10001:10001
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=30s --retries=3 \
    CMD ["python", "-c", "import os, sys, urllib.request; url = 'http://127.0.0.1:%s/v1/health' % os.environ.get('SERVICE_PORT', '8080'); sys.exit(0 if urllib.request.urlopen(url, timeout=2).status == 200 else 1)"]
ENTRYPOINT ["fraud-ai"]
CMD ["service", "run"]
