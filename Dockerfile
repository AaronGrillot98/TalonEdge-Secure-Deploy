# syntax=docker/dockerfile:1.7
#
# TalonEdge runtime image — multi-stage, non-root, base pinned by digest.
#
# IMPORTANT: refresh the digest before each release with:
#
#   docker buildx imagetools inspect python:3.11-slim --raw \
#     | jq -r '.manifests[] | select(.platform.architecture=="amd64") | .digest'
#
# The placeholder digest below is intentionally invalid format-correct so that
# `docker build` will fail loudly until you pin a real digest. This prevents
# accidental release with an unpinned base image.

ARG PYTHON_BASE=python:3.11.11-slim-bookworm@sha256:REPLACE_WITH_REAL_DIGEST_64_HEX_CHARS

FROM ${PYTHON_BASE} AS builder
WORKDIR /build
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1
COPY pyproject.toml requirements.txt ./
COPY src/ ./src/
RUN python -m pip install --upgrade pip \
 && python -m pip install --prefix=/install -r requirements.txt . \
 && find /install -name "__pycache__" -prune -exec rm -rf {} +

FROM ${PYTHON_BASE}
LABEL org.opencontainers.image.title="talonedge-secure-deploy" \
      org.opencontainers.image.source="https://github.com/AaronGrillot98/TalonEdge-Secure-Deploy" \
      org.opencontainers.image.description="Forward-deployed secure edge platform" \
      org.opencontainers.image.licenses="MIT"

# Non-root user with deterministic UID/GID matching the K8s securityContext.
RUN groupadd -r -g 10001 talon \
 && useradd -r -u 10001 -g 10001 -d /app -s /sbin/nologin talon \
 && mkdir -p /app/dist /app/reports /app/telemetry \
 && chown -R 10001:10001 /app

WORKDIR /app
COPY --from=builder /install /usr/local
COPY --chown=10001:10001 policies/ /app/policies/
COPY --chown=10001:10001 artifacts/ /app/artifacts/
COPY --chown=10001:10001 telemetry/sample_telemetry.json /app/telemetry/sample_telemetry.json

USER 10001:10001
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1

ENTRYPOINT ["python", "-m", "talonedge"]
CMD ["demo"]
