# FRANSCOR reference hub. Build from the franscor/ directory:
#   docker build -f deploy/Dockerfile -t franscor-hub .
FROM python:3.13-slim AS build
WORKDIR /src
COPY packages/sdk-python/ ./
RUN pip install --no-cache-dir build && python -m build --wheel --outdir /wheels

FROM python:3.13-slim
RUN useradd --create-home --uid 10001 franscor
COPY --from=build /wheels /wheels
RUN pip install --no-cache-dir /wheels/*.whl && rm -rf /wheels
USER franscor
# Hub key and revocation list live in a volume; never bake keys into the image.
ENV FRANSCOR_HOME=/data
VOLUME ["/data"]
EXPOSE 7700
HEALTHCHECK --interval=10s --timeout=3s --retries=3 \
  CMD python -c "import socket; socket.create_connection(('127.0.0.1', 7700), 2).close()"
# 0.0.0.0 inside the container only; publish the port behind a TLS proxy (wss://).
ENTRYPOINT ["franscor", "hub", "--host", "0.0.0.0", "--port", "7700", "--identity", "hub", "--revocations", "/data/revocations.jsonl"]
