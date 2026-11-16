FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2
ARG PROBE_ALLOWED=https://example.com
ARG PROBE_DENIED=http://denied.invalid
COPY safeyolo.crt /usr/local/share/ca-certificates/safeyolo.crt
ENV SSL_CERT_FILE=/usr/local/share/ca-certificates/safeyolo.crt
COPY network_probe.py notes.py /app/
CMD ["python3", "-u", "/app/notes.py"]
# VFS copies parent filesystems. Keep this Dockerfile's copies and metadata
# before Python installation; install and probe without intermediate snapshots.
RUN printf 'Acquire::http::Proxy "%s";\nAcquire::https::Proxy "%s";\nAcquire::https::CaInfo "%s";\n' "$HTTP_PROXY" "$HTTPS_PROXY" "$SSL_CERT_FILE" > /etc/apt/apt.conf.d/80-safeyolo-proxy \
    && apt-get update && apt-get install -y --no-install-recommends python3 \
    && rm -rf /var/lib/apt/lists/* && python3 /app/network_probe.py
