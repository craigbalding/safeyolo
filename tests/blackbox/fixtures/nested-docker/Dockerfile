FROM debian:trixie-slim
COPY safeyolo.crt /usr/local/share/ca-certificates/safeyolo.crt
ENV SSL_CERT_FILE=/usr/local/share/ca-certificates/safeyolo.crt
RUN printf 'Acquire::http::Proxy "%s";\nAcquire::https::Proxy "%s";\nAcquire::https::CaInfo "%s";\n' "$HTTP_PROXY" "$HTTPS_PROXY" "$SSL_CERT_FILE" > /etc/apt/apt.conf.d/80-safeyolo-proxy \
    && apt-get update && apt-get install -y --no-install-recommends python3 \
    && rm -rf /var/lib/apt/lists/*
COPY network_probe.py /app/network_probe.py
RUN python3 /app/network_probe.py
COPY notes.py /app/notes.py
CMD ["python3", "-u", "/app/notes.py"]
