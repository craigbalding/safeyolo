FROM python:3.13-slim-trixie
COPY safeyolo.crt /usr/local/share/ca-certificates/safeyolo.crt
ENV SSL_CERT_FILE=/usr/local/share/ca-certificates/safeyolo.crt
COPY network_probe.py /app/network_probe.py
RUN python3 /app/network_probe.py
COPY notes.py /app/notes.py
CMD ["python3", "-u", "/app/notes.py"]
