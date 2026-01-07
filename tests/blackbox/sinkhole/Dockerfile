# Sinkhole server - captures all test traffic for inspection
#
# TLS certificates are mounted from ./certs/ (signed by test CA).
# This mirrors production where upstreams have CA-signed certificates.
FROM python:3.12-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy server code
COPY *.py .

# Expose ports: 8080 HTTP, 443 HTTPS, 9999 control API
EXPOSE 8080 443 9999

# Run the sinkhole server
CMD ["python", "server.py"]
