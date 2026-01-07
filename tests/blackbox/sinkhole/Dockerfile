# Sinkhole server - captures all test traffic for inspection
FROM python:3.12-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy server code
COPY *.py .

# Expose ports: 8080 for HTTP traffic, 9999 for control API
EXPOSE 8080 9999

# Run the sinkhole server
CMD ["python", "server.py"]
