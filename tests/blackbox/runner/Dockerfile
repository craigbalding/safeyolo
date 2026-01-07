# Test runner - pytest-based black box test suite
FROM python:3.12-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy test code
COPY *.py .

# Default: run all tests with verbose output
# -p no:cacheprovider: disable cache (volume is read-only)
CMD ["pytest", "-v", "--tb=short", "--timeout=60", "-p", "no:cacheprovider"]
