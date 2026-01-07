# Test runner - pytest-based black box test suite
FROM python:3.12-slim@sha256:a75662dfec8d90bd7161c91050be2e0a9b21d284f3b7a7253d5db25f7d583fb3

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy test code
COPY *.py .

# Default: run all tests with verbose output
# -p no:cacheprovider: disable cache (volume is read-only)
CMD ["pytest", "-v", "--tb=short", "--timeout=60", "-p", "no:cacheprovider"]
