# Use an official slim Python base
FROM python:3.11-slim

# Set working dir
WORKDIR /app

# Install minimal system deps needed for builds and runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential ca-certificates curl gnupg2 && \
    rm -rf /var/lib/apt/lists/*

# Ensure pip/wheel/setuptools are pinned to patched versions at build time
# - pip==26.0 addresses pip CVEs
# - wheel==0.46.2 addresses wheel CVE
# - setuptools upgraded to latest stable
RUN python -m pip install --upgrade --no-cache-dir pip==26.0 \
    && python -m pip install --upgrade --no-cache-dir wheel==0.46.2 setuptools

# Copy requirements first to leverage Docker layer caching
COPY requirements.txt /app/requirements.txt

# Install Python dependencies from requirements.txt
# Use --no-cache-dir to avoid leaving caches in the image
RUN python -m pip install --no-cache-dir -r /app/requirements.txt

# Copy application code
COPY gateway.py /app/gateway.py

# Expose port and set env
ENV PYTHONUNBUFFERED=1
EXPOSE 8080

# Default command
CMD ["python", "/app/gateway.py"]
