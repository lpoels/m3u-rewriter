# Use an official slim Python base
FROM python:3.11-slim

# Set working dir
WORKDIR /app

# Install minimal system deps needed for builds and runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential ca-certificates curl gnupg2 gosu && \
    rm -rf /var/lib/apt/lists/*

# Ensure pip/wheel/setuptools are pinned to patched versions at build time
# - pip==26.0 addresses pip CVEs
# - wheel==0.46.2 addresses wheel CVE
# - setuptools upgraded to latest stable
RUN python -m pip install --upgrade --no-cache-dir pip==26.0 \
    && python -m pip install --upgrade --no-cache-dir wheel==0.46.2 setuptools

# Create non-root user
RUN groupadd -r app && useradd -r -g app -m -d /home/app app

# Copy requirements first to leverage Docker layer caching
COPY requirements.txt /app/requirements.txt

# Install Python dependencies from requirements.txt
# Use --no-cache-dir to avoid leaving caches in the image
RUN python -m pip install --no-cache-dir -r /app/requirements.txt

# Copy application code
COPY gateway.py /app/gateway.py

# Ensure /output exists (ownership will be fixed at runtime)
RUN mkdir -p /output

# Copy entrypoint to drop privileges after fixing /output perms
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Expose port and set env
ENV PYTHONUNBUFFERED=1
EXPOSE 8080

# Use entrypoint to chown /output (if root) then drop to app user
ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["python", "/app/gateway.py"]
