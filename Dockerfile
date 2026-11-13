# =============================================================================
# Bastion-Core — Hardened Production Dockerfile (Python 3.12-slim, Non-Root)
# =============================================================================
# Sub-60MB RAM footprint, Zero External DB, Non-Root Daemon
# =============================================================================

FROM python:3.12-slim

WORKDIR /app

# Install system tools and non-root user
RUN apt-get update && \
    apt-get install -y --no-install-recommends iputils-ping && \
    rm -rf /var/lib/apt/lists/* && \
    groupadd -g 10001 bastion && \
    useradd -u 10001 -g bastion -s /bin/sh -m bastion

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY adapters/ ./adapters/
COPY config/ ./config/
COPY core/ ./core/
COPY service/ ./service/
COPY telemetry/ ./telemetry/
COPY web/ ./web/
COPY bastion_main.py .
COPY main.py .

RUN chown -R bastion:bastion /app
USER bastion

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=5055

EXPOSE 5055

CMD ["python", "bastion_main.py"]
