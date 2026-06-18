FROM python:3.11-slim

LABEL maintainer="IDS Platform"
LABEL description="AI-powered Intrusion Detection System"

# System dependencies (Scapy needs libpcap)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    tcpdump \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source
COPY . .

# Create data directory
RUN mkdir -p data/reports

# Pre-train the model at build time
RUN python -m ml.train --samples 10000 || echo "ML train skipped"

EXPOSE 5000

# Run with privileged networking for packet capture
CMD ["python", "-m", "api.app", "--interface", "eth0", "--port", "5000"]
