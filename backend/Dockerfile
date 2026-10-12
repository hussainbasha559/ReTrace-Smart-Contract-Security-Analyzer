FROM python:3.11-slim

# Install system dependencies.
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    build-essential \
    git \
    libssl-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Configure Rust and Cargo.
ENV RUSTUP_HOME=/usr/local/rustup
ENV CARGO_HOME=/usr/local/cargo
ENV PATH="/usr/local/cargo/bin:/root/.bifrost/bin:/usr/local/bin:$PATH"

# Install Rust.
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --profile minimal

# Install Heimdall.
RUN curl -L https://get.heimdall.rs | bash \
    && /root/.bifrost/bin/bifrost \
    && cp /root/.bifrost/bin/heimdall /usr/local/bin/heimdall

# Set backend working directory.
WORKDIR /app

# Install Python dependencies first.
COPY requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend application code.
COPY . .

# Ensure Python imports resolve from the backend directory.
ENV PYTHONPATH=/app

# Start FastAPI using Render's assigned port.
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000} --proxy-headers --forwarded-allow-ips=*"]
