FROM python:3.11-slim

# Ensure UTF-8 and no interactive prompts
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    RUN_SCHNORR_SERVER=1 \
    CHAL_HOST=0.0.0.0 \
    CHAL_PORT=1337

WORKDIR /app

# System deps (if any needed)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy only requirements first for layer caching
COPY requirements.txt ./
RUN pip install -r requirements.txt

# Copy server and flag
COPY server.py ./
COPY flag.py ./

# Expose the challenge port
EXPOSE 1337

# Run the server
CMD ["python", "server.py"]


