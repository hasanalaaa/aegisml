FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y gcc libpq-dev curl && rm -rf /var/lib/apt/lists/*

# Install Astral's uv for ultra-fast, zero-backtracking dependency resolution
RUN pip install uv==0.2.13

# Copy requirements FIRST to lock Docker cache
COPY requirements.txt .

# Use uv to install requirements instantly instead of standard pip
RUN uv pip install --system --no-cache -r requirements.txt

# Copy application source
COPY . .

# CRITICAL FIX: Install the project itself to resolve pyproject.toml dependencies (stripe, resend, etc.)
RUN uv pip install --system --no-cache .

# Start the engine
CMD alembic upgrade head && uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000} --workers 4
