FROM python:3.11-slim

WORKDIR /app

# Install service dependencies first (layer caching)
COPY services/scan-engine/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy and install the aegisml package
COPY aegisml/ /app/aegisml_pkg/aegisml/
COPY pyproject.toml /app/aegisml_pkg/pyproject.toml
RUN pip install --no-cache-dir /app/aegisml_pkg

# Copy the scan engine service code
COPY services/scan-engine/ .

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
