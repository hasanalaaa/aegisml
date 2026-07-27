# syntax=docker/dockerfile:1

FROM python:3.11-slim AS cli

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY aegisml_scanner ./aegisml_scanner
RUN python -m pip install --no-cache-dir . \
    && useradd --create-home --uid 10001 aegisml

USER aegisml
WORKDIR /work
ENTRYPOINT ["aegisml"]
CMD ["--help"]


FROM python:3.11-slim AS api

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    TMPDIR=/scan-jobs

WORKDIR /app
RUN apt-get update \
    && apt-get install --yes --no-install-recommends gcc libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY services/scan-engine/requirements.txt /tmp/requirements.txt
RUN python -m pip install --no-cache-dir --requirement /tmp/requirements.txt

# Install the same audited local scanner package used by the CLI.  The API
# service adapter imports it directly, so production images cannot silently
# fall back to the retired service-local implementation.
COPY pyproject.toml README.md LICENSE /tmp/aegisml-scanner/
COPY aegisml_scanner /tmp/aegisml-scanner/aegisml_scanner
RUN python -m pip install --no-cache-dir --no-deps /tmp/aegisml-scanner

COPY services/scan-engine /app
RUN useradd --create-home --uid 10001 aegisml \
    && mkdir -p /data /scan-jobs \
    && chown -R aegisml:aegisml /app /data /scan-jobs

USER aegisml
EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
