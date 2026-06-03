# Minimal, offline-capable image for running the scanner in CI or air-gapped
# environments. Builds with only the two runtime deps; no network access is
# needed at run time for the stub target.
FROM python:3.11-slim

# Don't write .pyc files; flush stdout/stderr immediately (clean CI logs).
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install dependencies first for better layer caching.
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Install the package itself.
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir .

# Run as a non-root user.
RUN useradd --create-home --uid 10001 scanner
USER scanner

# `docker run ... run --target stub --out /app/reports`
ENTRYPOINT ["llm-scan"]
CMD ["run", "--target", "stub", "--out", "/app/reports"]
