FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY pyproject.toml README.md ./
COPY gateway ./gateway
COPY agent ./agent
RUN pip install --no-cache-dir ".[dev]"

RUN useradd --create-home --uid 10001 app
USER app
