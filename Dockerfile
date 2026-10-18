FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && groupadd --system agenttrust \
    && useradd --system \
        --gid agenttrust \
        --home-dir /app \
        --shell /usr/sbin/nologin \
        agenttrust \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=agenttrust:agenttrust . .

# The application creates SQLite databases relative to /app.
# Ensure the non-root user can create them and access dashboard files.
RUN chown agenttrust:agenttrust /app \
    && install -d -o agenttrust -g agenttrust /app/data /app/dashboard

USER agenttrust

EXPOSE 8000

CMD ["python", "-m", "uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8000"]
