FROM python:3.12-slim

WORKDIR /app

# System deps (libpq for asyncpg)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq-dev gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p logs

# CMD is overridden per-service in docker-compose.yml
CMD ["python", "honeypot.py"]
