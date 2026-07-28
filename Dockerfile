# Dockerfile skeleton (Phase 2 will flesh this out)
FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . /app
ENTRYPOINT ["python", "main.py"]
