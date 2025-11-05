FROM python:3.13-slim

RUN apt-get update && \
    apt-get install -y tshark && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY app/requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY app/ .

COPY entrypoint.sh .
COPY .env-example .

RUN chmod +x entrypoint.sh

ENV INGEST_BASE_DIRECTORY=/data/ingest
ENV UPLOAD_DIRECTORY=/app/uploads

RUN mkdir -p /app/uploads

EXPOSE 8000

ENTRYPOINT ["/app/entrypoint.sh"]