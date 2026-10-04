FROM python:3.12-alpine@sha256:0687a6bc9716edc2a6ee0fbfb0f87e7ee358b262b67c9215de91bc9b2d38ba71

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DATA_DIR=/app/data \
    OUTPUT_DIR=/app/output \
    WEB_HOST=0.0.0.0 \
    WEB_PORT=8787 \
    WAITRESS_THREADS=6 \
    RTP2HTTPD_PORT=5140 \
    CAPTURE_SECONDS=30 \
    MAX_TIMED_CAPTURE_SECONDS=3600 \
    MIN_PACKET_COUNT=3 \
    PROBE_TIMEOUT_SECONDS=10 \
    PROBE_ANALYZE_DURATION_US=8000000 \
    PROBE_SIZE_BYTES=8000000 \
    PROBE_BUFFER_SIZE=131072

RUN apk add --no-cache \
      tcpdump \
      iproute2 \
      ffmpeg \
      ca-certificates \
      tzdata \
    && mkdir -p /app/data /app/output /app/services /app/templates /app/static

WORKDIR /app
COPY requirements.txt requirements.lock /app/
RUN pip install --no-cache-dir --require-hashes -r /app/requirements.lock

COPY app.py config.py models.py utils.py /app/
COPY services /app/services
COPY tools /app/tools
COPY templates /app/templates
COPY static /app/static

EXPOSE 8787
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 CMD python3 -c 'import os, urllib.request; urllib.request.urlopen("http://127.0.0.1:%s/api/health" % os.environ.get("WEB_PORT", "8787"), timeout=3).read()' || exit 1
CMD ["python3", "/app/app.py"]
