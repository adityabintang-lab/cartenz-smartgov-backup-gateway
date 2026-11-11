FROM python:3.11-slim

# Install system dependencies & curl untuk healthcheck
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Buat non-root user untuk keamanan container
RUN groupadd -g 1000 smartgov && \
    useradd -u 1000 -g smartgov -m -s /bin/bash smartgov

# Install dependensi Python
RUN pip install --no-cache-dir \
    fastapi>=0.110.0 \
    "uvicorn[standard]>=0.28.0" \
    cos-python-sdk-v5>=1.9.30 \
    slowapi>=0.1.9 \
    python-multipart>=0.0.9

# Salin kode aplikasi gateway
COPY ui_gateway.py /app/ui_gateway.py

# Buat direktori data persisten dan sesuaikan permission
RUN mkdir -p /app/data && \
    chown -R smartgov:smartgov /app

USER smartgov

# Port diselaraskan ke 25100
EXPOSE 25100

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD curl -f http://127.0.0.1:25100/healthz || exit 1

CMD ["uvicorn", "ui_gateway:app", "--host", "0.0.0.0", "--port", "25100"]
