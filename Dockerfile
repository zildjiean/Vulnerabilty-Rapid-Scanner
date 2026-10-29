FROM python:3.12-slim

ARG NUCLEI_VERSION=3.8.0

RUN apt-get update \
 && apt-get install -y --no-install-recommends nmap ca-certificates curl unzip libcap2-bin git \
 && rm -rf /var/lib/apt/lists/*

RUN ARCH="$(dpkg --print-architecture)" \
 && case "$ARCH" in amd64) NARCH=amd64 ;; arm64) NARCH=arm64 ;; *) echo "unsupported arch $ARCH" && exit 1 ;; esac \
 && curl -fsSL -o /tmp/nuclei.zip "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${NARCH}.zip" \
 && mkdir -p /opt/nuclei && unzip -q /tmp/nuclei.zip nuclei -d /opt/nuclei && rm /tmp/nuclei.zip \
 && chmod +x /opt/nuclei/nuclei \
 && useradd -r -u 10001 -d /data -s /usr/sbin/nologin scanner \
 && mkdir -p /data && chown -R scanner:scanner /data /opt/nuclei \
 && setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip /usr/bin/nmap

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app

ENV DATA_DIR=/data \
    HOME=/data \
    NMAP_BIN=/usr/bin/nmap \
    NUCLEI_BIN=/opt/nuclei/nuclei \
    NUCLEI_TEMPLATES_DIR=/data/nuclei-templates \
    PYTHONUNBUFFERED=1

USER scanner
EXPOSE 8000
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s CMD curl -fsS http://127.0.0.1:8000/healthz || exit 1
CMD ["uvicorn", "app.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers"]
