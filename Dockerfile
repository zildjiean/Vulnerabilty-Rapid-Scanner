FROM python:3.12-slim

ARG APP_VERSION=1.7.0
LABEL org.opencontainers.image.title="0-Day Rapid Scanner" \
      org.opencontainers.image.version="${APP_VERSION}" \
      org.opencontainers.image.source="https://github.com/zildjiean/Vulnerabilty-Rapid-Scanner" \
      org.opencontainers.image.licenses="MIT"

ARG NUCLEI_VERSION=3.11.1
ARG SUBFINDER_VERSION=2.17.0
ARG HTTPX_VERSION=1.12.0
# SHA-256 of each release zip, from the release's *_checksums.txt; bump them together with the versions.
ARG NUCLEI_SHA256_AMD64=ea63d4ae232808cd7c6bc00d0142428e231fab59dae01042246097d195835ab6
ARG NUCLEI_SHA256_ARM64=8044e3d9768ba0a744b2872c1a87e813006f013da97ca9f50f7661a4203bec07
ARG SUBFINDER_SHA256_AMD64=a39c3e5c7a26ef3c430915c4d6cbf7716a00f26769a75e9405aba796142eba37
ARG SUBFINDER_SHA256_ARM64=24913d49dddc1d3a5e99a4a7580da5be980959b9415b96f52c4f7f4124392190
ARG HTTPX_SHA256_AMD64=9d8439e8b6c9aa7d1e2314817a392e00d5178da3af5652f7475f88868f418f76
ARG HTTPX_SHA256_ARM64=fd7b123c1dfbc3d69f19f524e4eebcd6ec06b9a6cbd56813c76f11645197331e

RUN apt-get update \
 && apt-get install -y --no-install-recommends nmap ca-certificates curl unzip libcap2-bin git \
 && rm -rf /var/lib/apt/lists/*

RUN ARCH="$(dpkg --print-architecture)" \
 && case "$ARCH" in \
      amd64) NARCH=amd64; NUCLEI_SHA256="$NUCLEI_SHA256_AMD64"; SUBFINDER_SHA256="$SUBFINDER_SHA256_AMD64"; HTTPX_SHA256="$HTTPX_SHA256_AMD64" ;; \
      arm64) NARCH=arm64; NUCLEI_SHA256="$NUCLEI_SHA256_ARM64"; SUBFINDER_SHA256="$SUBFINDER_SHA256_ARM64"; HTTPX_SHA256="$HTTPX_SHA256_ARM64" ;; \
      *) echo "unsupported arch $ARCH" && exit 1 ;; \
    esac \
 && curl -fsSL -o /tmp/nuclei.zip "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${NARCH}.zip" \
 && curl -fsSL -o /tmp/subfinder.zip "https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION}_linux_${NARCH}.zip" \
 && curl -fsSL -o /tmp/httpx.zip "https://github.com/projectdiscovery/httpx/releases/download/v${HTTPX_VERSION}/httpx_${HTTPX_VERSION}_linux_${NARCH}.zip" \
 && printf '%s  %s\n' "$NUCLEI_SHA256" /tmp/nuclei.zip "$SUBFINDER_SHA256" /tmp/subfinder.zip "$HTTPX_SHA256" /tmp/httpx.zip \
    | sha256sum --strict -c - \
 && mkdir -p /opt/nuclei && unzip -q /tmp/nuclei.zip nuclei -d /opt/nuclei && rm /tmp/nuclei.zip \
 && chmod +x /opt/nuclei/nuclei \
 && mkdir -p /opt/pd && unzip -q /tmp/subfinder.zip subfinder -d /opt/pd && unzip -q /tmp/httpx.zip httpx -d /opt/pd \
 && rm /tmp/subfinder.zip /tmp/httpx.zip && chmod +x /opt/pd/subfinder /opt/pd/httpx \
 && useradd -r -u 10001 -d /data -s /usr/sbin/nologin scanner \
 && mkdir -p /data && chown -R scanner:scanner /data /opt/nuclei /opt/pd \
 && setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip /usr/bin/nmap

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app

ENV DATA_DIR=/data \
    HOME=/data \
    NMAP_BIN=/usr/bin/nmap \
    NUCLEI_BIN=/opt/nuclei/nuclei \
    SUBFINDER_BIN=/opt/pd/subfinder \
    HTTPX_BIN=/opt/pd/httpx \
    NUCLEI_TEMPLATES_DIR=/data/nuclei-templates \
    PYTHONUNBUFFERED=1

USER scanner
EXPOSE 8000
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s CMD curl -fsS http://127.0.0.1:8000/healthz || exit 1
CMD ["uvicorn", "app.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers"]
