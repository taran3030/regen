FROM ubuntu:24.04

RUN apt-get update && apt-get install -y \
    nmap \
    python3 \
    python3-pip \
    python3-venv \
    curl \
    wget \
    git \
    jq \
    chromium-browser \
    && rm -rf /var/lib/apt/lists/*

RUN curl -sL https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_linux_amd64.zip -o /tmp/nuclei.zip \
    && unzip /tmp/nuclei.zip -d /usr/local/bin/ \
    && rm /tmp/nuclei.zip \
    && nuclei -update-templates

RUN pip3 install --break-system-packages osv-scanner

WORKDIR /regen
COPY engine/ ./engine/
COPY scanners/ ./scanners/
COPY skills/ ./skills/

ENTRYPOINT ["python3", "-m", "engine"]
