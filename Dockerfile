# -----------------------
# Stage 1: Python Builder
# -----------------------
    FROM python:3.12-slim AS builder

    WORKDIR /app
    
    # Environment
    ENV PYTHONUNBUFFERED=1 \
        PYTHONDONTWRITEBYTECODE=1
    
    # Install build dependencies
    RUN apt-get update && \
        apt-get install -y --no-install-recommends \
        gcc \
        python3-dev \
        libpq-dev && \
        rm -rf /var/lib/apt/lists/*
    
    RUN python -m venv /opt/venv
    ENV PATH="/opt/venv/bin:$PATH"
    
    COPY requirements.txt .
    RUN pip install --no-cache-dir --upgrade pip && \
        pip install --no-cache-dir -r requirements.txt
    
    # -----------------------
    # Stage 2: Runtime Image
    # -----------------------
    FROM python:3.12-slim AS runtime
    
    WORKDIR /app
    
    # Environment
    ENV PYTHONUNBUFFERED=1 \
        PYTHONDONTWRITEBYTECODE=1 \
        VIRTUAL_ENV="/opt/venv" \
        PATH="/opt/venv/bin:/root/go/bin:$PATH"
    
    # Install runtime tools & dependencies
    RUN apt-get update && \
        apt-get install -y --no-install-recommends \
        nmap \
        curl \
        golang-go \
        ca-certificates \
        libyaml-dev \
        ruby \
        ruby-dev \
        build-essential \
        git && \
        git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap && \
        apt-get clean && \
        rm -rf /var/lib/apt/lists/*

    #to run sql map directly
    RUN ln -s /opt/sqlmap/sqlmap.py /usr/local/bin/sqlmap && \
    chmod +x /usr/local/bin/sqlmap

    
    # ✅ Install Go tools
    RUN go install github.com/lc/gau@latest && \
        go install github.com/tomnomnom/waybackurls@latest
    
    # ✅ Copy Python virtual environment from builder
    COPY --from=builder /opt/venv /opt/venv
    
    # ✅ Copy application source code
    COPY . .
    
    # ✅ Start FastAPI app with Uvicorn
    #CMD ["uvicorn", "app.app:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
    CMD ["gunicorn", "app.app:app", "-k", "uvicorn.workers.UvicornWorker", "-b", "0.0.0.0:8000", "--workers", "8", "--log-level", "info","--timeout", "900"]
