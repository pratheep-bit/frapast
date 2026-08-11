# frapAST Docker Engine — Runtime-Proven Static Security Analysis for Frappe & ERPNext
FROM python:3.11-slim

LABEL org.opencontainers.image.title="frapAST Security Engine"
LABEL org.opencontainers.image.description="Runtime-proven SAST scanner for Frappe & ERPNext applications"
LABEL org.opencontainers.image.vendor="frapAST"
LABEL org.opencontainers.image.source="https://github.com/pratheep-bit/frapast"

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    gcc \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy project definition and source
COPY pyproject.toml README.md /app/
COPY scanner /app/scanner
COPY taxonomy /app/taxonomy

# Install frapAST CLI package
RUN pip install --no-cache-dir .

# Create workspace directory for mounted scans
WORKDIR /scan

# Entry point defaults to frapast executable
ENTRYPOINT ["frapast"]
CMD ["--help"]
