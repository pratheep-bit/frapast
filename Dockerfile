FROM python:3.11-slim

LABEL org.opencontainers.image.title="frapAST Security Engine"
LABEL org.opencontainers.image.description="Runtime-proven SAST scanner for Frappe & ERPNext applications"
LABEL org.opencontainers.image.vendor="frapAST"
LABEL org.opencontainers.image.source="https://github.com/pratheep-bit/frapast"

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    gcc \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pyproject.toml README.md /app/
COPY scanner /app/scanner

RUN pip install --no-cache-dir .

RUN groupadd -r frapast && useradd -r -g frapast frapast
WORKDIR /scan
RUN chown frapast:frapast /scan
USER frapast

ENTRYPOINT ["frapast"]
CMD ["--help"]
