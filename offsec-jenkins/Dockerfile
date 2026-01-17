FROM python:3.11-slim

LABEL maintainer="offsec-jenkins"
LABEL description="Jenkins Credential Decryptor for CTF and Red Team Operations"

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY decrypt.py .
COPY tests/ tests/
COPY test_fixtures/ test_fixtures/

# Create volume mount point for Jenkins files
RUN mkdir -p /data

# Set environment variable to skip venv (already in container)
ENV INSIDE_VENV=1

# Default command shows help
ENTRYPOINT ["python", "decrypt.py"]
CMD ["--help"]
