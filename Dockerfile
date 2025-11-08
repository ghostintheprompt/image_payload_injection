# ImageGuard - Production Dockerfile
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    imagemagick \
    exiftool \
    libmagic1 \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt gunicorn

# Copy application
COPY . .

# Create upload and result directories
RUN mkdir -p /tmp/ipi_uploads /tmp/ipi_results && \
    chmod 777 /tmp/ipi_uploads /tmp/ipi_results

# Expose port
EXPOSE 5000

# Set environment variables
ENV FLASK_APP=ipi.web_interface
ENV PYTHONUNBUFFERED=1

# Run with gunicorn for production
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "4", "--timeout", "120", "ipi.web_interface:app"]
