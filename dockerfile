# Use official Python image as base
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Update package list and install system dependencies
RUN apt-get update && \
    apt-get install -y \
        build-essential \
        python3-dev             \
        pkg-config               \
        libxml2-dev               \
        libxslt1-dev              \
        libxmlsec1-dev            \
        libxmlsec1-openssl        \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements if present
COPY requirements.txt .

# Install dependencies if requirements.txt exists
RUN if [ -f requirements.txt ]; then \
      pip install --no-cache-dir --no-binary lxml,xmlsec -r requirements.txt; \
    fi

# Copy project files
COPY . .

# Expose port (change if your app uses a different port)
EXPOSE 5000

# Set default command (update as needed for your app)
CMD ["python", "app.py"]