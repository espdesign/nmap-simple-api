# Use official Python image as base
FROM python:3.11-slim

# Install nmap
RUN apt-get update && \
    apt-get install -y nmap && \
    rm -rf /var/lib/apt/lists/*

# Set work directory
WORKDIR /app

# Copy requirements.txt and install dependencies
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt



# Copy the rest of the application
COPY . .

# Create a non-root user and group
RUN groupadd -r appuser && useradd -r -g appuser appuser

# Ensure logs directory exists and is owned by the non-root user (after COPY)
RUN mkdir -p /app/logs && chown -R appuser:appuser /app/logs

# Switch to non-root user
USER appuser


# Expose port for FastAPI
EXPOSE 5000

# Run both the FastAPI app and the daily scan script
CMD ["/bin/sh", "-c", "python daily_scan.py & exec uvicorn app:app --host 0.0.0.0 --port 5000"]
