FROM python:3.9-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    tshark \
    tcpdump \
    net-tools \
    wget \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements file
COPY backend/requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY backend/ ./backend/
COPY frontend/ ./frontend/
COPY data/ ./data/
COPY env.example ./.env

# Create output directory
RUN mkdir -p ./output

# Expose ports
EXPOSE 8000 8501

# Set environment variables
ENV PYTHONPATH=/app
ENV DATA_DIR=/app/data
ENV OUTPUT_DIR=/app/output

# Create startup script
RUN echo '#!/bin/bash\n\
    cd /app\n\
    echo "Starting backend API server..."\n\
    python backend/app.py &\n\
    sleep 5\n\
    echo "Starting Streamlit frontend..."\n\
    streamlit run frontend/streamlit_app.py --server.port=8501 --server.address=0.0.0.0\n\
    ' > /app/start.sh && chmod +x /app/start.sh

# Default command
CMD ["/app/start.sh"] 