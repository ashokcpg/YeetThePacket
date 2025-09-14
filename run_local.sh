#!/bin/bash

# Packet-to-Prompt Local Development Setup
echo "🚀 Starting Packet-to-Prompt Application"

# Check if .env file exists
if [ ! -f .env ]; then
    echo "⚠️  Creating .env file from template..."
    cp env.example .env
    echo "📝 Please edit .env file with your API keys before running again"
    exit 1
fi

# Create directories if they don't exist
mkdir -p data output

echo "📦 Building and starting Docker containers..."
docker-compose up --build

echo "✅ Application should be available at:"
echo "   🌐 Frontend (Streamlit): http://localhost:8501"
echo "   🔗 Backend API: http://localhost:8000"
echo "   📚 API Docs: http://localhost:8000/docs" 