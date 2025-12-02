#!/bin/bash
# CloudClear Simple API - Quick Test Script

set -e

echo "========================================="
echo "CloudClear Simple API - Quick Test"
echo "========================================="
echo

# Check if Docker is available
if ! command -v docker &> /dev/null; then
    echo "❌ Docker not found. Please install Docker first."
    exit 1
fi

# Check if docker-compose is available
if ! command -v docker-compose &> /dev/null; then
    echo "❌ docker-compose not found. Please install docker-compose first."
    exit 1
fi

# Build and start
echo "📦 Building Docker image..."
docker-compose -f docker-compose.simple.yml build

echo
echo "🚀 Starting Simple API..."
docker-compose -f docker-compose.simple.yml up -d

echo
echo "⏳ Waiting for API to be ready (10 seconds)..."
sleep 10

echo
echo "🏥 Testing health endpoint..."
if curl -f -s http://localhost:5000/health | jq .; then
    echo "✅ Health check passed!"
else
    echo "❌ Health check failed!"
    docker-compose -f docker-compose.simple.yml logs
    exit 1
fi

echo
echo "📋 Getting API documentation..."
curl -s http://localhost:5000/ | jq .

echo
echo "🔍 Testing scan endpoint (example.com)..."
echo "This may take 30-60 seconds..."
if curl -f -s "http://localhost:5000/api/scan?domain=example.com" | jq .; then
    echo "✅ Scan test passed!"
else
    echo "❌ Scan test failed!"
    docker-compose -f docker-compose.simple.yml logs
    exit 1
fi

echo
echo "========================================="
echo "✅ All tests passed!"
echo "========================================="
echo
echo "Simple API is running on http://localhost:5000"
echo
echo "Try these commands:"
echo "  curl http://localhost:5000/health"
echo "  curl \"http://localhost:5000/api/scan?domain=google.com\""
echo
echo "To stop:"
echo "  docker-compose -f docker-compose.simple.yml down"
echo

exit 0
