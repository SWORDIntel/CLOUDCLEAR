#!/bin/bash
#
# CloudClear Docker Startup Script
# Automatically assigns random available ports and displays them to the user
#

set -e
# Don't exit on errors for docker-compose down (containers may not exist)
set +e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Function to find an available port
find_available_port() {
    local min_port=${1:-8000}
    local max_port=${2:-65535}
    local port
    local max_attempts=100
    local attempt=0

    while [ $attempt -lt $max_attempts ]; do
        # Generate random port in range
        port=$((RANDOM % (max_port - min_port + 1) + min_port))

        # Check if port is available using multiple methods
        local port_in_use=false

        # Try lsof first (if available)
        if command -v lsof &> /dev/null; then
            if lsof -Pi :$port -sTCP:LISTEN -t >/dev/null 2>&1; then
                port_in_use=true
            fi
        # Try ss (modern Linux)
        elif command -v ss &> /dev/null; then
            if ss -lnt | grep -q ":$port "; then
                port_in_use=true
            fi
        # Try netstat (fallback)
        elif command -v netstat &> /dev/null; then
            if netstat -lnt 2>/dev/null | grep -q ":$port "; then
                port_in_use=true
            fi
        # Try simple connection test as last resort
        else
            if timeout 0.1 bash -c "echo > /dev/tcp/127.0.0.1/$port" 2>/dev/null; then
                port_in_use=true
            fi
        fi

        if [ "$port_in_use" = false ]; then
            echo $port
            return 0
        fi

        attempt=$((attempt + 1))
    done

    # If we couldn't find a port, use a fallback
    echo $((min_port + RANDOM % 1000))
}

# Function to check if docker-compose is available
check_docker_compose() {
    if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
        echo -e "${RED}Error: docker-compose not found${NC}"
        exit 1
    fi
}

# Function to get docker-compose command
get_docker_compose_cmd() {
    if docker compose version &> /dev/null; then
        echo "docker compose"
    else
        echo "docker-compose"
    fi
}

# Banner
echo -e "${CYAN}"
echo "╔════════════════════════════════════════════════════════════╗"
echo "║         CloudClear Docker Startup Script                  ║"
echo "║         Random Port Assignment & Auto-Display            ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check prerequisites
check_docker_compose
DOCKER_COMPOSE_CMD=$(get_docker_compose_cmd)

# Find available ports
echo -e "${YELLOW}Finding available ports...${NC}"
HTTP_PORT=$(find_available_port 8000 9000)
HTTPS_PORT=$(find_available_port 9000 10000)

# Ensure HTTPS port is different from HTTP port
while [ "$HTTPS_PORT" == "$HTTP_PORT" ]; do
    HTTPS_PORT=$(find_available_port 9000 10000)
done

echo -e "${GREEN}✓ Found available ports:${NC}"
echo -e "  HTTP Port:  ${CYAN}${HTTP_PORT}${NC}"
echo -e "  HTTPS Port: ${CYAN}${HTTPS_PORT}${NC}"
echo ""

# Export ports as environment variables
export CADDY_HTTP_PORT=$HTTP_PORT
export CADDY_HTTPS_PORT=$HTTPS_PORT

# Stop any existing containers
echo -e "${YELLOW}Stopping any existing containers...${NC}"
$DOCKER_COMPOSE_CMD down 2>/dev/null || true
set -e

# Start containers
echo -e "${YELLOW}Starting CloudClear containers...${NC}"
$DOCKER_COMPOSE_CMD up -d --build

# Wait for containers to be ready
echo -e "${YELLOW}Waiting for services to start...${NC}"
sleep 5

# Check container status
if $DOCKER_COMPOSE_CMD ps | grep -q "Up"; then
    echo -e "${GREEN}✓ Containers started successfully!${NC}"
    echo ""

    # Display port information
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                    ACCESS INFORMATION                      ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${GREEN}Web Interface (HTTP):${NC}"
    echo -e "  ${BLUE}http://localhost:${HTTP_PORT}${NC}"
    echo ""
    echo -e "${GREEN}Web Interface (HTTPS):${NC}"
    echo -e "  ${BLUE}https://localhost:${HTTPS_PORT}${NC}"
    echo ""
    echo -e "${GREEN}API Health Check:${NC}"
    echo -e "  ${BLUE}http://localhost:${HTTP_PORT}/health${NC}"
    echo ""
    echo -e "${GREEN}API Endpoint:${NC}"
    echo -e "  ${BLUE}http://localhost:${HTTP_PORT}/api/${NC}"
    echo ""
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                    QUICK COMMANDS                          ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "View logs:        ${YELLOW}$DOCKER_COMPOSE_CMD logs -f${NC}"
    echo -e "Stop containers:  ${YELLOW}$DOCKER_COMPOSE_CMD down${NC}"
    echo -e "Restart:          ${YELLOW}$DOCKER_COMPOSE_CMD restart${NC}"
    echo -e "Status:           ${YELLOW}$DOCKER_COMPOSE_CMD ps${NC}"
    echo ""
    echo -e "${GREEN}Ports saved to: ${CYAN}.docker-ports${NC}"
    echo "$HTTP_PORT" > .docker-ports
    echo "$HTTPS_PORT" >> .docker-ports

else
    echo -e "${RED}✗ Failed to start containers${NC}"
    echo -e "${YELLOW}Checking logs...${NC}"
    $DOCKER_COMPOSE_CMD logs --tail=20
    exit 1
fi

