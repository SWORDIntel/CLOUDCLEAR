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

# Check if Caddy should be enabled (default: enabled, set USE_CADDY=0 to disable)
USE_CADDY=${USE_CADDY:-1}
CADDY_PROFILE=""

if [ "$USE_CADDY" = "1" ] || [ "$USE_CADDY" = "true" ]; then
    echo -e "${CYAN}Mode: ${GREEN}Caddy Reverse Proxy Enabled${NC}"
    CADDY_PROFILE="--profile caddy"

    # Find available ports for Caddy
    echo -e "${YELLOW}Finding available ports for Caddy...${NC}"
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
else
    echo -e "${CYAN}Mode: ${YELLOW}Direct API Access (Caddy Disabled)${NC}"
    echo -e "${YELLOW}Finding available port for direct API access...${NC}"

    # Find port for direct API access
    API_DIRECT_PORT=$(find_available_port 8000 9000)
    export API_DIRECT_PORT=$API_DIRECT_PORT

    echo -e "${GREEN}✓ Found available port:${NC}"
    echo -e "  API Port:   ${CYAN}${API_DIRECT_PORT}${NC}"
    echo ""
fi

# Stop any existing containers
echo -e "${YELLOW}Stopping any existing containers...${NC}"
$DOCKER_COMPOSE_CMD down 2>/dev/null || true
set -e

# Start containers
echo -e "${YELLOW}Starting CloudClear containers...${NC}"
if [ -n "$CADDY_PROFILE" ]; then
    $DOCKER_COMPOSE_CMD $CADDY_PROFILE up -d --build
else
    $DOCKER_COMPOSE_CMD up -d --build cloudclear-api
fi

# Wait for containers to be ready
echo -e "${YELLOW}Waiting for services to start...${NC}"
sleep 5

# Check container status
if $DOCKER_COMPOSE_CMD ps | grep -q "Up"; then
    echo -e "${GREEN}✓ Containers started successfully!${NC}"
    echo ""

    # Display port information based on mode
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                    ACCESS INFORMATION                      ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    if [ "$USE_CADDY" = "1" ] || [ "$USE_CADDY" = "true" ]; then
        # Caddy mode - show web interface and API through Caddy
        echo -e "${GREEN}Web Interface (HTTP):${NC}"
        echo -e "  ${BLUE}http://localhost:${HTTP_PORT}${NC}"
        echo ""
        echo -e "${GREEN}Web Interface (HTTPS):${NC}"
        echo -e "  ${BLUE}https://localhost:${HTTPS_PORT}${NC}"
        echo ""
        echo -e "${GREEN}API Health Check (via Caddy):${NC}"
        echo -e "  ${BLUE}http://localhost:${HTTP_PORT}/health${NC}"
        echo ""
        echo -e "${GREEN}API Endpoint (via Caddy):${NC}"
        echo -e "  ${BLUE}http://localhost:${HTTP_PORT}/api/${NC}"
        echo ""
        echo -e "${YELLOW}Direct API Access (fallback):${NC}"
        echo -e "  ${BLUE}http://localhost:$(docker port cloudclear-api 8080/tcp 2>/dev/null | cut -d: -f2 || echo 'N/A')${NC}"

        # Save ports
        echo "$HTTP_PORT" > .docker-ports
        echo "$HTTPS_PORT" >> .docker-ports
        echo "caddy" >> .docker-ports
    else
        # Direct API mode - get actual assigned port from Docker
        ACTUAL_API_PORT=$(docker port cloudclear-api 2>/dev/null | grep "8080/tcp" | cut -d: -f2 | head -1)
        if [ -z "$ACTUAL_API_PORT" ]; then
            ACTUAL_API_PORT=$API_DIRECT_PORT
        fi

        # Direct API mode - show direct API access
        echo -e "${GREEN}API Direct Access:${NC}"
        echo -e "  ${BLUE}http://localhost:${ACTUAL_API_PORT}${NC}"
        echo ""
        echo -e "${GREEN}API Health Check:${NC}"
        echo -e "  ${BLUE}http://localhost:${ACTUAL_API_PORT}/health${NC}"
        echo ""
        echo -e "${GREEN}API Endpoint:${NC}"
        echo -e "  ${BLUE}http://localhost:${ACTUAL_API_PORT}/api/${NC}"
        echo ""
        echo -e "${YELLOW}Note:${NC} Caddy reverse proxy is disabled. Web UI not available."
        echo -e "      Enable with: ${CYAN}USE_CADDY=1 ./docker-start.sh${NC}"

        # Save port
        echo "$ACTUAL_API_PORT" > .docker-ports
        echo "direct" >> .docker-ports
    fi

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

else
    echo -e "${RED}✗ Failed to start containers${NC}"
    echo -e "${YELLOW}Checking logs...${NC}"
    $DOCKER_COMPOSE_CMD logs --tail=20
    exit 1
fi

