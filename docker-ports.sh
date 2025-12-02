#!/bin/bash
#
# CloudClear Docker Port Display Script
# Shows the currently assigned ports for CloudClear containers
#

# Colors for output
CYAN='\033[0;36m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║              CloudClear Port Information                  ║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Check if containers are running
if ! docker ps --format '{{.Names}}' | grep -q "cloudclear-api"; then
    echo -e "${YELLOW}No CloudClear containers are currently running.${NC}"
    echo ""
    echo -e "Start containers with: ${GREEN}./docker-start.sh${NC}"
    exit 0
fi

# Get API port (always available)
API_PORT=$(docker port cloudclear-api 2>/dev/null | grep "8080/tcp" | cut -d: -f2 | head -1)

# Check if Caddy is also running
CADDY_RUNNING=false
if docker ps --format '{{.Names}}' | grep -q "cloudclear-caddy"; then
    CADDY_RUNNING=true
fi

echo -e "${GREEN}Current Port Mappings:${NC}"
echo ""

# Always show API port first
if [ -n "$API_PORT" ]; then
    echo -e "${GREEN}API Access:${NC}"
    echo -e "  Port: ${BLUE}${API_PORT}${NC}"
    echo -e "    → ${CYAN}http://localhost:${API_PORT}${NC}"
    echo ""
fi

if [ "$CADDY_RUNNING" = true ]; then
    echo -e "${CYAN}Caddy Reverse Proxy: ${GREEN}Running${NC}"

    # Get HTTP port from Caddy
    HTTP_PORT=$(docker port cloudclear-caddy 2>/dev/null | grep "80/tcp" | cut -d: -f2 | head -1)
    if [ -n "$HTTP_PORT" ]; then
        echo -e "  HTTP:  ${BLUE}${HTTP_PORT}${NC} → ${CYAN}http://localhost:${HTTP_PORT}${NC}"
    fi

    # Get HTTPS port from Caddy
    HTTPS_PORT=$(docker port cloudclear-caddy 2>/dev/null | grep "443/tcp" | cut -d: -f2 | head -1)
    if [ -n "$HTTPS_PORT" ]; then
        echo -e "  HTTPS: ${BLUE}${HTTPS_PORT}${NC} → ${CYAN}https://localhost:${HTTPS_PORT}${NC}"
    fi
else
    echo -e "${CYAN}Caddy Reverse Proxy: ${YELLOW}Not running${NC}"
    echo -e "  Enable with: ${CYAN}USE_CADDY=1 ./docker-start.sh${NC}"
fi

echo ""
echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║                    QUICK LINKS                             ║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

if [ -n "$API_PORT" ]; then
    echo -e "API:        ${BLUE}http://localhost:${API_PORT}${NC}"
    echo -e "Health:     ${BLUE}http://localhost:${API_PORT}/health${NC}"
    echo -e "Endpoint:   ${BLUE}http://localhost:${API_PORT}/api/${NC}"
fi

if [ "$CADDY_RUNNING" = true ] && [ -n "$HTTP_PORT" ]; then
    echo ""
    echo -e "Web UI:     ${BLUE}http://localhost:${HTTP_PORT}${NC}"
    if [ -n "$HTTPS_PORT" ]; then
        echo -e "Web UI (HTTPS): ${BLUE}https://localhost:${HTTPS_PORT}${NC}"
    fi
fi

echo ""

# Check if .docker-ports file exists
if [ -f ".docker-ports" ]; then
    echo -e "${GREEN}Saved ports from startup:${NC}"
    API_SAVED=$(sed -n '1p' .docker-ports)
    echo -e "  API: ${BLUE}${API_SAVED}${NC}"

    MODE=$(tail -1 .docker-ports 2>/dev/null || echo "")
    if [ "$MODE" = "caddy" ]; then
        HTTP_SAVED=$(sed -n '2p' .docker-ports)
        HTTPS_SAVED=$(sed -n '3p' .docker-ports)
        echo -e "  Caddy HTTP:  ${BLUE}${HTTP_SAVED}${NC}"
        echo -e "  Caddy HTTPS: ${BLUE}${HTTPS_SAVED}${NC}"
    fi
fi

