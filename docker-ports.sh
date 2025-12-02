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

# Check if Caddy is running
CADDY_RUNNING=false
if docker ps --format '{{.Names}}' | grep -q "cloudclear-caddy"; then
    CADDY_RUNNING=true
fi

# Get ports from docker
echo -e "${GREEN}Current Port Mappings:${NC}"
echo ""

if [ "$CADDY_RUNNING" = true ]; then
    # Caddy mode
    echo -e "${CYAN}Mode: Caddy Reverse Proxy${NC}"
    echo ""

    # Get HTTP port from Caddy
    HTTP_PORT=$(docker port cloudclear-caddy 2>/dev/null | grep "80/tcp" | cut -d: -f2 | head -1)
    if [ -n "$HTTP_PORT" ]; then
        echo -e "  HTTP Port (Caddy):  ${BLUE}${HTTP_PORT}${NC}"
        echo -e "    → ${CYAN}http://localhost:${HTTP_PORT}${NC}"
    fi

    echo ""

    # Get HTTPS port from Caddy
    HTTPS_PORT=$(docker port cloudclear-caddy 2>/dev/null | grep "443/tcp" | cut -d: -f2 | head -1)
    if [ -n "$HTTPS_PORT" ]; then
        echo -e "  HTTPS Port (Caddy): ${BLUE}${HTTPS_PORT}${NC}"
        echo -e "    → ${CYAN}https://localhost:${HTTPS_PORT}${NC}"
    fi

    echo ""
    echo -e "${YELLOW}Direct API Access (fallback):${NC}"
else
    # Direct API mode
    echo -e "${CYAN}Mode: Direct API Access (Caddy Disabled)${NC}"
    echo ""
fi

# Get direct API port
API_DIRECT_PORT=$(docker port cloudclear-api 2>/dev/null | grep "8080/tcp" | cut -d: -f2 | head -1)
if [ -n "$API_DIRECT_PORT" ]; then
    echo -e "  API Port (Direct): ${BLUE}${API_DIRECT_PORT}${NC}"
    echo -e "    → ${CYAN}http://localhost:${API_DIRECT_PORT}${NC}"
fi

echo ""
echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║                    QUICK LINKS                             ║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

if [ "$CADDY_RUNNING" = true ] && [ -n "$HTTP_PORT" ]; then
    echo -e "Web Interface:     ${BLUE}http://localhost:${HTTP_PORT}${NC}"
    echo -e "API Health (Caddy): ${BLUE}http://localhost:${HTTP_PORT}/health${NC}"
    echo -e "API Endpoint (Caddy): ${BLUE}http://localhost:${HTTP_PORT}/api/${NC}"
    if [ -n "$HTTPS_PORT" ]; then
        echo -e "Web Interface (HTTPS): ${BLUE}https://localhost:${HTTPS_PORT}${NC}"
    fi
    echo ""
fi

if [ -n "$API_DIRECT_PORT" ]; then
    echo -e "API Direct Access: ${BLUE}http://localhost:${API_DIRECT_PORT}${NC}"
    echo -e "API Health (Direct): ${BLUE}http://localhost:${API_DIRECT_PORT}/health${NC}"
    echo -e "API Endpoint (Direct): ${BLUE}http://localhost:${API_DIRECT_PORT}/api/${NC}"
fi

echo ""

# Check if .docker-ports file exists
if [ -f ".docker-ports" ]; then
    echo -e "${GREEN}Saved ports from startup:${NC}"
    MODE=$(sed -n '3p' .docker-ports 2>/dev/null || echo "")
    if [ "$MODE" = "caddy" ]; then
        HTTP_SAVED=$(sed -n '1p' .docker-ports)
        HTTPS_SAVED=$(sed -n '2p' .docker-ports)
        echo -e "  HTTP:  ${BLUE}${HTTP_SAVED}${NC} (via Caddy)"
        echo -e "  HTTPS: ${BLUE}${HTTPS_SAVED}${NC} (via Caddy)"
    elif [ "$MODE" = "direct" ]; then
        API_SAVED=$(sed -n '1p' .docker-ports)
        echo -e "  API:   ${BLUE}${API_SAVED}${NC} (direct access)"
    fi
fi

