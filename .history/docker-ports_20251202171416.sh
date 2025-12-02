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
if ! docker ps --format '{{.Names}}' | grep -q "cloudclear-caddy\|cloudclear-api"; then
    echo -e "${YELLOW}No CloudClear containers are currently running.${NC}"
    echo ""
    echo -e "Start containers with: ${GREEN}./docker-start.sh${NC}"
    exit 0
fi

# Get ports from docker
echo -e "${GREEN}Current Port Mappings:${NC}"
echo ""

# Get HTTP port
HTTP_PORT=$(docker port cloudclear-caddy 2>/dev/null | grep "80/tcp" | cut -d: -f2 | head -1)
if [ -n "$HTTP_PORT" ]; then
    echo -e "  HTTP Port:  ${BLUE}${HTTP_PORT}${NC}"
    echo -e "    → ${CYAN}http://localhost:${HTTP_PORT}${NC}"
else
    echo -e "  ${YELLOW}HTTP port not found${NC}"
fi

echo ""

# Get HTTPS port
HTTPS_PORT=$(docker port cloudclear-caddy 2>/dev/null | grep "443/tcp" | cut -d: -f2 | head -1)
if [ -n "$HTTPS_PORT" ]; then
    echo -e "  HTTPS Port: ${BLUE}${HTTPS_PORT}${NC}"
    echo -e "    → ${CYAN}https://localhost:${HTTPS_PORT}${NC}"
else
    echo -e "  ${YELLOW}HTTPS port not found${NC}"
fi

echo ""
echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║                    QUICK LINKS                             ║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

if [ -n "$HTTP_PORT" ]; then
    echo -e "Web Interface:     ${BLUE}http://localhost:${HTTP_PORT}${NC}"
    echo -e "API Health:         ${BLUE}http://localhost:${HTTP_PORT}/health${NC}"
    echo -e "API Endpoint:       ${BLUE}http://localhost:${HTTP_PORT}/api/${NC}"
fi

if [ -n "$HTTPS_PORT" ]; then
    echo -e "Web Interface (HTTPS): ${BLUE}https://localhost:${HTTPS_PORT}${NC}"
fi

echo ""

# Check if .docker-ports file exists
if [ -f ".docker-ports" ]; then
    echo -e "${GREEN}Saved ports from startup:${NC}"
    HTTP_SAVED=$(sed -n '1p' .docker-ports)
    HTTPS_SAVED=$(sed -n '2p' .docker-ports)
    echo -e "  HTTP:  ${BLUE}${HTTP_SAVED}${NC}"
    echo -e "  HTTPS: ${BLUE}${HTTPS_SAVED}${NC}"
fi

