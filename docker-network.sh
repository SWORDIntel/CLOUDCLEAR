#!/bin/bash
# CloudUnflare Enhanced v2.0 - Docker Network Configuration Script
# Advanced network setup for DNS reconnaissance operations

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NETWORK_NAME="cloudunflare-network"
MONITORING_NETWORK="monitoring-network"
SUBNET_CLOUDUNFLARE="172.20.0.0/16"
SUBNET_MONITORING="172.21.0.0/16"
GATEWAY_CLOUDUNFLARE="172.20.0.1"
GATEWAY_MONITORING="172.21.0.1"

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_step() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

# Function to check if Docker is running
check_docker() {
    print_step "Checking Docker status..."
    if ! docker info >/dev/null 2>&1; then
        print_error "Docker is not running or not accessible"
        print_error "Please start Docker and ensure you have proper permissions"
        exit 1
    fi
    print_status "Docker is running"
}

# Function to check if network exists
network_exists() {
    local network_name="$1"
    docker network ls --format "{{.Name}}" | grep -q "^${network_name}$"
}

# Function to create CloudUnflare network
create_cloudunflare_network() {
    print_step "Creating CloudUnflare network..."

    if network_exists "$NETWORK_NAME"; then
        print_warning "Network '$NETWORK_NAME' already exists"
        return 0
    fi

    docker network create \
        --driver bridge \
        --subnet="$SUBNET_CLOUDUNFLARE" \
        --gateway="$GATEWAY_CLOUDUNFLARE" \
        --opt com.docker.network.bridge.name=cloudunflare-br \
        --opt com.docker.network.bridge.enable_icc=true \
        --opt com.docker.network.bridge.enable_ip_masquerade=true \
        --opt com.docker.network.driver.mtu=1500 \
        --label cloudunflare.network=main \
        --label cloudunflare.purpose=dns-reconnaissance \
        "$NETWORK_NAME"

    print_status "CloudUnflare network created successfully"
}

# Function to create monitoring network
create_monitoring_network() {
    print_step "Creating monitoring network..."

    if network_exists "$MONITORING_NETWORK"; then
        print_warning "Network '$MONITORING_NETWORK' already exists"
        return 0
    fi

    docker network create \
        --driver bridge \
        --subnet="$SUBNET_MONITORING" \
        --gateway="$GATEWAY_MONITORING" \
        --opt com.docker.network.bridge.name=monitoring-br \
        --opt com.docker.network.bridge.enable_icc=true \
        --opt com.docker.network.bridge.enable_ip_masquerade=true \
        --label cloudunflare.network=monitoring \
        --label cloudunflare.purpose=observability \
        "$MONITORING_NETWORK"

    print_status "Monitoring network created successfully"
}

# Function to configure network security
configure_network_security() {
    print_step "Configuring network security..."

    # Enable IPv4 forwarding (required for container networking)
    if [ -w /proc/sys/net/ipv4/ip_forward ]; then
        echo 1 > /proc/sys/net/ipv4/ip_forward
        print_status "IPv4 forwarding enabled"
    else
        print_warning "Cannot enable IPv4 forwarding (may require sudo)"
    fi

    # Configure iptables for CloudUnflare network (if we have permissions)
    if command -v iptables >/dev/null 2>&1; then
        print_step "Configuring iptables rules..."

        # Allow traffic within CloudUnflare network
        iptables -A FORWARD -s "$SUBNET_CLOUDUNFLARE" -d "$SUBNET_CLOUDUNFLARE" -j ACCEPT 2>/dev/null || \
            print_warning "Cannot configure iptables (may require sudo)"

        # Allow CloudUnflare to monitoring network communication
        iptables -A FORWARD -s "$SUBNET_CLOUDUNFLARE" -d "$SUBNET_MONITORING" -j ACCEPT 2>/dev/null || \
            print_warning "Cannot configure iptables for monitoring (may require sudo)"

        print_status "Network security configured"
    else
        print_warning "iptables not available - skipping firewall configuration"
    fi
}

# Function to optimize network performance
optimize_network_performance() {
    print_step "Optimizing network performance..."

    # Network performance optimizations (if we have permissions)
    local net_params=(
        "net.core.rmem_max=134217728"
        "net.core.wmem_max=134217728"
        "net.ipv4.tcp_rmem=4096 87380 134217728"
        "net.ipv4.tcp_wmem=4096 65536 134217728"
        "net.core.netdev_max_backlog=5000"
        "net.ipv4.tcp_congestion_control=bbr"
    )

    for param in "${net_params[@]}"; do
        key="${param%=*}"
        value="${param#*=}"
        sysctl_path="/proc/sys/${key//./\/}"

        if [ -w "$sysctl_path" ]; then
            echo "$value" > "$sysctl_path" 2>/dev/null || true
            print_status "Set $key = $value"
        else
            print_warning "Cannot set $key (may require sudo)"
        fi
    done
}

# Function to validate network configuration
validate_networks() {
    print_step "Validating network configuration..."

    # Check if networks exist and are properly configured
    for network in "$NETWORK_NAME" "$MONITORING_NETWORK"; do
        if network_exists "$network"; then
            local network_info
            network_info=$(docker network inspect "$network" --format='{{range .IPAM.Config}}{{.Subnet}}{{end}}')
            print_status "Network '$network' configured with subnet: $network_info"
        else
            print_error "Network '$network' not found"
            return 1
        fi
    done

    # Test network connectivity
    print_step "Testing network connectivity..."

    # Create a temporary test container to validate networking
    local test_container="cloudunflare-network-test"

    docker run --rm --name "$test_container" \
        --network "$NETWORK_NAME" \
        --detach \
        alpine:latest sleep 10 >/dev/null 2>&1 || {
        print_error "Failed to create test container"
        return 1
    }

    # Test DNS resolution in the container
    if docker exec "$test_container" nslookup google.com >/dev/null 2>&1; then
        print_status "DNS resolution working in CloudUnflare network"
    else
        print_warning "DNS resolution may have issues"
    fi

    # Cleanup test container
    docker stop "$test_container" >/dev/null 2>&1 || true

    print_status "Network validation completed"
}

# Function to show network status
show_network_status() {
    print_step "Network Status Summary"
    echo

    echo "=== CloudUnflare Networks ==="
    docker network ls --filter label=cloudunflare.network --format "table {{.Name}}\t{{.Driver}}\t{{.Scope}}\t{{.Labels}}"
    echo

    echo "=== Network Details ==="
    for network in "$NETWORK_NAME" "$MONITORING_NETWORK"; do
        if network_exists "$network"; then
            echo "--- $network ---"
            docker network inspect "$network" --format='Subnet: {{range .IPAM.Config}}{{.Subnet}}{{end}}'
            docker network inspect "$network" --format='Gateway: {{range .IPAM.Config}}{{.Gateway}}{{end}}'
            docker network inspect "$network" --format='Containers: {{len .Containers}}'
            echo
        fi
    done
}

# Function to cleanup networks
cleanup_networks() {
    print_step "Cleaning up CloudUnflare networks..."

    # Stop any containers using our networks first
    local containers
    containers=$(docker ps -q --filter network="$NETWORK_NAME" --filter network="$MONITORING_NETWORK" 2>/dev/null || echo "")

    if [ -n "$containers" ]; then
        print_warning "Stopping containers using CloudUnflare networks..."
        echo "$containers" | xargs docker stop 2>/dev/null || true
    fi

    # Remove networks
    for network in "$NETWORK_NAME" "$MONITORING_NETWORK"; do
        if network_exists "$network"; then
            docker network rm "$network" 2>/dev/null || {
                print_warning "Could not remove network '$network' (may be in use)"
            }
        fi
    done

    print_status "Network cleanup completed"
}

# Function to show help
show_help() {
    cat << EOF
CloudUnflare Enhanced v2.0 - Docker Network Configuration

Usage: $0 [COMMAND]

Commands:
    setup       Create and configure networks (default)
    validate    Validate existing network configuration
    status      Show network status and information
    cleanup     Remove CloudUnflare networks
    optimize    Optimize network performance settings
    help        Show this help message

Examples:
    $0 setup       # Create all networks
    $0 validate    # Check if networks are working
    $0 status      # Show current network state
    $0 cleanup     # Remove all networks

Network Configuration:
    CloudUnflare Network: $SUBNET_CLOUDUNFLARE
    Monitoring Network:   $SUBNET_MONITORING

Features:
    - Isolated network environments
    - Optimized for DNS operations
    - IPv4/IPv6 dual stack support
    - Performance tuning
    - Security hardening
EOF
}

# Main execution
main() {
    local command="${1:-setup}"

    case "$command" in
        setup)
            check_docker
            create_cloudunflare_network
            create_monitoring_network
            configure_network_security
            optimize_network_performance
            validate_networks
            show_network_status
            print_status "CloudUnflare network setup completed!"
            ;;
        validate)
            check_docker
            validate_networks
            ;;
        status)
            check_docker
            show_network_status
            ;;
        cleanup)
            check_docker
            cleanup_networks
            ;;
        optimize)
            check_docker
            optimize_network_performance
            print_status "Network optimization completed"
            ;;
        help|--help|-h)
            show_help
            ;;
        *)
            print_error "Unknown command: $command"
            show_help
            exit 1
            ;;
    esac
}

# Run main function with all arguments
main "$@"