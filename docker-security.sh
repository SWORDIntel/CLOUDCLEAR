#!/bin/bash
# CloudUnflare Enhanced v2.0 - Docker Security Configuration Script
# OPSEC-compliant security hardening for containerized deployment

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SECURITY_CONFIG_DIR="$SCRIPT_DIR/data/config/security"
SECRETS_DIR="$SCRIPT_DIR/data/secrets"
CONTAINER_NAME_PREFIX="cloudunflare"

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

# Function to check if running as root
check_privileges() {
    if [ "$EUID" -eq 0 ]; then
        print_warning "Running as root - some security features may be limited"
    else
        print_status "Running as non-root user (recommended)"
    fi
}

# Function to create security directories
create_security_directories() {
    print_step "Creating security directory structure..."

    # Create security configuration directories
    mkdir -p "$SECURITY_CONFIG_DIR"
    mkdir -p "$SECRETS_DIR"
    mkdir -p "$SCRIPT_DIR/data/certificates"
    mkdir -p "$SCRIPT_DIR/data/keys"

    # Set restrictive permissions
    chmod 750 "$SECURITY_CONFIG_DIR"
    chmod 700 "$SECRETS_DIR"
    chmod 700 "$SCRIPT_DIR/data/certificates"
    chmod 700 "$SCRIPT_DIR/data/keys"

    print_status "Security directories created with restrictive permissions"
}

# Function to generate security configuration
generate_security_config() {
    print_step "Generating security configuration files..."

    # AppArmor profile for CloudUnflare
    cat > "$SECURITY_CONFIG_DIR/apparmor-profile" << 'EOF'
#include <tunables/global>

profile cloudunflare-enhanced flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>
  #include <abstractions/nameservice>
  #include <abstractions/openssl>

  # Allow network access
  network inet tcp,
  network inet udp,
  network inet6 tcp,
  network inet6 udp,

  # Application executable
  /app/cloudunflare* ix,
  /app/test_* ix,
  /app/zone_transfer_* ix,

  # Configuration and data access
  /app/config/** r,
  /app/results/** rw,
  /app/logs/** rw,
  /app/wordlists/** r,
  /app/probes/** r,

  # System libraries and dependencies
  /lib/** mr,
  /usr/lib/** mr,
  /lib64/** mr,

  # Temporary files
  /tmp/cloudunflare/** rw,
  owner /tmp/cloudunflare-* rw,

  # Deny dangerous operations
  deny /proc/sys/** w,
  deny /sys/** w,
  deny capability sys_admin,
  deny capability sys_module,

  # Allow specific capabilities needed for OPSEC
  capability net_admin,
  capability net_raw,
  capability sys_ptrace,
}
EOF

    # SELinux policy (basic template)
    cat > "$SECURITY_CONFIG_DIR/selinux-policy.te" << 'EOF'
policy_module(cloudunflare_enhanced, 1.0)

require {
    type container_t;
    type container_file_t;
    class capability { net_admin net_raw sys_ptrace };
    class tcp_socket { create connect getattr read write };
    class udp_socket { create connect getattr read write };
}

# Allow CloudUnflare enhanced capabilities
allow container_t self:capability { net_admin net_raw sys_ptrace };

# Allow network operations
allow container_t self:tcp_socket { create connect getattr read write };
allow container_t self:udp_socket { create connect getattr read write };

# Allow file operations in container
allow container_t container_file_t:file { read write create unlink };
EOF

    # Docker security options
    cat > "$SECURITY_CONFIG_DIR/docker-security-opts.conf" << 'EOF'
# CloudUnflare Enhanced Docker Security Options
# These options should be applied to container runs

# Security options
--security-opt=no-new-privileges:true
--security-opt=apparmor:cloudunflare-enhanced

# Capability restrictions (add only what's needed)
--cap-drop=ALL
--cap-add=NET_ADMIN
--cap-add=NET_RAW
--cap-add=SYS_PTRACE

# Read-only root filesystem (with writable mounts)
--read-only
--tmpfs=/tmp:rw,noexec,nosuid,size=100m
--tmpfs=/var/run:rw,noexec,nosuid,size=100m

# User namespace remapping
--user=cloudunflare:cloudunflare

# Resource limits
--memory=512m
--cpus=2.0
--pids-limit=100

# Network restrictions
--network=cloudunflare-network

# Logging security
--log-driver=json-file
--log-opt=max-size=10m
--log-opt=max-file=3
EOF

    print_status "Security configuration files generated"
}

# Function to generate TLS certificates for internal communication
generate_tls_certificates() {
    print_step "Generating TLS certificates for secure communication..."

    local cert_dir="$SCRIPT_DIR/data/certificates"
    local key_dir="$SCRIPT_DIR/data/keys"

    # Generate CA private key
    openssl genrsa -out "$key_dir/ca-key.pem" 4096 2>/dev/null

    # Generate CA certificate
    openssl req -new -x509 -days 3650 -key "$key_dir/ca-key.pem" \
        -out "$cert_dir/ca.pem" \
        -subj "/C=US/ST=Virtual/L=Container/O=CloudUnflare/CN=CloudUnflare-CA" \
        2>/dev/null

    # Generate server private key
    openssl genrsa -out "$key_dir/server-key.pem" 4096 2>/dev/null

    # Generate server certificate signing request
    openssl req -new -key "$key_dir/server-key.pem" \
        -out "$cert_dir/server.csr" \
        -subj "/C=US/ST=Virtual/L=Container/O=CloudUnflare/CN=cloudunflare-server" \
        2>/dev/null

    # Generate server certificate
    openssl x509 -req -days 365 -in "$cert_dir/server.csr" \
        -CA "$cert_dir/ca.pem" -CAkey "$key_dir/ca-key.pem" \
        -CAcreateserial -out "$cert_dir/server.pem" \
        2>/dev/null

    # Generate client private key
    openssl genrsa -out "$key_dir/client-key.pem" 4096 2>/dev/null

    # Generate client certificate signing request
    openssl req -new -key "$key_dir/client-key.pem" \
        -out "$cert_dir/client.csr" \
        -subj "/C=US/ST=Virtual/L=Container/O=CloudUnflare/CN=cloudunflare-client" \
        2>/dev/null

    # Generate client certificate
    openssl x509 -req -days 365 -in "$cert_dir/client.csr" \
        -CA "$cert_dir/ca.pem" -CAkey "$key_dir/ca-key.pem" \
        -CAcreateserial -out "$cert_dir/client.pem" \
        2>/dev/null

    # Set secure permissions
    chmod 600 "$key_dir"/*.pem
    chmod 644 "$cert_dir"/*.pem

    # Clean up CSR files
    rm -f "$cert_dir"/*.csr

    print_status "TLS certificates generated and secured"
}

# Function to create secrets
create_secrets() {
    print_step "Creating application secrets..."

    # Generate random secrets
    local api_secret
    local encryption_key
    local session_secret

    api_secret=$(openssl rand -hex 32)
    encryption_key=$(openssl rand -hex 64)
    session_secret=$(openssl rand -hex 32)

    # Store secrets securely
    cat > "$SECRETS_DIR/api-secrets.env" << EOF
# CloudUnflare Enhanced API Secrets
# DO NOT COMMIT TO VERSION CONTROL

CLOUDUNFLARE_API_SECRET=$api_secret
CLOUDUNFLARE_ENCRYPTION_KEY=$encryption_key
CLOUDUNFLARE_SESSION_SECRET=$session_secret
EOF

    # Generate database credentials (if using external database)
    cat > "$SECRETS_DIR/database-secrets.env" << EOF
# CloudUnflare Enhanced Database Secrets
# DO NOT COMMIT TO VERSION CONTROL

DB_HOST=localhost
DB_PORT=5432
DB_NAME=cloudunflare
DB_USER=cloudunflare_user
DB_PASSWORD=$(openssl rand -hex 16)
EOF

    # Set restrictive permissions
    chmod 600 "$SECRETS_DIR"/*.env

    print_status "Application secrets created and secured"
}

# Function to configure container runtime security
configure_runtime_security() {
    print_step "Configuring container runtime security..."

    # Create runtime security configuration
    cat > "$SECURITY_CONFIG_DIR/runtime-security.conf" << 'EOF'
# CloudUnflare Enhanced Runtime Security Configuration

[container_security]
# Disable privilege escalation
no_new_privs = true

# User namespace remapping
user_remap = true
user_id = 1000
group_id = 1000

# Resource limits
memory_limit = 512M
cpu_limit = 2.0
pids_limit = 100
nofile_limit = 1024

# Filesystem restrictions
read_only_root = true
temp_mount_size = 100M
disable_swap = true

[network_security]
# Network isolation
custom_network = true
network_name = cloudunflare-network
disable_inter_container = false

# DNS restrictions
custom_dns = true
dns_servers = ["1.1.1.1", "8.8.8.8"]

[capabilities]
# Minimal capability set
drop_all = true
add_net_admin = true
add_net_raw = true
add_sys_ptrace = true

[monitoring]
# Security monitoring
audit_logging = true
syscall_monitoring = true
network_monitoring = true
file_monitoring = true
EOF

    print_status "Runtime security configuration created"
}

# Function to set up logging security
configure_secure_logging() {
    print_step "Configuring secure logging..."

    # Create secure logging configuration
    cat > "$SECURITY_CONFIG_DIR/logging-security.conf" << 'EOF'
# CloudUnflare Enhanced Secure Logging Configuration

[log_security]
# Log rotation and retention
max_log_size = 10M
max_log_files = 5
log_retention_days = 30

# Log encryption
encrypt_logs = false
compression = true

# Sensitive data filtering
filter_secrets = true
filter_credentials = true
filter_api_keys = true

# Audit trail
audit_commands = true
audit_network = true
audit_file_access = true

[log_destinations]
# Local logging
local_logs = true
log_directory = /app/logs

# Remote logging (if configured)
remote_logging = false
remote_host =
remote_port = 514
remote_protocol = tcp

[privacy]
# OPSEC considerations
anonymize_ips = true
anonymize_domains = false
redact_sensitive = true
EOF

    print_status "Secure logging configuration created"
}

# Function to generate security checklist
generate_security_checklist() {
    print_step "Generating security deployment checklist..."

    cat > "$SECURITY_CONFIG_DIR/deployment-checklist.md" << 'EOF'
# CloudUnflare Enhanced v2.0 - Security Deployment Checklist

## Pre-Deployment Security Checks

### Container Security
- [ ] Container runs as non-root user (cloudunflare:cloudunflare)
- [ ] Read-only root filesystem with minimal writable mounts
- [ ] Minimal capability set (NET_ADMIN, NET_RAW, SYS_PTRACE only)
- [ ] No privilege escalation allowed (no-new-privileges)
- [ ] Resource limits configured (memory, CPU, PIDs)
- [ ] Security profiles applied (AppArmor/SELinux)

### Network Security
- [ ] Custom isolated network (cloudunflare-network)
- [ ] Monitoring network isolated from main network
- [ ] TLS certificates generated and deployed
- [ ] DNS servers configured securely
- [ ] Network policies applied
- [ ] Firewall rules configured

### Secrets Management
- [ ] API secrets generated and stored securely
- [ ] Database credentials secured
- [ ] TLS certificates have proper permissions (600/644)
- [ ] Secrets directory permissions set to 700
- [ ] No secrets committed to version control

### Logging and Monitoring
- [ ] Audit logging enabled
- [ ] Log rotation configured
- [ ] Sensitive data filtering enabled
- [ ] Security event monitoring active
- [ ] Log file permissions secured

### Application Security
- [ ] OPSEC mode enabled
- [ ] Rate limiting configured
- [ ] Memory protection enabled
- [ ] Stack protection enabled
- [ ] Emergency cleanup handlers active

### Operational Security
- [ ] Stealth mode operational
- [ ] User agent rotation configured
- [ ] Request timing randomization active
- [ ] Circuit breaker mechanisms enabled
- [ ] Anomaly detection thresholds set

### Post-Deployment Verification
- [ ] Security scan completed
- [ ] Network connectivity tested
- [ ] Certificate validation successful
- [ ] Log aggregation functioning
- [ ] Health checks passing
- [ ] Resource usage within limits

## Security Incident Response

### Detection
- Monitor for unusual network activity
- Watch for memory usage spikes
- Check for failed authentication attempts
- Monitor DNS query patterns

### Response
- Automated circuit breaker activation
- Container isolation procedures
- Log preservation and analysis
- Incident reporting workflow

## Compliance and Audit

### OPSEC Compliance
- Timing analysis resistance
- Traffic pattern randomization
- Minimal logging footprint
- Secure communication channels

### Security Audit Points
- Container escape prevention
- Network isolation validation
- Secrets protection verification
- Resource usage monitoring
EOF

    print_status "Security deployment checklist generated"
}

# Function to validate security configuration
validate_security_setup() {
    print_step "Validating security configuration..."

    local validation_errors=0

    # Check directory permissions
    print_step "Checking directory permissions..."

    if [ ! -d "$SECRETS_DIR" ] || [ "$(stat -c %a "$SECRETS_DIR")" != "700" ]; then
        print_error "Secrets directory permissions incorrect"
        ((validation_errors++))
    fi

    if [ ! -d "$SCRIPT_DIR/data/keys" ] || [ "$(stat -c %a "$SCRIPT_DIR/data/keys")" != "700" ]; then
        print_error "Keys directory permissions incorrect"
        ((validation_errors++))
    fi

    # Check certificate files
    print_step "Checking certificates..."

    local cert_files=("ca.pem" "server.pem" "client.pem")
    for cert in "${cert_files[@]}"; do
        if [ ! -f "$SCRIPT_DIR/data/certificates/$cert" ]; then
            print_error "Certificate $cert not found"
            ((validation_errors++))
        fi
    done

    # Check key files
    local key_files=("ca-key.pem" "server-key.pem" "client-key.pem")
    for key in "${key_files[@]}"; do
        if [ ! -f "$SCRIPT_DIR/data/keys/$key" ]; then
            print_error "Private key $key not found"
            ((validation_errors++))
        elif [ "$(stat -c %a "$SCRIPT_DIR/data/keys/$key")" != "600" ]; then
            print_error "Private key $key has incorrect permissions"
            ((validation_errors++))
        fi
    done

    # Check secrets
    if [ ! -f "$SECRETS_DIR/api-secrets.env" ] || [ "$(stat -c %a "$SECRETS_DIR/api-secrets.env")" != "600" ]; then
        print_error "API secrets file missing or has incorrect permissions"
        ((validation_errors++))
    fi

    # Report validation results
    if [ $validation_errors -eq 0 ]; then
        print_status "Security validation completed successfully"
        return 0
    else
        print_error "Security validation failed with $validation_errors errors"
        return 1
    fi
}

# Function to show security status
show_security_status() {
    print_step "Security Configuration Status"
    echo

    echo "=== Security Directories ==="
    echo "Security Config: $SECURITY_CONFIG_DIR ($(stat -c %a "$SECURITY_CONFIG_DIR" 2>/dev/null || echo "missing"))"
    echo "Secrets:        $SECRETS_DIR ($(stat -c %a "$SECRETS_DIR" 2>/dev/null || echo "missing"))"
    echo "Certificates:   $SCRIPT_DIR/data/certificates ($(stat -c %a "$SCRIPT_DIR/data/certificates" 2>/dev/null || echo "missing"))"
    echo "Keys:           $SCRIPT_DIR/data/keys ($(stat -c %a "$SCRIPT_DIR/data/keys" 2>/dev/null || echo "missing"))"
    echo

    echo "=== Security Files ==="
    echo "AppArmor Profile:     $([ -f "$SECURITY_CONFIG_DIR/apparmor-profile" ] && echo "✓" || echo "✗")"
    echo "SELinux Policy:       $([ -f "$SECURITY_CONFIG_DIR/selinux-policy.te" ] && echo "✓" || echo "✗")"
    echo "Docker Security Opts: $([ -f "$SECURITY_CONFIG_DIR/docker-security-opts.conf" ] && echo "✓" || echo "✗")"
    echo "Runtime Security:     $([ -f "$SECURITY_CONFIG_DIR/runtime-security.conf" ] && echo "✓" || echo "✗")"
    echo "Logging Security:     $([ -f "$SECURITY_CONFIG_DIR/logging-security.conf" ] && echo "✓" || echo "✗")"
    echo

    echo "=== Certificates and Keys ==="
    echo "CA Certificate:       $([ -f "$SCRIPT_DIR/data/certificates/ca.pem" ] && echo "✓" || echo "✗")"
    echo "Server Certificate:   $([ -f "$SCRIPT_DIR/data/certificates/server.pem" ] && echo "✓" || echo "✗")"
    echo "Client Certificate:   $([ -f "$SCRIPT_DIR/data/certificates/client.pem" ] && echo "✓" || echo "✗")"
    echo "CA Private Key:       $([ -f "$SCRIPT_DIR/data/keys/ca-key.pem" ] && echo "✓" || echo "✗")"
    echo "Server Private Key:   $([ -f "$SCRIPT_DIR/data/keys/server-key.pem" ] && echo "✓" || echo "✗")"
    echo "Client Private Key:   $([ -f "$SCRIPT_DIR/data/keys/client-key.pem" ] && echo "✓" || echo "✗")"
    echo

    echo "=== Secrets ==="
    echo "API Secrets:          $([ -f "$SECRETS_DIR/api-secrets.env" ] && echo "✓" || echo "✗")"
    echo "Database Secrets:     $([ -f "$SECRETS_DIR/database-secrets.env" ] && echo "✓" || echo "✗")"
    echo
}

# Function to cleanup security configuration
cleanup_security() {
    print_step "Cleaning up security configuration..."

    read -p "This will remove all security configurations, certificates, and secrets. Continue? (y/N): " -n 1 -r
    echo

    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_status "Security cleanup cancelled"
        return 0
    fi

    # Remove security directories
    rm -rf "$SECURITY_CONFIG_DIR"
    rm -rf "$SECRETS_DIR"
    rm -rf "$SCRIPT_DIR/data/certificates"
    rm -rf "$SCRIPT_DIR/data/keys"

    print_status "Security configuration cleaned up"
}

# Function to show help
show_help() {
    cat << EOF
CloudUnflare Enhanced v2.0 - Docker Security Configuration

Usage: $0 [COMMAND]

Commands:
    setup       Configure complete security setup (default)
    validate    Validate existing security configuration
    status      Show security configuration status
    cleanup     Remove all security configurations
    certs       Generate TLS certificates only
    secrets     Generate application secrets only
    help        Show this help message

Examples:
    $0 setup       # Complete security setup
    $0 validate    # Check security configuration
    $0 status      # Show current security state
    $0 certs       # Generate certificates only

Security Features:
    - AppArmor/SELinux profiles
    - TLS certificate generation
    - Secure secrets management
    - Container hardening
    - Network isolation
    - OPSEC compliance
    - Audit logging
    - Resource limits

Directory Structure:
    data/config/security/   - Security configurations
    data/secrets/          - Application secrets (600)
    data/certificates/     - TLS certificates (644)
    data/keys/            - Private keys (600)
EOF
}

# Main execution
main() {
    local command="${1:-setup}"

    case "$command" in
        setup)
            check_privileges
            create_security_directories
            generate_security_config
            generate_tls_certificates
            create_secrets
            configure_runtime_security
            configure_secure_logging
            generate_security_checklist
            validate_security_setup
            show_security_status
            print_status "CloudUnflare security setup completed!"
            ;;
        validate)
            validate_security_setup
            ;;
        status)
            show_security_status
            ;;
        cleanup)
            cleanup_security
            ;;
        certs)
            create_security_directories
            generate_tls_certificates
            print_status "TLS certificates generated"
            ;;
        secrets)
            create_security_directories
            create_secrets
            print_status "Application secrets generated"
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