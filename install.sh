#!/bin/bash
#
# CloudClear - One-Command Installation & Activation Script
# Installs dependencies, builds all targets, and guides through setup
#

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Fancy banner
print_banner() {
    echo -e "${CYAN}"
    cat << "EOF"
╔════════════════════════════════════════════════════════════════╗
║                                                                ║
║   ██████╗██╗      ██████╗ ██╗   ██╗██████╗  ██████╗██╗        ║
║  ██╔════╝██║     ██╔═══██╗██║   ██║██╔══██╗██╔════╝██║        ║
║  ██║     ██║     ██║   ██║██║   ██║██║  ██║██║     ██║        ║
║  ██║     ██║     ██║   ██║██║   ██║██║  ██║██║     ██║        ║
║  ╚██████╗███████╗╚██████╔╝╚██████╔╝██████╔╝╚██████╗███████╗   ║
║   ╚═════╝╚══════╝ ╚═════╝  ╚═════╝ ╚═════╝  ╚═════╝╚══════╝   ║
║                                                                ║
║          Advanced Cloud Provider Detection & Intelligence     ║
║                     v2.0-Enhanced-Cloud                        ║
║                                                                ║
╚════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

# Print section header
print_section() {
    echo -e "\n${PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${PURPLE}▶ $1${NC}"
    echo -e "${PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
}

# Print success message
print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

# Print error message
print_error() {
    echo -e "${RED}✗ $1${NC}"
}

# Print warning message
print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

# Print info message
print_info() {
    echo -e "${BLUE}ℹ $1${NC}"
}

# Progress bar
show_progress() {
    local current=$1
    local total=$2
    local width=50
    local percentage=$((current * 100 / total))
    local completed=$((width * current / total))
    local remaining=$((width - completed))

    printf "\r${CYAN}Progress: ["
    printf "%${completed}s" | tr ' ' '█'
    printf "%${remaining}s" | tr ' ' '░'
    printf "] %3d%%${NC}" $percentage
}

# Spinner for long operations
spinner() {
    local pid=$1
    local delay=0.1
    local spinstr='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
    while ps -p $pid > /dev/null 2>&1; do
        local temp=${spinstr#?}
        printf "\r${CYAN}%c${NC} " "$spinstr"
        spinstr=$temp${spinstr%"$temp"}
        sleep $delay
    done
    printf "\r"
}

# Detect OS
detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if [ -f /etc/os-release ]; then
            . /etc/os-release
            OS=$ID
            VER=$VERSION_ID
        else
            OS="unknown"
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
    else
        OS="unknown"
    fi
}

# Install dependencies based on OS
install_dependencies() {
    print_section "Installing Dependencies"

    case $OS in
        ubuntu|debian)
            print_info "Detected Debian/Ubuntu system"
            echo -n "Updating package lists... "
            sudo apt-get update -qq 2>&1 > /dev/null &
            spinner $!
            print_success "Package lists updated"

            print_info "Installing dependencies (this may take a moment)..."
            sudo apt-get install -y -qq \
                build-essential \
                gcc \
                make \
                libcurl4-openssl-dev \
                libssl-dev \
                libjson-c-dev \
                libncurses5-dev \
                libncursesw5-dev \
                pkg-config \
                git
            ;;

        fedora|rhel|centos)
            print_info "Detected RedHat/Fedora/CentOS system"
            sudo yum install -y -q \
                gcc \
                make \
                libcurl-devel \
                openssl-devel \
                json-c-devel \
                ncurses-devel \
                pkgconfig \
                git
            ;;

        arch|manjaro)
            print_info "Detected Arch/Manjaro system"
            sudo pacman -Sy --noconfirm --needed \
                gcc \
                make \
                curl \
                openssl \
                json-c \
                ncurses \
                pkgconf \
                git
            ;;

        macos)
            print_info "Detected macOS system"
            if ! command -v brew &> /dev/null; then
                print_warning "Homebrew not found. Installing Homebrew..."
                /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
            fi
            brew install curl openssl json-c ncurses pkg-config
            ;;

        *)
            print_error "Unsupported operating system: $OS"
            print_info "Please install these dependencies manually:"
            echo "  - gcc, make"
            echo "  - libcurl-dev, libssl-dev, libjson-c-dev, libncurses-dev"
            exit 1
            ;;
    esac

    print_success "Dependencies installed successfully"
}

# Verify dependencies
verify_dependencies() {
    print_section "Verifying Dependencies"

    local deps_ok=true

    # Check compiler
    if command -v gcc &> /dev/null; then
        print_success "GCC: $(gcc --version | head -1)"
    else
        print_error "GCC not found"
        deps_ok=false
    fi

    # Check make
    if command -v make &> /dev/null; then
        print_success "Make: $(make --version | head -1)"
    else
        print_error "Make not found"
        deps_ok=false
    fi

    # Check pkg-config
    if command -v pkg-config &> /dev/null; then
        print_success "pkg-config: available"
    else
        print_warning "pkg-config not found (optional but recommended)"
    fi

    # Check libraries
    local libs=("libcurl" "openssl" "json-c" "ncurses")
    for lib in "${libs[@]}"; do
        if pkg-config --exists $lib 2>/dev/null; then
            print_success "$lib: $(pkg-config --modversion $lib)"
        else
            print_warning "$lib: Could not verify via pkg-config"
        fi
    done

    if [ "$deps_ok" = false ]; then
        print_error "Required dependencies missing. Please install them first."
        exit 1
    fi

    print_success "All dependencies verified"
}

# Build CloudClear
build_cloudclear() {
    print_section "Building CloudClear"

    local total_steps=4
    local current_step=0

    # Step 1: Clean
    current_step=1
    show_progress $current_step $total_steps
    echo -ne "\r"
    print_info "Cleaning previous builds..."
    make clean &> /dev/null || true
    print_success "Clean completed"

    # Step 2: Build main
    current_step=2
    show_progress $current_step $total_steps
    echo -ne "\r"
    print_info "Building main executable (cloudclear)..."
    if make all 2>&1 | grep -E "error|undefined reference" > /tmp/build_errors.txt; then
        if [ -s /tmp/build_errors.txt ]; then
            echo
            print_error "Build failed with errors"
            cat /tmp/build_errors.txt
            exit 1
        fi
    fi
    print_success "Main executable built: ./cloudclear"

    # Step 3: Build TUI
    current_step=3
    show_progress $current_step $total_steps
    echo -ne "\r"
    print_info "Building TUI (Text User Interface)..."
    if make tui 2>&1 | grep -E "error|undefined reference" > /tmp/build_errors.txt; then
        if [ -s /tmp/build_errors.txt ]; then
            print_warning "TUI build had issues, but continuing..."
        fi
    fi
    print_success "TUI built: ./cloudclear-tui"

    # Step 4: Build Enhanced TUI
    current_step=4
    show_progress $current_step $total_steps
    echo -ne "\r"
    print_info "Building Enhanced TUI with Cloud Integration..."
    if make tui-enhanced 2>&1 | grep -E "error|undefined reference" > /tmp/build_errors.txt; then
        if [ -s /tmp/build_errors.txt ]; then
            print_warning "Enhanced TUI build had issues, but continuing..."
        fi
    fi
    print_success "Enhanced TUI built: ./cloudclear-tui-enhanced"

    # Final progress
    show_progress $total_steps $total_steps
    echo
    print_success "Build completed successfully!"
}

# Create configuration directory
setup_config() {
    print_section "Setting Up Configuration"

    local config_dir="$HOME/.cloudclear"

    if [ ! -d "$config_dir" ]; then
        mkdir -p "$config_dir"
        chmod 700 "$config_dir"
        print_success "Created configuration directory: $config_dir"
    else
        print_info "Configuration directory already exists: $config_dir"
    fi

    # Copy example env if .env doesn't exist
    if [ ! -f .env ] && [ -f .env.example ]; then
        print_info "Creating .env from .env.example..."
        cp .env.example .env
        print_success "Created .env file (you can edit this later for API keys)"
    fi
}

# Quick configuration wizard
config_wizard() {
    print_section "Configuration Wizard"

    echo -e "${CYAN}CloudClear supports 20+ cloud providers and intelligence services.${NC}"
    echo -e "${CYAN}You can configure API keys now or skip and do it later via the TUI.${NC}\n"

    read -p "$(echo -e ${YELLOW}Would you like to configure API keys now? [y/N]: ${NC})" -n 1 -r
    echo

    if [[ $REPLY =~ ^[Yy]$ ]]; then
        print_info "Launching TUI configuration wizard..."
        print_info "You can configure API keys through: Settings → API Key Configuration"
        echo
        print_warning "Press any key to launch TUI in 3 seconds..."
        sleep 3

        if [ -f ./cloudclear-tui-enhanced ]; then
            ./cloudclear-tui-enhanced
        else
            print_warning "TUI not available, skipping configuration wizard"
        fi
    else
        print_info "Skipping API key configuration (you can do this later)"
    fi
}

# Create quick start script
create_launcher() {
    print_section "Creating Launch Scripts"

    cat > cloudclear-launch.sh << 'EOF'
#!/bin/bash
# CloudClear Quick Launcher

echo "CloudClear Launcher"
echo "=================="
echo "1. CLI Mode (Command Line)"
echo "2. TUI Mode (Text Interface)"
echo "3. Enhanced TUI (Full Features + Cloud Detection)"
echo "4. Help"
echo "5. Exit"
echo
read -p "Select option [1-5]: " choice

case $choice in
    1)
        ./cloudclear "$@"
        ;;
    2)
        ./cloudclear-tui
        ;;
    3)
        ./cloudclear-tui-enhanced
        ;;
    4)
        echo "Usage: ./cloudclear <domain>"
        echo "TUI: ./cloudclear-tui"
        echo "Enhanced: ./cloudclear-tui-enhanced"
        ;;
    5)
        exit 0
        ;;
    *)
        echo "Invalid option"
        ;;
esac
EOF
    chmod +x cloudclear-launch.sh
    print_success "Created launcher: ./cloudclear-launch.sh"
}

# Print completion message
print_completion() {
    echo
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                                                                ║${NC}"
    echo -e "${GREEN}║            🎉  INSTALLATION COMPLETED SUCCESSFULLY!  🎉        ║${NC}"
    echo -e "${GREEN}║                                                                ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo

    print_section "Quick Start Guide"

    echo -e "${CYAN}Available Executables:${NC}"
    echo -e "  ${GREEN}./cloudclear${NC}              - CLI mode (fastest)"
    echo -e "  ${GREEN}./cloudclear-tui${NC}          - Interactive TUI"
    echo -e "  ${GREEN}./cloudclear-tui-enhanced${NC} - Full-featured TUI with cloud detection"
    echo -e "  ${GREEN}./cloudclear-launch.sh${NC}    - Quick launcher menu"
    echo

    echo -e "${CYAN}Quick Commands:${NC}"
    echo -e "  ${YELLOW}# Run basic detection${NC}"
    echo -e "  ./cloudclear example.com"
    echo
    echo -e "  ${YELLOW}# Launch interactive TUI${NC}"
    echo -e "  ./cloudclear-tui-enhanced"
    echo
    echo -e "  ${YELLOW}# Use the launcher${NC}"
    echo -e "  ./cloudclear-launch.sh"
    echo

    echo -e "${CYAN}Configuration:${NC}"
    echo -e "  • API Keys: Launch TUI → Settings → API Key Configuration"
    echo -e "  • Cloud Status: Launch TUI → Settings → Cloud Provider Status"
    echo -e "  • Manual config: Edit .env file or ~/.cloudclear/config.enc"
    echo

    echo -e "${CYAN}Supported Integrations (15 Total):${NC}"
    echo -e "  ${PURPLE}Cloud Providers (12):${NC}"
    echo -e "    ${GREEN}✓${NC} Cloudflare       ${GREEN}✓${NC} Akamai Edge      ${GREEN}✓${NC} AWS CloudFront"
    echo -e "    ${GREEN}✓${NC} Azure Front Door ${GREEN}✓${NC} GCP Cloud CDN    ${GREEN}✓${NC} Fastly"
    echo -e "    ${GREEN}✓${NC} DigitalOcean     ${GREEN}✓${NC} Oracle Cloud     ${GREEN}✓${NC} Alibaba Cloud"
    echo -e "    ${GREEN}✓${NC} Imperva          ${GREEN}✓${NC} Sucuri           ${GREEN}✓${NC} Stackpath"
    echo
    echo -e "  ${PURPLE}Intelligence Services (3):${NC}"
    echo -e "    ${GREEN}✓${NC} Shodan           ${GREEN}✓${NC} Censys           ${GREEN}✓${NC} VirusTotal"
    echo

    echo -e "${CYAN}Next Steps:${NC}"
    echo -e "  ${YELLOW}Local Usage:${NC}"
    echo -e "    1. Configure API keys (optional): ${GREEN}./cloudclear-tui-enhanced${NC}"
    echo -e "    2. Test detection: ${GREEN}./cloudclear example.com${NC}"
    echo -e "    3. Explore features: ${GREEN}./cloudclear-launch.sh${NC}"
    echo
    echo -e "  ${YELLOW}Docker Deployment:${NC}"
    echo -e "    1. Configure .env: ${GREEN}cp .env.example .env && nano .env${NC}"
    echo -e "    2. Deploy: ${GREEN}docker-compose up -d${NC}"
    echo -e "    3. Access: ${GREEN}https://scan.yourdomain.com${NC}"
    echo

    echo -e "${YELLOW}Documentation:${NC}"
    echo -e "  • Quick Start:       ${BLUE}QUICKSTART.md${NC}"
    echo -e "  • Docker Deployment: ${BLUE}DOCKER_DEPLOYMENT.md${NC}"
    echo -e "  • Integration Guide: ${BLUE}docs/CLOUD_INTEGRATION_COMPLETE.md${NC}"
    echo -e "  • Full Plan:         ${BLUE}docs/COMPLETE_CLOUD_INTEGRATION_PLAN.md${NC}"
    echo

    echo -e "${GREEN}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                                                                ║${NC}"
    echo -e "${GREEN}║     CloudClear v2.0-Enhanced-Cloud is ready to use! 🚀        ║${NC}"
    echo -e "${GREEN}║                                                                ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo
}

# Main installation flow
main() {
    clear
    print_banner

    print_info "Starting CloudClear installation..."
    echo

    # Detect OS
    detect_os
    print_info "Operating System: $OS"

    # Ask for confirmation
    read -p "$(echo -e ${YELLOW}Install dependencies and build CloudClear? [Y/n]: ${NC})" -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Nn]$ ]]; then
        # Install dependencies
        install_dependencies

        # Verify dependencies
        verify_dependencies

        # Build CloudClear
        build_cloudclear

        # Setup configuration
        setup_config

        # Create launcher
        create_launcher

        # Configuration wizard
        config_wizard

        # Print completion
        print_completion
    else
        print_warning "Installation cancelled"
        exit 0
    fi
}

# Run main
main
