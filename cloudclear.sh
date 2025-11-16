#!/bin/bash

#############################################################################
# CloudClear Unified Launcher Script
# Interactive menu system for building, running, and managing CloudClear
#############################################################################

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Function to print colored output
print_header() {
    echo -e "${CYAN}${BOLD}"
    echo "╔════════════════════════════════════════════════════════════════╗"
    echo "║                    CLOUDCLEAR LAUNCHER                         ║"
    echo "║              Advanced DNS Reconnaissance Tool                  ║"
    echo "╚════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

print_section() {
    echo -e "${BLUE}${BOLD}═══ $1 ═══${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

print_info() {
    echo -e "${CYAN}ℹ $1${NC}"
}

# Function to check if dependencies are installed
check_dependencies() {
    local missing_deps=()

    print_section "Checking Dependencies"

    if ! pkg-config --exists libcurl; then
        missing_deps+=("libcurl4-openssl-dev")
        print_error "libcurl not found"
    else
        print_success "libcurl found"
    fi

    if ! pkg-config --exists openssl; then
        missing_deps+=("libssl-dev")
        print_error "OpenSSL not found"
    else
        print_success "OpenSSL found"
    fi

    if ! pkg-config --exists json-c; then
        missing_deps+=("libjson-c-dev")
        print_error "json-c not found"
    else
        print_success "json-c found"
    fi

    if ! pkg-config --exists ncurses 2>/dev/null; then
        if [[ "$1" == "tui" ]]; then
            missing_deps+=("libncurses-dev")
            print_error "ncurses not found (required for TUI)"
        else
            print_warning "ncurses not found (optional, required for TUI)"
        fi
    else
        print_success "ncurses found"
    fi

    if [ ${#missing_deps[@]} -ne 0 ]; then
        echo ""
        print_error "Missing dependencies: ${missing_deps[*]}"
        echo ""
        read -p "Do you want to install missing dependencies? (y/n): " install_choice
        if [[ "$install_choice" == "y" || "$install_choice" == "Y" ]]; then
            install_dependencies
        else
            print_error "Cannot proceed without required dependencies"
            exit 1
        fi
    else
        print_success "All dependencies satisfied"
    fi
    echo ""
}

# Function to install dependencies
install_dependencies() {
    print_section "Installing Dependencies"
    echo ""
    sudo apt-get update
    sudo apt-get install -y libcurl4-openssl-dev libssl-dev libjson-c-dev libncurses-dev build-essential pkg-config
    echo ""
    print_success "Dependencies installed successfully"
    echo ""
}

# Main menu
show_main_menu() {
    print_header
    echo -e "${BOLD}Main Menu:${NC}"
    echo ""
    echo "  1) Build & Run CloudClear"
    echo "  2) Docker Operations"
    echo "  3) Install Dependencies"
    echo "  4) Clean Build Files"
    echo "  5) Run Tests"
    echo "  6) Show Project Structure"
    echo "  7) System Installation"
    echo "  8) Help & Documentation"
    echo "  9) Exit"
    echo ""
}

# Build menu
show_build_menu() {
    clear
    print_header
    echo -e "${BOLD}Build Options:${NC}"
    echo ""
    echo "  1) Standard Build         - Core DNS reconnaissance"
    echo "  2) TUI Build             - Interactive terminal interface"
    echo "  3) TUI Enhanced Build    - Modern UI with Unicode"
    echo "  4) Recon Build           - All reconnaissance modules"
    echo "  5) Build All Variants    - Create all builds"
    echo "  6) Back to Main Menu"
    echo ""
}

# Docker menu
show_docker_menu() {
    clear
    print_header
    echo -e "${BOLD}Docker Operations:${NC}"
    echo ""
    echo "  1) Build Docker Image"
    echo "  2) Run with Docker Compose"
    echo "  3) Stop Docker Compose"
    echo "  4) View Docker Logs"
    echo "  5) Remove Docker Containers"
    echo "  6) Back to Main Menu"
    echo ""
}

# Build function
build_cloudclear() {
    local build_type=$1
    local target=""
    local binary=""

    case $build_type in
        1)
            target=""
            binary="cloudclear"
            check_dependencies "standard"
            ;;
        2)
            target="tui"
            binary="cloudclear-tui"
            check_dependencies "tui"
            ;;
        3)
            target="tui-enhanced"
            binary="cloudclear-tui-enhanced"
            check_dependencies "tui"
            ;;
        4)
            target="recon"
            binary="cloudclear-recon"
            check_dependencies "standard"
            ;;
        5)
            check_dependencies "tui"
            make clean
            make all
            make tui
            make tui-enhanced
            make recon
            print_success "All builds completed successfully!"
            return
            ;;
        *)
            print_error "Invalid build type"
            return 1
            ;;
    esac

    print_section "Building CloudClear"
    echo ""

    if [ -n "$target" ]; then
        make "$target"
    else
        make all
    fi

    echo ""
    print_success "Build completed successfully!"
    echo ""

    # Ask if user wants to run the binary
    if [ -n "$binary" ] && [ -f "./$binary" ]; then
        read -p "Do you want to run $binary now? (y/n): " run_choice
        if [[ "$run_choice" == "y" || "$run_choice" == "Y" ]]; then
            echo ""
            print_section "Running $binary"
            echo ""
            ./"$binary"
        fi
    fi
}

# Docker operations
docker_operation() {
    local operation=$1

    case $operation in
        1)
            print_section "Building Docker Image"
            echo ""
            make docker
            print_success "Docker image built successfully"
            ;;
        2)
            print_section "Starting Docker Compose"
            echo ""
            cd docker
            docker-compose up -d
            cd ..
            print_success "Docker containers started"
            docker-compose -f docker/docker-compose.yml ps
            ;;
        3)
            print_section "Stopping Docker Compose"
            echo ""
            docker-compose -f docker/docker-compose.yml down
            print_success "Docker containers stopped"
            ;;
        4)
            print_section "Docker Logs"
            echo ""
            docker-compose -f docker/docker-compose.yml logs -f
            ;;
        5)
            print_section "Removing Docker Containers"
            echo ""
            docker-compose -f docker/docker-compose.yml down -v
            print_success "Docker containers and volumes removed"
            ;;
        *)
            print_error "Invalid operation"
            ;;
    esac
    echo ""
}

# Clean build files
clean_build() {
    print_section "Cleaning Build Files"
    echo ""
    make clean
    print_success "Build files cleaned"
    echo ""
}

# Run tests
run_tests() {
    print_section "Running Tests"
    echo ""
    check_dependencies "standard"
    make test
    echo ""
}

# Show project structure
show_structure() {
    clear
    print_header
    make structure
    echo ""
}

# System installation
system_install() {
    print_section "System Installation"
    echo ""
    print_warning "This will install CloudClear to /usr/local/bin/"
    read -p "Continue? (y/n): " install_choice

    if [[ "$install_choice" == "y" || "$install_choice" == "Y" ]]; then
        if [ ! -f "./cloudclear" ]; then
            print_info "Building CloudClear first..."
            build_cloudclear 1
        fi
        make install
        print_success "CloudClear installed to system"
    else
        print_info "Installation cancelled"
    fi
    echo ""
}

# Show help
show_help() {
    clear
    print_header
    make help
    echo ""
    echo -e "${BOLD}Quick Start Guide:${NC}"
    echo ""
    echo "1. First-time setup:"
    echo "   - Select option 3 to install dependencies"
    echo "   - Select option 1 to build and run"
    echo ""
    echo "2. Choose your build:"
    echo "   - Standard: Core functionality, lightweight"
    echo "   - TUI: Interactive terminal interface"
    echo "   - TUI Enhanced: Modern UI with Unicode (requires UTF-8 terminal)"
    echo "   - Recon: All reconnaissance modules enabled"
    echo ""
    echo "3. Docker deployment:"
    echo "   - Select option 2 for Docker operations"
    echo "   - Recommended for production use"
    echo ""
}

# Main loop
main() {
    while true; do
        show_main_menu
        read -p "Select an option [1-9]: " choice

        case $choice in
            1)
                while true; do
                    show_build_menu
                    read -p "Select build option [1-6]: " build_choice
                    if [ "$build_choice" == "6" ]; then
                        break
                    fi
                    build_cloudclear "$build_choice"
                    read -p "Press Enter to continue..."
                done
                ;;
            2)
                while true; do
                    show_docker_menu
                    read -p "Select Docker operation [1-6]: " docker_choice
                    if [ "$docker_choice" == "6" ]; then
                        break
                    fi
                    docker_operation "$docker_choice"
                    read -p "Press Enter to continue..."
                done
                ;;
            3)
                install_dependencies
                read -p "Press Enter to continue..."
                ;;
            4)
                clean_build
                read -p "Press Enter to continue..."
                ;;
            5)
                run_tests
                read -p "Press Enter to continue..."
                ;;
            6)
                show_structure
                read -p "Press Enter to continue..."
                ;;
            7)
                system_install
                read -p "Press Enter to continue..."
                ;;
            8)
                show_help
                read -p "Press Enter to continue..."
                ;;
            9)
                print_info "Exiting CloudClear Launcher"
                exit 0
                ;;
            *)
                print_error "Invalid option. Please select 1-9."
                sleep 2
                ;;
        esac

        clear
    done
}

# Check if script is being run with arguments (non-interactive mode)
if [ $# -gt 0 ]; then
    case $1 in
        --build-standard)
            build_cloudclear 1
            ;;
        --build-tui)
            build_cloudclear 2
            ;;
        --build-enhanced)
            build_cloudclear 3
            ;;
        --build-recon)
            build_cloudclear 4
            ;;
        --build-all)
            build_cloudclear 5
            ;;
        --install-deps)
            install_dependencies
            ;;
        --clean)
            clean_build
            ;;
        --docker-build)
            docker_operation 1
            ;;
        --docker-up)
            docker_operation 2
            ;;
        --docker-down)
            docker_operation 3
            ;;
        --help)
            show_help
            ;;
        *)
            echo "Unknown option: $1"
            echo ""
            echo "Available options:"
            echo "  --build-standard    Build standard version"
            echo "  --build-tui         Build TUI version"
            echo "  --build-enhanced    Build enhanced TUI version"
            echo "  --build-recon       Build recon version"
            echo "  --build-all         Build all versions"
            echo "  --install-deps      Install dependencies"
            echo "  --clean             Clean build files"
            echo "  --docker-build      Build Docker image"
            echo "  --docker-up         Start Docker Compose"
            echo "  --docker-down       Stop Docker Compose"
            echo "  --help              Show help"
            exit 1
            ;;
    esac
else
    # Interactive mode
    main
fi
