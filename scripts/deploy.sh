#!/bin/bash
#
# T-Pot Honeypot Infrastructure Deployment Script
# Automated deployment with health checks and error handling
#
# Usage: ./deploy.sh [--skip-checks] [--dev-mode]
#
# Author: Threat Intelligence Pipeline
# Version: 1.0.0
#

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
DOCKER_COMPOSE_FILE="$PROJECT_ROOT/infrastructure/docker-compose.yml"
MIN_DISK_GB=50
MIN_RAM_GB=8
SKIP_CHECKS=false
DEV_MODE=false

# Parse arguments
for arg in "$@"; do
    case $arg in
        --skip-checks)
            SKIP_CHECKS=true
            shift
            ;;
        --dev-mode)
            DEV_MODE=true
            shift
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --skip-checks    Skip system requirement checks"
            echo "  --dev-mode       Deploy in development mode (reduced resources)"
            echo "  --help           Show this help message"
            exit 0
            ;;
    esac
done

# Banner
echo -e "${BLUE}"
echo "================================================================"
echo "  T-POT HONEYPOT INFRASTRUCTURE DEPLOYMENT"
echo "  Threat Intelligence Collection System"
echo "================================================================"
echo -e "${NC}"

# Functions
print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[*]${NC} $1"
}

# Check if running as root
check_root() {
    if [ "$EUID" -eq 0 ]; then
        print_warning "Running as root. This is not recommended for security reasons."
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
}

# Check system requirements
check_system_requirements() {
    if [ "$SKIP_CHECKS" = true ]; then
        print_warning "Skipping system requirement checks"
        return
    fi

    print_info "Checking system requirements..."

    # Check Docker
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed"
        echo "Install Docker: https://docs.docker.com/get-docker/"
        exit 1
    fi
    print_success "Docker installed: $(docker --version)"

    # Check Docker Compose
    if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
        print_error "Docker Compose is not installed"
        echo "Install Docker Compose: https://docs.docker.com/compose/install/"
        exit 1
    fi
    print_success "Docker Compose installed"

    # Check disk space
    available_disk=$(df -BG "$PROJECT_ROOT" | awk 'NR==2 {print $4}' | sed 's/G//')
    if [ "$available_disk" -lt "$MIN_DISK_GB" ]; then
        print_error "Insufficient disk space: ${available_disk}GB (minimum ${MIN_DISK_GB}GB required)"
        exit 1
    fi
    print_success "Disk space: ${available_disk}GB available"

    # Check RAM
    total_ram=$(free -g | awk 'NR==2 {print $2}')
    if [ "$total_ram" -lt "$MIN_RAM_GB" ]; then
        print_warning "Low RAM: ${total_ram}GB (recommended ${MIN_RAM_GB}GB+)"
        print_warning "System may experience performance issues"
    else
        print_success "RAM: ${total_ram}GB available"
    fi

    # Check CPU cores
    cpu_cores=$(nproc)
    if [ "$cpu_cores" -lt 4 ]; then
        print_warning "Limited CPU cores: ${cpu_cores} (recommended 4+)"
    else
        print_success "CPU cores: ${cpu_cores}"
    fi
}

# Check port availability
check_ports() {
    print_info "Checking port availability..."

    REQUIRED_PORTS=(
        "2222:Cowrie SSH"
        "2223:Cowrie Telnet"
        "80:Dionaea HTTP"
        "443:Dionaea HTTPS"
        "9200:Elasticsearch"
        "5601:Kibana"
    )

    all_available=true

    for port_desc in "${REQUIRED_PORTS[@]}"; do
        IFS=':' read -r port service <<< "$port_desc"

        if lsof -Pi :$port -sTCP:LISTEN -t >/dev/null 2>&1 || \
           netstat -tuln 2>/dev/null | grep -q ":$port "; then
            print_error "Port $port ($service) is already in use"
            all_available=false
        fi
    done

    if [ "$all_available" = false ]; then
        print_error "Some required ports are in use. Stop conflicting services or modify docker-compose.yml"
        exit 1
    fi

    print_success "All required ports are available"
}

# Create required directories
create_directories() {
    print_info "Creating required directories..."

    DIRS=(
        "$PROJECT_ROOT/data/elasticsearch"
        "$PROJECT_ROOT/data/cowrie/logs"
        "$PROJECT_ROOT/data/cowrie/downloads"
        "$PROJECT_ROOT/data/dionaea/logs"
        "$PROJECT_ROOT/data/dionaea/binaries"
        "$PROJECT_ROOT/data/suricata/logs"
        "$PROJECT_ROOT/data/kibana"
        "$PROJECT_ROOT/infrastructure/elk-stack/geoip"
    )

    for dir in "${DIRS[@]}"; do
        mkdir -p "$dir"
    done

    print_success "Directories created"
}

# Download GeoIP databases
download_geoip() {
    print_info "Checking GeoIP databases..."

    GEOIP_DIR="$PROJECT_ROOT/infrastructure/elk-stack/geoip"

    if [ -f "$GEOIP_DIR/GeoLite2-City.mmdb" ] && [ -f "$GEOIP_DIR/GeoLite2-ASN.mmdb" ]; then
        print_success "GeoIP databases already exist"
        return
    fi

    print_warning "GeoIP databases not found"
    echo "Download GeoLite2 databases from: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data"
    echo "Place GeoLite2-City.mmdb and GeoLite2-ASN.mmdb in: $GEOIP_DIR"
    echo ""
    read -p "Continue deployment without GeoIP? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
}

# Set proper permissions
set_permissions() {
    print_info "Setting file permissions..."

    # Make scripts executable
    chmod +x "$PROJECT_ROOT"/scripts/*.sh
    chmod +x "$PROJECT_ROOT"/analysis/*.py

    # Set Elasticsearch data directory permissions
    if [ -d "$PROJECT_ROOT/data/elasticsearch" ]; then
        chmod -R 777 "$PROJECT_ROOT/data/elasticsearch" 2>/dev/null || true
    fi

    print_success "Permissions set"
}

# Pull Docker images
pull_images() {
    print_info "Pulling Docker images (this may take several minutes)..."

    cd "$PROJECT_ROOT/infrastructure"

    if docker-compose pull; then
        print_success "Docker images pulled successfully"
    else
        print_error "Failed to pull Docker images"
        exit 1
    fi
}

# Start services
start_services() {
    print_info "Starting honeypot infrastructure..."

    cd "$PROJECT_ROOT/infrastructure"

    if docker-compose up -d; then
        print_success "Services started successfully"
    else
        print_error "Failed to start services"
        exit 1
    fi
}

# Wait for services to be ready
wait_for_services() {
    print_info "Waiting for services to become healthy..."

    # Wait for Elasticsearch
    print_info "Waiting for Elasticsearch..."
    for i in {1..60}; do
        if curl -s http://localhost:9200/_cluster/health >/dev/null 2>&1; then
            print_success "Elasticsearch is ready"
            break
        fi
        if [ $i -eq 60 ]; then
            print_error "Elasticsearch failed to start (timeout)"
            docker-compose -f "$DOCKER_COMPOSE_FILE" logs elasticsearch
            exit 1
        fi
        sleep 5
    done

    # Wait for Kibana
    print_info "Waiting for Kibana..."
    for i in {1..60}; do
        if curl -s http://localhost:5601/api/status >/dev/null 2>&1; then
            print_success "Kibana is ready"
            break
        fi
        if [ $i -eq 60 ]; then
            print_error "Kibana failed to start (timeout)"
            exit 1
        fi
        sleep 5
    done

    # Wait for Logstash
    print_info "Waiting for Logstash..."
    sleep 30  # Logstash takes time to initialize pipeline
    print_success "Logstash should be ready"
}

# Display deployment summary
display_summary() {
    echo ""
    echo -e "${GREEN}"
    echo "================================================================"
    echo "  DEPLOYMENT SUCCESSFUL!"
    echo "================================================================"
    echo -e "${NC}"
    echo ""
    echo "Access Points:"
    echo "  • Kibana Dashboard:    http://localhost:5601"
    echo "  • Elasticsearch API:   http://localhost:9200"
    echo "  • T-Pot Admin:         https://localhost:64295"
    echo ""
    echo "Honeypot Services:"
    echo "  • SSH (Cowrie):        Port 2222"
    echo "  • Telnet (Cowrie):     Port 2223"
    echo "  • HTTP (Dionaea):      Port 80"
    echo "  • HTTPS (Dionaea):     Port 443"
    echo "  • MySQL (Dionaea):     Port 3306"
    echo "  • SMB (Dionaea):       Port 445"
    echo ""
    echo "Monitoring:"
    echo "  • View logs:           docker-compose -f $DOCKER_COMPOSE_FILE logs -f"
    echo "  • Check status:        docker-compose -f $DOCKER_COMPOSE_FILE ps"
    echo "  • Run monitor script:  $PROJECT_ROOT/scripts/monitor.sh"
    echo ""
    echo "Analysis Tools:"
    echo "  • IOC Extraction:      python3 $PROJECT_ROOT/analysis/ioc_extraction.py"
    echo "  • GeoIP Mapping:       python3 $PROJECT_ROOT/analysis/geolocation_mapper.py"
    echo "  • MITRE Mapping:       python3 $PROJECT_ROOT/analysis/mitre_attck_mapper.py"
    echo ""
    echo "Next Steps:"
    echo "  1. Configure Kibana index patterns (honeypot-*)"
    echo "  2. Import dashboard configurations from dashboards/"
    echo "  3. Run analysis scripts after collecting data (recommend 24-48 hours)"
    echo "  4. Set up automated reporting with scripts/generate_report.sh"
    echo ""
    echo -e "${YELLOW}SECURITY WARNING:${NC}"
    echo "  This honeypot infrastructure is exposed to the internet."
    echo "  Ensure proper firewall rules and monitoring are in place."
    echo "  Only expose honeypot ports, not management interfaces."
    echo ""
    echo "================================================================"
}

# Main deployment flow
main() {
    check_root
    check_system_requirements
    check_ports
    create_directories
    download_geoip
    set_permissions
    pull_images
    start_services
    wait_for_services
    display_summary
}

# Run main
main
