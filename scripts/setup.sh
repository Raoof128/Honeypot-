#!/bin/bash
#
# Initial Setup Script for Honeypot Infrastructure
# Prepares environment for first-time deployment
#
# Usage: ./setup.sh
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo -e "${BLUE}"
echo "================================================================"
echo "  HONEYPOT INFRASTRUCTURE - INITIAL SETUP"
echo "================================================================"
echo -e "${NC}"

# Function to print messages
print_success() { echo -e "${GREEN}[✓]${NC} $1"; }
print_error() { echo -e "${RED}[✗]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[!]${NC} $1"; }
print_info() { echo -e "${BLUE}[*]${NC} $1"; }

# Check Python version
check_python() {
    print_info "Checking Python installation..."

    if ! command -v python3 &> /dev/null; then
        print_error "Python 3 is not installed"
        echo "Install: sudo apt install python3 python3-pip"
        exit 1
    fi

    python_version=$(python3 --version | cut -d' ' -f2)
    print_success "Python $python_version installed"
}

# Install Python dependencies
install_dependencies() {
    print_info "Installing Python dependencies..."

    if [ -f "$PROJECT_ROOT/requirements.txt" ]; then
        pip3 install -r "$PROJECT_ROOT/requirements.txt" --user
        print_success "Python dependencies installed"
    else
        print_warning "requirements.txt not found, skipping"
    fi
}

# Create necessary directories
create_directories() {
    print_info "Creating data directories..."

    DIRS=(
        "$PROJECT_ROOT/data/elasticsearch"
        "$PROJECT_ROOT/data/cowrie/logs"
        "$PROJECT_ROOT/data/cowrie/downloads"
        "$PROJECT_ROOT/data/dionaea/logs"
        "$PROJECT_ROOT/data/dionaea/binaries"
        "$PROJECT_ROOT/data/suricata/logs"
        "$PROJECT_ROOT/data/kibana"
        "$PROJECT_ROOT/infrastructure/elk-stack/geoip"
        "$PROJECT_ROOT/reports/generated"
        "$PROJECT_ROOT/reports/automated"
        "$PROJECT_ROOT/backups"
    )

    for dir in "${DIRS[@]}"; do
        mkdir -p "$dir"
    done

    print_success "Directories created"
}

# Set permissions
set_permissions() {
    print_info "Setting file permissions..."

    # Make scripts executable
    chmod +x "$PROJECT_ROOT"/scripts/*.sh 2>/dev/null || true
    chmod +x "$PROJECT_ROOT"/analysis/*.py 2>/dev/null || true

    # Elasticsearch needs specific permissions
    if [ -d "$PROJECT_ROOT/data/elasticsearch" ]; then
        chmod -R 777 "$PROJECT_ROOT/data/elasticsearch" 2>/dev/null || true
    fi

    print_success "Permissions set"
}

# Download GeoIP databases
setup_geoip() {
    print_info "Checking GeoIP databases..."

    GEOIP_DIR="$PROJECT_ROOT/infrastructure/elk-stack/geoip"

    if [ -f "$GEOIP_DIR/GeoLite2-City.mmdb" ] && [ -f "$GEOIP_DIR/GeoLite2-ASN.mmdb" ]; then
        print_success "GeoIP databases already exist"
        return
    fi

    print_warning "GeoIP databases not found"
    echo ""
    echo "Please download GeoLite2 databases manually:"
    echo "1. Register at: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data"
    echo "2. Download: GeoLite2-City.mmdb and GeoLite2-ASN.mmdb"
    echo "3. Place files in: $GEOIP_DIR/"
    echo ""

    # Alternative: Try to download using MaxMind account key if provided
    if [ -n "$MAXMIND_LICENSE_KEY" ]; then
        print_info "Attempting download with license key..."

        CITY_URL="https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=${MAXMIND_LICENSE_KEY}&suffix=tar.gz"
        ASN_URL="https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-ASN&license_key=${MAXMIND_LICENSE_KEY}&suffix=tar.gz"

        cd "$GEOIP_DIR"

        curl -o city.tar.gz "$CITY_URL" && \
        tar -xzf city.tar.gz --strip-components=1 && \
        rm city.tar.gz

        curl -o asn.tar.gz "$ASN_URL" && \
        tar -xzf asn.tar.gz --strip-components=1 && \
        rm asn.tar.gz

        cd "$PROJECT_ROOT"

        if [ -f "$GEOIP_DIR/GeoLite2-City.mmdb" ]; then
            print_success "GeoIP databases downloaded"
        fi
    fi
}

# Check Docker
check_docker() {
    print_info "Checking Docker installation..."

    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed"
        echo ""
        echo "Install Docker:"
        echo "  curl -fsSL https://get.docker.com -o get-docker.sh"
        echo "  sudo sh get-docker.sh"
        echo "  sudo usermod -aG docker \$USER"
        echo ""
        exit 1
    fi

    docker_version=$(docker --version | cut -d' ' -f3 | tr -d ',')
    print_success "Docker $docker_version installed"

    # Check if user is in docker group
    if ! groups | grep -q docker; then
        print_warning "Current user not in 'docker' group"
        echo "Run: sudo usermod -aG docker \$USER"
        echo "Then log out and back in"
    fi
}

# Check Docker Compose
check_docker_compose() {
    print_info "Checking Docker Compose..."

    if command -v docker-compose &> /dev/null; then
        compose_version=$(docker-compose --version | cut -d' ' -f3 | tr -d ',')
        print_success "Docker Compose $compose_version installed"
    elif docker compose version &> /dev/null; then
        compose_version=$(docker compose version --short)
        print_success "Docker Compose v2 (plugin) $compose_version installed"
    else
        print_error "Docker Compose is not installed"
        echo ""
        echo "Install Docker Compose:"
        echo "  sudo curl -L \"https://github.com/docker/compose/releases/latest/download/docker-compose-\$(uname -s)-\$(uname -m)\" -o /usr/local/bin/docker-compose"
        echo "  sudo chmod +x /usr/local/bin/docker-compose"
        echo ""
        exit 1
    fi
}

# Validate configurations
validate_configs() {
    print_info "Validating configurations..."

    # Check docker-compose.yml syntax
    if cd "$PROJECT_ROOT/infrastructure" && docker-compose config > /dev/null 2>&1; then
        print_success "docker-compose.yml is valid"
    else
        print_error "docker-compose.yml has syntax errors"
        cd "$PROJECT_ROOT/infrastructure" && docker-compose config
        exit 1
    fi

    cd "$PROJECT_ROOT"

    # Validate Python scripts
    for script in "$PROJECT_ROOT"/analysis/*.py; do
        if python3 -m py_compile "$script" 2>/dev/null; then
            print_success "$(basename "$script") syntax OK"
        else
            print_error "$(basename "$script") has syntax errors"
        fi
    done
}

# Create environment file template
create_env_template() {
    print_info "Creating environment file template..."

    ENV_FILE="$PROJECT_ROOT/.env.example"

    cat > "$ENV_FILE" << 'EOF'
# Environment Configuration for Honeypot Infrastructure
# Copy to .env and customize

# Elasticsearch
ES_JAVA_OPTS=-Xms2g -Xmx2g
ELASTICSEARCH_HOST=localhost
ELASTICSEARCH_PORT=9200

# Logstash
LS_JAVA_OPTS=-Xms1g -Xmx1g

# MaxMind GeoIP (optional - for automatic downloads)
# Get key from: https://www.maxmind.com/en/accounts/current/license-key
# MAXMIND_LICENSE_KEY=your_license_key_here

# Slack notifications (optional)
# SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL

# Timezone
TZ=UTC

# Log levels
LOG_LEVEL=INFO
EOF

    print_success "Created .env.example template"

    if [ ! -f "$PROJECT_ROOT/.env" ]; then
        cp "$ENV_FILE" "$PROJECT_ROOT/.env"
        print_success "Created .env file (customize as needed)"
    fi
}

# Summary
print_summary() {
    echo ""
    echo -e "${GREEN}"
    echo "================================================================"
    echo "  SETUP COMPLETE!"
    echo "================================================================"
    echo -e "${NC}"
    echo ""
    echo "Next Steps:"
    echo "  1. Customize .env file (optional): nano .env"
    echo "  2. Download GeoIP databases if not done"
    echo "  3. Deploy infrastructure: ./scripts/deploy.sh"
    echo "  4. Or use Make: make deploy"
    echo ""
    echo "Quick Commands:"
    echo "  make help        - Show all available commands"
    echo "  make deploy      - Deploy infrastructure"
    echo "  make status      - Check service status"
    echo "  make monitor     - Real-time monitoring"
    echo ""
}

# Main execution
main() {
    check_python
    check_docker
    check_docker_compose
    create_directories
    set_permissions
    install_dependencies
    setup_geoip
    validate_configs
    create_env_template
    print_summary
}

main
