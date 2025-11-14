#!/bin/bash
#
# Honeypot Infrastructure Diagnostics
# Comprehensive system health check and troubleshooting
#
# Usage: ./diagnostics.sh [--verbose]
#

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

VERBOSE=false

# Parse arguments
for arg in "$@"; do
    case $arg in
        --verbose|-v)
            VERBOSE=true
            shift
            ;;
    esac
done

# Helper functions
print_header() {
    echo ""
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}========================================${NC}"
}

print_check() {
    if [ "$2" = "OK" ]; then
        echo -e "${GREEN}[✓]${NC} $1"
    elif [ "$2" = "WARN" ]; then
        echo -e "${YELLOW}[!]${NC} $1"
    else
        echo -e "${RED}[✗]${NC} $1"
    fi
}

# Banner
echo -e "${BLUE}"
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║  HONEYPOT INFRASTRUCTURE - DIAGNOSTICS                         ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo "Timestamp: $(date '+%Y-%m-%d %H:%M:%S %Z')"
echo ""

# System Information
print_header "SYSTEM INFORMATION"

echo "Hostname: $(hostname)"
echo "OS: $(uname -s) $(uname -r)"
echo "Architecture: $(uname -m)"
echo "Uptime: $(uptime -p 2>/dev/null || uptime)"

if command -v lsb_release &> /dev/null; then
    echo "Distribution: $(lsb_release -d | cut -f2-)"
fi

echo ""
echo "CPU Cores: $(nproc)"
echo "Total RAM: $(free -h | awk '/^Mem:/ {print $2}')"
echo "Available RAM: $(free -h | awk '/^Mem:/ {print $7}')"
echo "Disk Usage: $(df -h . | awk 'NR==2 {print $3 "/" $2 " (" $5 ")"}')"

# Docker Status
print_header "DOCKER STATUS"

if command -v docker &> /dev/null; then
    docker_version=$(docker --version | cut -d' ' -f3 | tr -d ',')
    print_check "Docker installed (v$docker_version)" "OK"

    if docker info > /dev/null 2>&1; then
        print_check "Docker daemon running" "OK"

        echo ""
        echo "Docker Info:"
        echo "  Images: $(docker images -q | wc -l)"
        echo "  Containers: $(docker ps -a -q | wc -l)"
        echo "  Running: $(docker ps -q | wc -l)"
        echo "  Volumes: $(docker volume ls -q | wc -l)"
    else
        print_check "Docker daemon not accessible" "FAIL"
        echo "  Try: sudo systemctl start docker"
    fi
else
    print_check "Docker not installed" "FAIL"
fi

if command -v docker-compose &> /dev/null; then
    compose_version=$(docker-compose --version | cut -d' ' -f3 | tr -d ',')
    print_check "Docker Compose installed (v$compose_version)" "OK"
elif docker compose version &> /dev/null 2>&1; then
    compose_version=$(docker compose version --short)
    print_check "Docker Compose v2 installed (v$compose_version)" "OK"
else
    print_check "Docker Compose not installed" "FAIL"
fi

# Container Status
print_header "CONTAINER STATUS"

if docker ps > /dev/null 2>&1; then
    containers=(
        "elasticsearch"
        "logstash"
        "kibana"
        "cowrie"
        "dionaea"
        "suricata"
    )

    for container in "${containers[@]}"; do
        if docker ps --filter "name=$container" --filter "status=running" --format "{{.Names}}" | grep -q "$container"; then
            uptime=$(docker ps --filter "name=$container" --format "{{.Status}}")
            print_check "$container: $uptime" "OK"
        elif docker ps -a --filter "name=$container" --format "{{.Names}}" | grep -q "$container"; then
            status=$(docker ps -a --filter "name=$container" --format "{{.Status}}")
            print_check "$container: $status" "FAIL"
        else
            print_check "$container: Not deployed" "WARN"
        fi
    done
else
    print_check "Cannot query containers" "FAIL"
fi

# Service Health Checks
print_header "SERVICE HEALTH"

# Elasticsearch
if curl -s -f http://localhost:9200/_cluster/health > /dev/null 2>&1; then
    es_status=$(curl -s http://localhost:9200/_cluster/health | jq -r '.status' 2>/dev/null || echo "unknown")
    es_nodes=$(curl -s http://localhost:9200/_cluster/health | jq -r '.number_of_nodes' 2>/dev/null || echo "?")

    if [ "$es_status" = "green" ]; then
        print_check "Elasticsearch: $es_status ($es_nodes nodes)" "OK"
    elif [ "$es_status" = "yellow" ]; then
        print_check "Elasticsearch: $es_status ($es_nodes nodes) - Normal for single node" "WARN"
    else
        print_check "Elasticsearch: $es_status ($es_nodes nodes)" "FAIL"
    fi

    if [ "$VERBOSE" = true ]; then
        echo "  $(curl -s http://localhost:9200 | jq -r '.version.number' 2>/dev/null)"
    fi
else
    print_check "Elasticsearch: Not responding on :9200" "FAIL"
fi

# Kibana
if curl -s -f http://localhost:5601/api/status > /dev/null 2>&1; then
    kibana_status=$(curl -s http://localhost:5601/api/status | jq -r '.status.overall.level' 2>/dev/null || echo "unknown")

    if [ "$kibana_status" = "available" ]; then
        print_check "Kibana: available" "OK"
    else
        print_check "Kibana: $kibana_status" "WARN"
    fi
else
    print_check "Kibana: Not responding on :5601" "FAIL"
fi

# Logstash
if curl -s -f http://localhost:9600/_node/stats > /dev/null 2>&1; then
    ls_events_in=$(curl -s http://localhost:9600/_node/stats/pipelines | jq -r '.pipelines.main.events.in' 2>/dev/null || echo "0")
    ls_events_out=$(curl -s http://localhost:9600/_node/stats/pipelines | jq -r '.pipelines.main.events.out' 2>/dev/null || echo "0")

    print_check "Logstash: responding (in: $ls_events_in, out: $ls_events_out)" "OK"

    if [ "$ls_events_in" -eq 0 ]; then
        print_check "  Warning: No events received yet" "WARN"
    fi
else
    print_check "Logstash: Not responding on :9600" "FAIL"
fi

# Network Ports
print_header "NETWORK PORTS"

check_port() {
    local port=$1
    local service=$2

    if netstat -tuln 2>/dev/null | grep -q ":$port " || lsof -i ":$port" > /dev/null 2>&1; then
        print_check "Port $port ($service): LISTENING" "OK"
    else
        print_check "Port $port ($service): NOT LISTENING" "WARN"
    fi
}

check_port 9200 "Elasticsearch"
check_port 5601 "Kibana"
check_port 9600 "Logstash"
check_port 2222 "Cowrie SSH"
check_port 2223 "Cowrie Telnet"
check_port 80 "Dionaea HTTP"
check_port 443 "Dionaea HTTPS"
check_port 3306 "Dionaea MySQL"

# Data Analysis
print_header "DATA ANALYSIS"

if curl -s http://localhost:9200/_cat/indices > /dev/null 2>&1; then
    indices_count=$(curl -s "http://localhost:9200/_cat/indices/honeypot-*" | wc -l)
    print_check "Honeypot indices: $indices_count" "OK"

    total_events=$(curl -s "http://localhost:9200/honeypot-*/_count" | jq -r '.count' 2>/dev/null || echo "0")
    print_check "Total events indexed: $total_events" "OK"

    if [ "$total_events" -eq 0 ]; then
        print_check "  Warning: No events collected yet" "WARN"
        echo "    - Wait 15-30 minutes for attacks to be logged"
        echo "    - Or test: ssh root@localhost -p 2222"
    fi

    if [ "$VERBOSE" = true ] && [ "$total_events" -gt 0 ]; then
        echo ""
        echo "  Events by honeypot:"
        for index_pattern in "cowrie" "dionaea" "suricata"; do
            count=$(curl -s "http://localhost:9200/honeypot-${index_pattern}-*/_count" | jq -r '.count' 2>/dev/null || echo "0")
            echo "    - $index_pattern: $count"
        done
    fi
else
    print_check "Cannot query Elasticsearch indices" "FAIL"
fi

# File System Checks
print_header "FILE SYSTEM"

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

check_directory() {
    local dir=$1
    local desc=$2

    if [ -d "$dir" ]; then
        size=$(du -sh "$dir" 2>/dev/null | cut -f1)
        print_check "$desc: $size" "OK"
    else
        print_check "$desc: Missing" "WARN"
    fi
}

check_directory "$PROJECT_ROOT/data/elasticsearch" "Elasticsearch data"
check_directory "$PROJECT_ROOT/data/cowrie" "Cowrie data"
check_directory "$PROJECT_ROOT/data/dionaea" "Dionaea data"

# Check for GeoIP databases
if [ -f "$PROJECT_ROOT/infrastructure/elk-stack/geoip/GeoLite2-City.mmdb" ]; then
    print_check "GeoIP City database" "OK"
else
    print_check "GeoIP City database: Missing" "WARN"
    echo "    Download from: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data"
fi

if [ -f "$PROJECT_ROOT/infrastructure/elk-stack/geoip/GeoLite2-ASN.mmdb" ]; then
    print_check "GeoIP ASN database" "OK"
else
    print_check "GeoIP ASN database: Missing" "WARN"
fi

# Python Dependencies
print_header "PYTHON DEPENDENCIES"

if command -v python3 &> /dev/null; then
    python_version=$(python3 --version | cut -d' ' -f2)
    print_check "Python $python_version" "OK"

    # Check critical packages
    for package in "elasticsearch" "geoip2" "stix2"; do
        if python3 -c "import $package" 2>/dev/null; then
            version=$(python3 -c "import $package; print($package.__version__)" 2>/dev/null || echo "")
            print_check "Python package: $package $version" "OK"
        else
            print_check "Python package: $package - Not installed" "WARN"
            echo "    Install: pip3 install $package"
        fi
    done
else
    print_check "Python 3 not installed" "FAIL"
fi

# Resource Usage
print_header "RESOURCE USAGE"

echo "Docker Container Resources:"
if docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}" 2>/dev/null | grep -E "elasticsearch|logstash|kibana|cowrie|dionaea"; then
    :
else
    echo "  No containers running"
fi

# Recent Logs (errors)
print_header "RECENT ERRORS"

if docker ps > /dev/null 2>&1; then
    echo "Checking for errors in logs (last 50 lines)..."

    for container in elasticsearch logstash kibana; do
        if docker ps --filter "name=$container" --filter "status=running" -q > /dev/null 2>&1; then
            error_count=$(docker logs --tail 50 "$container" 2>&1 | grep -i error | wc -l)

            if [ "$error_count" -gt 0 ]; then
                print_check "$container: $error_count errors found" "WARN"

                if [ "$VERBOSE" = true ]; then
                    echo "  Last errors:"
                    docker logs --tail 50 "$container" 2>&1 | grep -i error | tail -3 | sed 's/^/    /'
                fi
            else
                print_check "$container: No recent errors" "OK"
            fi
        fi
    done
fi

# Configuration Validation
print_header "CONFIGURATION VALIDATION"

# Validate docker-compose.yml
if [ -f "$PROJECT_ROOT/infrastructure/docker-compose.yml" ]; then
    if cd "$PROJECT_ROOT/infrastructure" && docker-compose config > /dev/null 2>&1; then
        print_check "docker-compose.yml syntax" "OK"
    else
        print_check "docker-compose.yml has errors" "FAIL"
    fi
    cd - > /dev/null
else
    print_check "docker-compose.yml not found" "FAIL"
fi

# Validate Python scripts
python_errors=0
for script in "$PROJECT_ROOT"/analysis/*.py; do
    if [ -f "$script" ]; then
        if python3 -m py_compile "$script" 2>/dev/null; then
            :
        else
            ((python_errors++))
        fi
    fi
done

if [ "$python_errors" -eq 0 ]; then
    print_check "Python scripts syntax" "OK"
else
    print_check "Python scripts: $python_errors errors" "FAIL"
fi

# Summary
print_header "SUMMARY"

echo "Diagnostic scan complete!"
echo ""
echo "Recommendations:"

# Check if any containers are not running
if docker ps 2>/dev/null | grep -qE "elasticsearch|logstash|kibana|cowrie|dionaea"; then
    echo "  ✓ Core services are running"
else
    echo "  ! Deploy infrastructure: ./scripts/deploy.sh"
fi

# Check if events are being collected
total_events=$(curl -s "http://localhost:9200/honeypot-*/_count" 2>/dev/null | jq -r '.count' 2>/dev/null || echo "0")
if [ "$total_events" -gt 0 ]; then
    echo "  ✓ Events are being collected ($total_events total)"
else
    echo "  ! No events yet - wait or test manually"
fi

# Check GeoIP
if [ ! -f "$PROJECT_ROOT/infrastructure/elk-stack/geoip/GeoLite2-City.mmdb" ]; then
    echo "  ! Download GeoIP databases for geographic analysis"
fi

echo ""
echo "For detailed logs: docker-compose -f infrastructure/docker-compose.yml logs -f"
echo "For monitoring: ./scripts/monitor.sh"
echo ""
