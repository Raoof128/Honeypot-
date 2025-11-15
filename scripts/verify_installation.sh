#!/bin/bash
#
# Installation Verification Script
# Comprehensive health check for honeypot infrastructure
#
# Usage: ./verify_installation.sh
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Counters
TOTAL_CHECKS=0
PASSED_CHECKS=0
FAILED_CHECKS=0
WARNING_CHECKS=0

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Default values
ES_HOST="localhost:9200"
KIBANA_HOST="localhost:5601"

echo -e "${BLUE}"
echo "================================================================"
echo "  HONEYPOT INFRASTRUCTURE - INSTALLATION VERIFICATION"
echo "================================================================"
echo -e "${NC}"
echo "Running comprehensive health checks..."
echo ""

# Helper functions
check_start() {
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    echo -n -e "${CYAN}[?]${NC} $1... "
}

check_pass() {
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
    echo -e "${GREEN}[✓] PASS${NC}"
    [ -n "$1" ] && echo "    $1"
}

check_fail() {
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
    echo -e "${RED}[✗] FAIL${NC}"
    [ -n "$1" ] && echo -e "    ${RED}$1${NC}"
}

check_warning() {
    WARNING_CHECKS=$((WARNING_CHECKS + 1))
    echo -e "${YELLOW}[!] WARNING${NC}"
    [ -n "$1" ] && echo -e "    ${YELLOW}$1${NC}"
}

# =============================================================================
# SECTION 1: PREREQUISITES
# =============================================================================

echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}[1] PREREQUISITES${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

# Check Docker
check_start "Docker installed"
if command -v docker &> /dev/null; then
    docker_version=$(docker --version | cut -d' ' -f3 | tr -d ',')
    check_pass "Version: $docker_version"
else
    check_fail "Docker is not installed"
fi

# Check Docker Compose
check_start "Docker Compose installed"
if command -v docker-compose &> /dev/null; then
    compose_version=$(docker-compose --version | cut -d' ' -f3 | tr -d ',')
    check_pass "Version: $compose_version"
else
    check_fail "Docker Compose is not installed"
fi

# Check Python
check_start "Python 3.8+ installed"
if command -v python3 &> /dev/null; then
    python_version=$(python3 --version | cut -d' ' -f2)
    python_major=$(echo "$python_version" | cut -d. -f1)
    python_minor=$(echo "$python_version" | cut -d. -f2)

    if [ "$python_major" -ge 3 ] && [ "$python_minor" -ge 8 ]; then
        check_pass "Version: $python_version"
    else
        check_fail "Python 3.8+ required, found $python_version"
    fi
else
    check_fail "Python 3 is not installed"
fi

# Check disk space
check_start "Sufficient disk space (>20GB free)"
available_gb=$(df -BG "$PROJECT_ROOT" | awk 'NR==2 {print $4}' | tr -d 'G')
if [ "$available_gb" -ge 20 ]; then
    check_pass "Available: ${available_gb}GB"
else
    check_warning "Low disk space: ${available_gb}GB (recommend 20GB+)"
fi

# Check memory
check_start "Sufficient RAM (>8GB)"
total_mem_mb=$(free -m | awk 'NR==2 {print $2}')
total_mem_gb=$((total_mem_mb / 1024))
if [ "$total_mem_gb" -ge 8 ]; then
    check_pass "Total RAM: ${total_mem_gb}GB"
else
    check_warning "Limited RAM: ${total_mem_gb}GB (recommend 8GB+)"
fi

# =============================================================================
# SECTION 2: DOCKER CONTAINERS
# =============================================================================

echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}[2] DOCKER CONTAINERS${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

CONTAINERS=("elasticsearch" "logstash" "kibana" "cowrie" "dionaea" "suricata")

for container in "${CONTAINERS[@]}"; do
    check_start "Container '$container' running"

    if docker ps --filter "name=$container" --filter "status=running" -q | grep -q .; then
        container_id=$(docker ps --filter "name=$container" -q | head -1)
        uptime=$(docker inspect --format='{{.State.StartedAt}}' "$container_id" 2>/dev/null | cut -d'T' -f1)
        check_pass "Running since: $uptime"
    else
        if docker ps -a --filter "name=$container" -q | grep -q .; then
            status=$(docker ps -a --filter "name=$container" --format "{{.Status}}" | head -1)
            check_fail "Container exists but not running ($status)"
        else
            check_fail "Container not found"
        fi
    fi
done

# =============================================================================
# SECTION 3: ELASTICSEARCH
# =============================================================================

echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}[3] ELASTICSEARCH${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

# Check Elasticsearch health
check_start "Elasticsearch health endpoint"
if curl -s "http://$ES_HOST/_cluster/health" > /dev/null 2>&1; then
    cluster_status=$(curl -s "http://$ES_HOST/_cluster/health" | jq -r '.status')
    if [ "$cluster_status" == "green" ]; then
        check_pass "Cluster status: green"
    elif [ "$cluster_status" == "yellow" ]; then
        check_warning "Cluster status: yellow (check replicas)"
    else
        check_fail "Cluster status: $cluster_status"
    fi
else
    check_fail "Elasticsearch not responding"
fi

# Check Elasticsearch indices
check_start "Honeypot indices created"
if curl -s "http://$ES_HOST/_cat/indices/honeypot-*?h=index" > /dev/null 2>&1; then
    index_count=$(curl -s "http://$ES_HOST/_cat/indices/honeypot-*?h=index" | wc -l)
    if [ "$index_count" -gt 0 ]; then
        check_pass "Found $index_count honeypot indices"
    else
        check_warning "No indices found yet (will be created on first log)"
    fi
else
    check_fail "Cannot query Elasticsearch indices"
fi

# Check index templates
check_start "Index templates loaded"
if curl -s "http://$ES_HOST/_index_template" > /dev/null 2>&1; then
    template_count=$(curl -s "http://$ES_HOST/_index_template" | jq -r '.index_templates[].name' | grep -c "honeypot-" || echo "0")
    if [ "$template_count" -gt 0 ]; then
        check_pass "Found $template_count honeypot templates"
    else
        check_warning "No index templates found (run scripts/setup_elasticsearch_templates.sh)"
    fi
else
    check_fail "Cannot query index templates"
fi

# Check Elasticsearch disk space
check_start "Elasticsearch disk usage"
if curl -s "http://$ES_HOST/_nodes/stats/fs" > /dev/null 2>&1; then
    es_disk_used=$(curl -s "http://$ES_HOST/_nodes/stats/fs" | jq -r '.nodes | .[] | .fs.total.total_in_bytes')
    es_disk_available=$(curl -s "http://$ES_HOST/_nodes/stats/fs" | jq -r '.nodes | .[] | .fs.total.available_in_bytes')

    if [ -n "$es_disk_available" ] && [ "$es_disk_available" != "null" ]; then
        es_disk_pct=$((100 - (es_disk_available * 100 / es_disk_used)))
        if [ "$es_disk_pct" -lt 85 ]; then
            check_pass "Disk usage: ${es_disk_pct}%"
        else
            check_warning "High disk usage: ${es_disk_pct}%"
        fi
    else
        check_warning "Cannot determine disk usage"
    fi
else
    check_fail "Cannot query Elasticsearch stats"
fi

# =============================================================================
# SECTION 4: KIBANA
# =============================================================================

echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}[4] KIBANA${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

# Check Kibana health
check_start "Kibana health endpoint"
if curl -s "http://$KIBANA_HOST/api/status" > /dev/null 2>&1; then
    kibana_status=$(curl -s "http://$KIBANA_HOST/api/status" | jq -r '.status.overall.state')
    if [ "$kibana_status" == "green" ]; then
        check_pass "Kibana status: green"
    elif [ "$kibana_status" == "yellow" ]; then
        check_warning "Kibana status: yellow"
    else
        check_fail "Kibana status: $kibana_status"
    fi
else
    check_fail "Kibana not responding"
fi

# Check Kibana version
check_start "Kibana version compatibility"
if curl -s "http://$KIBANA_HOST/api/status" > /dev/null 2>&1; then
    kibana_version=$(curl -s "http://$KIBANA_HOST/api/status" | jq -r '.version.number')
    check_pass "Version: $kibana_version"
else
    check_fail "Cannot determine Kibana version"
fi

# =============================================================================
# SECTION 5: LOGSTASH
# =============================================================================

echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}[5] LOGSTASH${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

# Check Logstash API
check_start "Logstash API responding"
if curl -s "http://localhost:9600/_node/stats" > /dev/null 2>&1; then
    check_pass "Logstash API accessible"
else
    check_fail "Logstash API not responding"
fi

# Check Logstash pipeline
check_start "Logstash pipeline running"
if curl -s "http://localhost:9600/_node/stats/pipelines" > /dev/null 2>&1; then
    pipeline_status=$(curl -s "http://localhost:9600/_node/stats/pipelines" | jq -r '.pipelines | keys[]' | head -1)
    if [ -n "$pipeline_status" ]; then
        check_pass "Pipeline active: $pipeline_status"
    else
        check_fail "No active pipelines"
    fi
else
    check_fail "Cannot query Logstash pipelines"
fi

# =============================================================================
# SECTION 6: HONEYPOTS
# =============================================================================

echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}[6] HONEYPOTS${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

# Check Cowrie SSH port
check_start "Cowrie SSH port (2222) listening"
if nc -z localhost 2222 2>/dev/null; then
    check_pass "Port 2222 is open"
else
    check_fail "Port 2222 is not accessible"
fi

# Check Cowrie Telnet port
check_start "Cowrie Telnet port (2223) listening"
if nc -z localhost 2223 2>/dev/null; then
    check_pass "Port 2223 is open"
else
    check_fail "Port 2223 is not accessible"
fi

# Check Cowrie logs
check_start "Cowrie logging directory exists"
if [ -d "$PROJECT_ROOT/data/cowrie/logs" ]; then
    log_count=$(find "$PROJECT_ROOT/data/cowrie/logs" -type f -name "*.json" 2>/dev/null | wc -l)
    if [ "$log_count" -gt 0 ]; then
        check_pass "Found $log_count log files"
    else
        check_warning "No log files yet (will be created on first connection)"
    fi
else
    check_fail "Cowrie logs directory not found"
fi

# Check Dionaea FTP port
check_start "Dionaea FTP port (21) listening"
if nc -z localhost 21 2>/dev/null; then
    check_pass "Port 21 is open"
else
    check_warning "Port 21 is not accessible (may require root)"
fi

# Check Dionaea HTTP port
check_start "Dionaea HTTP port (80) listening"
if nc -z localhost 80 2>/dev/null; then
    check_pass "Port 80 is open"
else
    check_warning "Port 80 is not accessible (may require root)"
fi

# =============================================================================
# SECTION 7: PYTHON ANALYSIS SCRIPTS
# =============================================================================

echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}[7] PYTHON ANALYSIS SCRIPTS${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

# Check Python dependencies
check_start "Python requirements installed"
if python3 -c "import elasticsearch, geoip2, stix2, pandas" 2>/dev/null; then
    check_pass "All required Python packages installed"
else
    check_fail "Missing Python dependencies (run: pip3 install -r requirements.txt)"
fi

# Check analysis scripts
SCRIPTS=("ioc_extraction.py" "geolocation_mapper.py" "mitre_attck_mapper.py" "threat_feed_generator.py")
missing_scripts=0

for script in "${SCRIPTS[@]}"; do
    check_start "Analysis script: $script"
    if [ -f "$PROJECT_ROOT/analysis/$script" ]; then
        check_pass "Script exists"
    else
        check_fail "Script not found"
        missing_scripts=$((missing_scripts + 1))
    fi
done

# =============================================================================
# SECTION 8: GEOIP DATABASES
# =============================================================================

echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}[8] GEOIP DATABASES${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

# Check GeoLite2 City
check_start "GeoLite2-City.mmdb exists"
if [ -f "$PROJECT_ROOT/data/geoip/GeoLite2-City.mmdb" ]; then
    file_size=$(du -h "$PROJECT_ROOT/data/geoip/GeoLite2-City.mmdb" | cut -f1)
    check_pass "Database size: $file_size"
else
    check_fail "GeoLite2-City.mmdb not found (run scripts/setup.sh)"
fi

# Check GeoLite2 ASN
check_start "GeoLite2-ASN.mmdb exists"
if [ -f "$PROJECT_ROOT/data/geoip/GeoLite2-ASN.mmdb" ]; then
    file_size=$(du -h "$PROJECT_ROOT/data/geoip/GeoLite2-ASN.mmdb" | cut -f1)
    check_pass "Database size: $file_size"
else
    check_fail "GeoLite2-ASN.mmdb not found (run scripts/setup.sh)"
fi

# =============================================================================
# SECTION 9: FILE PERMISSIONS
# =============================================================================

echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}[9] FILE PERMISSIONS${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

# Check script executability
SHELL_SCRIPTS=("deploy.sh" "monitor.sh" "generate_report.sh" "setup.sh" "cleanup.sh" "diagnostics.sh")

for script in "${SHELL_SCRIPTS[@]}"; do
    check_start "Script $script is executable"
    if [ -x "$PROJECT_ROOT/scripts/$script" ]; then
        check_pass "Executable permissions set"
    else
        check_warning "Not executable (run: chmod +x scripts/$script)"
    fi
done

# =============================================================================
# SECTION 10: NETWORK CONFIGURATION
# =============================================================================

echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}[10] NETWORK CONFIGURATION${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

# Check Docker networks
check_start "Docker honeypot network exists"
if docker network ls | grep -q "honeypot_network"; then
    check_pass "honeypot_network exists"
else
    check_fail "honeypot_network not found"
fi

check_start "Docker ELK network exists"
if docker network ls | grep -q "elk_network"; then
    check_pass "elk_network exists"
else
    check_fail "elk_network not found"
fi

# Check port conflicts
check_start "No port conflicts detected"
conflicts=""
for port in 9200 5601 2222 2223 21 80 443; do
    if netstat -tuln 2>/dev/null | grep -q ":$port " && ! docker ps --format "{{.Ports}}" | grep -q "$port"; then
        conflicts="$conflicts $port"
    fi
done

if [ -z "$conflicts" ]; then
    check_pass "All ports available"
else
    check_warning "Potential port conflicts:$conflicts"
fi

# =============================================================================
# FINAL SUMMARY
# =============================================================================

echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}VERIFICATION SUMMARY${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

echo ""
echo "Total checks: $TOTAL_CHECKS"
echo -e "${GREEN}Passed:       $PASSED_CHECKS${NC}"
echo -e "${YELLOW}Warnings:     $WARNING_CHECKS${NC}"
echo -e "${RED}Failed:       $FAILED_CHECKS${NC}"
echo ""

if [ "$FAILED_CHECKS" -eq 0 ]; then
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}✓ INSTALLATION VERIFIED SUCCESSFULLY${NC}"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo "Your honeypot infrastructure is fully operational!"
    echo ""
    echo "Next steps:"
    echo "  1. Access Kibana: http://localhost:5601"
    echo "  2. Start monitoring: ./scripts/monitor.sh"
    echo "  3. Test honeypots: ssh root@localhost -p 2222"
    echo ""
    exit 0
elif [ "$WARNING_CHECKS" -gt 0 ] && [ "$FAILED_CHECKS" -eq 0 ]; then
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${YELLOW}! INSTALLATION VERIFIED WITH WARNINGS${NC}"
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo "Installation is functional but has warnings."
    echo "Review warnings above and address if necessary."
    echo ""
    exit 0
else
    echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${RED}✗ INSTALLATION VERIFICATION FAILED${NC}"
    echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo "Please review the failed checks above and:"
    echo "  1. Check logs: docker-compose logs [service]"
    echo "  2. Run diagnostics: ./scripts/diagnostics.sh"
    echo "  3. Consult docs/TROUBLESHOOTING.md"
    echo ""
    exit 1
fi
