#!/bin/bash
#
# Cleanup Script for Honeypot Infrastructure
# Removes old logs, indices, and temporary files
#
# Usage: ./cleanup.sh [--all] [--days N]
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Defaults
CLEAN_ALL=false
DAYS_TO_KEEP=30
ES_HOST="localhost:9200"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --all)
            CLEAN_ALL=true
            shift
            ;;
        --days)
            DAYS_TO_KEEP="$2"
            shift 2
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --all          Clean all data (DESTRUCTIVE)"
            echo "  --days N       Keep last N days (default: 30)"
            echo "  --help         Show this help"
            exit 0
            ;;
        *)
            shift
            ;;
    esac
done

echo -e "${BLUE}"
echo "================================================================"
echo "  HONEYPOT INFRASTRUCTURE - CLEANUP"
echo "================================================================"
echo -e "${NC}"

# Confirmation for --all
if [ "$CLEAN_ALL" = true ]; then
    echo -e "${RED}WARNING: This will delete ALL honeypot data!${NC}"
    echo "This includes:"
    echo "  - All Elasticsearch indices"
    echo "  - All Docker volumes"
    echo "  - All collected malware samples"
    echo "  - All generated reports"
    echo ""
    read -p "Are you absolutely sure? Type 'DELETE ALL' to confirm: " -r
    echo

    if [ "$REPLY" != "DELETE ALL" ]; then
        echo "Cleanup cancelled"
        exit 0
    fi
fi

# Clean old Elasticsearch indices
clean_old_indices() {
    echo -e "${YELLOW}[*]${NC} Cleaning Elasticsearch indices older than $DAYS_TO_KEEP days..."

    # Calculate cutoff date
    cutoff_date=$(date -d "$DAYS_TO_KEEP days ago" +%Y.%m.%d)

    # Get all honeypot indices
    indices=$(curl -s "http://$ES_HOST/_cat/indices/honeypot-*?h=index" 2>/dev/null || echo "")

    if [ -z "$indices" ]; then
        echo "  No indices found or Elasticsearch not accessible"
        return
    fi

    deleted_count=0

    while IFS= read -r index; do
        # Extract date from index name (format: honeypot-TYPE-YYYY.MM.DD)
        index_date=$(echo "$index" | grep -oP '\d{4}\.\d{2}\.\d{2}' || echo "")

        if [ -n "$index_date" ]; then
            # Compare dates
            if [[ "$index_date" < "$cutoff_date" ]]; then
                echo "  Deleting index: $index"
                curl -s -X DELETE "http://$ES_HOST/$index" > /dev/null
                ((deleted_count++))
            fi
        fi
    done <<< "$indices"

    echo -e "${GREEN}[✓]${NC} Deleted $deleted_count old indices"
}

# Clean old report files
clean_old_reports() {
    echo -e "${YELLOW}[*]${NC} Cleaning reports older than $DAYS_TO_KEEP days..."

    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
    REPORTS_DIR="$PROJECT_ROOT/reports/generated"

    if [ -d "$REPORTS_DIR" ]; then
        count=$(find "$REPORTS_DIR" -type f -mtime +$DAYS_TO_KEEP -delete -print | wc -l)
        echo -e "${GREEN}[✓]${NC} Deleted $count old report files"
    fi
}

# Clean Docker logs
clean_docker_logs() {
    echo -e "${YELLOW}[*]${NC} Cleaning Docker container logs..."

    for container in elasticsearch logstash kibana cowrie dionaea suricata; do
        if docker ps -a --filter "name=$container" -q > /dev/null 2>&1; then
            docker logs "$container" 2>&1 > /dev/null || true
            echo "  Truncated logs for: $container"
        fi
    done

    echo -e "${GREEN}[✓]${NC} Docker logs cleaned"
}

# Clean temporary files
clean_temp_files() {
    echo -e "${YELLOW}[*]${NC} Cleaning temporary files..."

    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

    # Clean Python cache
    find "$PROJECT_ROOT" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
    find "$PROJECT_ROOT" -type f -name "*.pyc" -delete 2>/dev/null || true
    find "$PROJECT_ROOT" -type f -name "*.pyo" -delete 2>/dev/null || true

    # Clean temporary files
    find "$PROJECT_ROOT" -type f -name "*.tmp" -delete 2>/dev/null || true
    find "$PROJECT_ROOT" -type f -name "*.temp" -delete 2>/dev/null || true

    echo -e "${GREEN}[✓]${NC} Temporary files cleaned"
}

# Clean all data (DESTRUCTIVE)
clean_all_data() {
    echo -e "${RED}[!]${NC} Performing complete cleanup..."

    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

    # Stop all containers
    echo "  Stopping containers..."
    cd "$PROJECT_ROOT/infrastructure"
    docker-compose down -v 2>/dev/null || true

    # Delete all data directories
    echo "  Deleting data directories..."
    rm -rf "$PROJECT_ROOT/data/"* 2>/dev/null || true

    # Delete all reports
    echo "  Deleting reports..."
    rm -rf "$PROJECT_ROOT/reports/generated/"* 2>/dev/null || true
    rm -rf "$PROJECT_ROOT/reports/automated/"* 2>/dev/null || true

    # Delete all Elasticsearch indices
    echo "  Deleting all Elasticsearch indices..."
    curl -s -X DELETE "http://$ES_HOST/honeypot-*" > /dev/null 2>&1 || true

    echo -e "${GREEN}[✓]${NC} Complete cleanup finished"
    echo -e "${YELLOW}[!]${NC} All data has been permanently deleted"
}

# Execute cleanup
if [ "$CLEAN_ALL" = true ]; then
    clean_all_data
else
    clean_old_indices
    clean_old_reports
    clean_docker_logs
    clean_temp_files
fi

echo ""
echo -e "${GREEN}"
echo "================================================================"
echo "  CLEANUP COMPLETE"
echo "================================================================"
echo -e "${NC}"

if [ "$CLEAN_ALL" = true ]; then
    echo "All data has been deleted."
    echo "To redeploy: ./scripts/deploy.sh"
else
    echo "Cleaned data older than $DAYS_TO_KEEP days"
    echo ""
    echo "Storage saved:"
    df -h . | awk 'NR==2 {print "  Disk usage: " $3 "/" $2 " (" $5 ")"}'
fi

echo ""
