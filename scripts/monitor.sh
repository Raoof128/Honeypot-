#!/bin/bash
#
# Honeypot Infrastructure Monitoring Script
# Real-time monitoring of honeypot activity and system health
#
# Usage: ./monitor.sh [--interval SECONDS] [--alerts]
#
# Author: Threat Intelligence Pipeline
# Version: 1.0.0
#

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
INTERVAL=10
SHOW_ALERTS=false
ES_HOST="localhost:9200"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --interval)
            INTERVAL="$2"
            shift 2
            ;;
        --alerts)
            SHOW_ALERTS=true
            shift
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --interval SECONDS   Update interval (default: 10)"
            echo "  --alerts             Show recent alerts"
            echo "  --help               Show this help message"
            exit 0
            ;;
        *)
            shift
            ;;
    esac
done

# Functions
get_docker_status() {
    local container=$1
    if docker ps --filter "name=$container" --filter "status=running" --format "{{.Names}}" | grep -q "$container"; then
        echo -e "${GREEN}RUNNING${NC}"
    else
        echo -e "${RED}STOPPED${NC}"
    fi
}

get_event_count() {
    local index=$1
    local hours=$2

    count=$(curl -s "http://$ES_HOST/${index}/_count?q=@timestamp:[now-${hours}h TO now]" | jq -r '.count' 2>/dev/null)

    if [ -z "$count" ] || [ "$count" == "null" ]; then
        echo "0"
    else
        echo "$count"
    fi
}

get_unique_ips() {
    local hours=$1

    unique_ips=$(curl -s "http://$ES_HOST/honeypot-*/_search" -H 'Content-Type: application/json' -d '{
      "size": 0,
      "query": {
        "range": {
          "@timestamp": {
            "gte": "now-'$hours'h"
          }
        }
      },
      "aggs": {
        "unique_ips": {
          "cardinality": {
            "field": "attacker_ip.keyword"
          }
        }
      }
    }' 2>/dev/null | jq -r '.aggregations.unique_ips.value' 2>/dev/null)

    if [ -z "$unique_ips" ] || [ "$unique_ips" == "null" ]; then
        echo "0"
    else
        echo "$unique_ips"
    fi
}

get_top_countries() {
    curl -s "http://$ES_HOST/honeypot-*/_search" -H 'Content-Type: application/json' -d '{
      "size": 0,
      "query": {
        "range": {
          "@timestamp": {
            "gte": "now-24h"
          }
        }
      },
      "aggs": {
        "top_countries": {
          "terms": {
            "field": "geoip.country_name.keyword",
            "size": 5
          }
        }
      }
    }' 2>/dev/null | jq -r '.aggregations.top_countries.buckets[] | "\(.key): \(.doc_count)"' 2>/dev/null
}

# Main monitoring loop
clear
echo -e "${BLUE}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  T-POT HONEYPOT INFRASTRUCTURE - REAL-TIME MONITOR            ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════════╝${NC}"
echo ""

while true; do
    # System Health
    echo -e "${YELLOW}[SYSTEM HEALTH]${NC}"
    echo "────────────────────────────────────────────────────────────────"
    printf "%-20s %s\n" "Elasticsearch:" "$(get_docker_status elasticsearch)"
    printf "%-20s %s\n" "Logstash:" "$(get_docker_status logstash)"
    printf "%-20s %s\n" "Kibana:" "$(get_docker_status kibana)"
    printf "%-20s %s\n" "Cowrie:" "$(get_docker_status cowrie)"
    printf "%-20s %s\n" "Dionaea:" "$(get_docker_status dionaea)"
    printf "%-20s %s\n" "Suricata:" "$(get_docker_status suricata)"
    echo ""

    # Attack Statistics
    echo -e "${YELLOW}[ATTACK STATISTICS]${NC}"
    echo "────────────────────────────────────────────────────────────────"

    events_1h=$(get_event_count "honeypot-*" 1)
    events_24h=$(get_event_count "honeypot-*" 24)
    unique_ips_24h=$(get_unique_ips 24)

    printf "%-30s %s\n" "Events (Last Hour):" "$events_1h"
    printf "%-30s %s\n" "Events (Last 24 Hours):" "$events_24h"
    printf "%-30s %s\n" "Unique Attacker IPs (24h):" "$unique_ips_24h"
    echo ""

    # Honeypot-specific stats
    cowrie_events=$(get_event_count "honeypot-cowrie-*" 24)
    dionaea_events=$(get_event_count "honeypot-dionaea-*" 24)
    suricata_alerts=$(get_event_count "honeypot-suricata-*" 24)

    printf "%-30s %s\n" "Cowrie SSH/Telnet (24h):" "$cowrie_events"
    printf "%-30s %s\n" "Dionaea Multi-Protocol (24h):" "$dionaea_events"
    printf "%-30s %s\n" "Suricata IDS Alerts (24h):" "$suricata_alerts"
    echo ""

    # Top attacking countries
    echo -e "${YELLOW}[TOP ATTACKING COUNTRIES - 24H]${NC}"
    echo "────────────────────────────────────────────────────────────────"
    get_top_countries
    echo ""

    # Resource usage
    echo -e "${YELLOW}[RESOURCE USAGE]${NC}"
    echo "────────────────────────────────────────────────────────────────"
    es_mem=$(docker stats elasticsearch --no-stream --format "{{.MemUsage}}" 2>/dev/null | awk '{print $1}')
    printf "%-30s %s\n" "Elasticsearch Memory:" "${es_mem:-N/A}"

    disk_usage=$(df -h . | awk 'NR==2 {print $3 " / " $2 " (" $5 ")"}')
    printf "%-30s %s\n" "Disk Usage:" "$disk_usage"
    echo ""

    # Alerts (if enabled)
    if [ "$SHOW_ALERTS" = true ]; then
        echo -e "${YELLOW}[RECENT HIGH-SEVERITY ALERTS]${NC}"
        echo "────────────────────────────────────────────────────────────────"

        curl -s "http://$ES_HOST/honeypot-alerts-*/_search" -H 'Content-Type: application/json' -d '{
          "size": 5,
          "sort": [{"@timestamp": "desc"}],
          "query": {
            "range": {
              "@timestamp": {
                "gte": "now-1h"
              }
            }
          }
        }' 2>/dev/null | jq -r '.hits.hits[]._source | "\(._timestamp // .timestamp): \(.attacker_ip // "N/A") - \(.alert_signature // .command_executed // "Alert")"' 2>/dev/null | head -5

        echo ""
    fi

    # Footer
    echo "────────────────────────────────────────────────────────────────"
    echo -e "Last updated: $(date '+%Y-%m-%d %H:%M:%S')  |  Refresh: ${INTERVAL}s"
    echo "Press Ctrl+C to exit"

    sleep "$INTERVAL"

    # Clear screen for next update
    clear
    echo -e "${BLUE}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║  T-POT HONEYPOT INFRASTRUCTURE - REAL-TIME MONITOR            ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
done
