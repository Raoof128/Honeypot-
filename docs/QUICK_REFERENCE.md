# Quick Reference Guide

Fast reference for common honeypot operations, commands, and troubleshooting.

---

## Table of Contents

- [Essential Commands](#essential-commands)
- [Docker Operations](#docker-operations)
- [Elasticsearch Queries](#elasticsearch-queries)
- [Monitoring & Analysis](#monitoring--analysis)
- [Common Tasks](#common-tasks)
- [Troubleshooting](#troubleshooting)

---

## Essential Commands

### Initial Setup

```bash
# Clone and navigate to project
git clone <repository-url>
cd honeypot-threat-intelligence

# Run initial setup
sudo ./scripts/setup.sh

# Deploy infrastructure
sudo ./scripts/deploy.sh

# Verify installation
./scripts/verify_installation.sh
```

### Daily Operations

```bash
# Start monitoring dashboard
./scripts/monitor.sh --interval 10

# Generate weekly report
./scripts/generate_report.sh --days 7

# Check system health
./scripts/diagnostics.sh

# View logs
./scripts/monitor.sh --service elasticsearch
```

### Maintenance

```bash
# Clean old data (30+ days)
./scripts/cleanup.sh --days 30

# Update GeoIP databases
curl -L "https://mmdb-cdn.example.com/GeoLite2-City.mmdb" \
  -o data/geoip/GeoLite2-City.mmdb

# Restart all services
cd infrastructure && docker-compose restart

# Stop all services
cd infrastructure && docker-compose down
```

---

## Docker Operations

### Service Management

```bash
# Start all services
docker-compose up -d

# Stop all services
docker-compose down

# Restart specific service
docker-compose restart elasticsearch

# View service status
docker-compose ps

# Follow logs for service
docker-compose logs -f cowrie
```

### Container Operations

```bash
# Execute command in container
docker exec -it elasticsearch bash

# View container stats
docker stats --no-stream

# Inspect container
docker inspect elasticsearch

# Copy files from container
docker cp elasticsearch:/usr/share/elasticsearch/logs ./logs

# Remove stopped containers
docker-compose rm -f
```

### Network & Volumes

```bash
# List Docker networks
docker network ls

# Inspect honeypot network
docker network inspect honeypot_network

# List volumes
docker volume ls

# Remove unused volumes
docker volume prune -f
```

---

## Elasticsearch Queries

### Basic Queries

```bash
# Cluster health
curl -s localhost:9200/_cluster/health?pretty

# List all indices
curl -s localhost:9200/_cat/indices?v

# Count documents in index
curl -s localhost:9200/honeypot-cowrie-*/_count?pretty

# Get index mapping
curl -s localhost:9200/honeypot-cowrie-*/_mapping?pretty
```

### Search Queries

```bash
# Search for SSH attacks in last 24 hours
curl -s localhost:9200/honeypot-*/_search?pretty -H 'Content-Type: application/json' -d'
{
  "query": {
    "bool": {
      "must": [
        {"match": {"protocol": "ssh"}},
        {"range": {"@timestamp": {"gte": "now-24h"}}}
      ]
    }
  },
  "size": 10
}'

# Get top 10 attacker IPs
curl -s localhost:9200/honeypot-*/_search?pretty -H 'Content-Type: application/json' -d'
{
  "size": 0,
  "aggs": {
    "top_attackers": {
      "terms": {
        "field": "attacker_ip",
        "size": 10
      }
    }
  }
}'

# Find failed login attempts
curl -s localhost:9200/honeypot-cowrie-*/_search?pretty -H 'Content-Type: application/json' -d'
{
  "query": {
    "match": {"eventid": "cowrie.login.failed"}
  },
  "size": 20
}'
```

### Index Management

```bash
# Delete old indices
curl -X DELETE localhost:9200/honeypot-cowrie-2024.01.01

# Reindex data
curl -X POST localhost:9200/_reindex?pretty -H 'Content-Type: application/json' -d'
{
  "source": {"index": "honeypot-cowrie-old"},
  "dest": {"index": "honeypot-cowrie-new"}
}'

# Force merge index
curl -X POST localhost:9200/honeypot-cowrie-2024.01.01/_forcemerge?max_num_segments=1

# Refresh index
curl -X POST localhost:9200/honeypot-*/_refresh
```

---

## Monitoring & Analysis

### Python Analysis Scripts

```bash
# Extract IOCs (last 7 days)
python3 analysis/ioc_extraction.py --days 7 --output reports/generated/iocs.json

# Generate geographic analysis
python3 analysis/geolocation_mapper.py --days 7 --output reports/generated/geo_analysis.json

# Map MITRE ATT&CK techniques
python3 analysis/mitre_attck_mapper.py --days 7 --output reports/generated/mitre_analysis.json

# Generate threat feeds (all formats)
python3 analysis/threat_feed_generator.py \
  --days 7 \
  --formats stix,json,csv \
  --output reports/generated/
```

### Real-Time Monitoring

```bash
# Monitor Elasticsearch logs
docker logs -f elasticsearch | grep -i error

# Monitor Cowrie sessions
tail -f data/cowrie/logs/cowrie.json | jq '.'

# Monitor system resources
watch -n 2 'docker stats --no-stream'

# Monitor attack rate
watch -n 5 'curl -s localhost:9200/honeypot-*/_count | jq .count'
```

### Kibana Access

```bash
# Open Kibana in browser
http://localhost:5601

# Discover page (view raw logs)
http://localhost:5601/app/discover

# Dashboards
http://localhost:5601/app/dashboards

# Dev Tools (run queries)
http://localhost:5601/app/dev_tools
```

---

## Common Tasks

### Extract Top 10 Attacker IPs

```bash
curl -s localhost:9200/honeypot-*/_search -H 'Content-Type: application/json' -d'
{
  "size": 0,
  "aggs": {
    "top_ips": {
      "terms": {"field": "attacker_ip", "size": 10}
    }
  }
}' | jq '.aggregations.top_ips.buckets[] | "\(.key): \(.doc_count)"'
```

### Find Malware Downloads

```bash
# Search for wget/curl commands
curl -s localhost:9200/honeypot-cowrie-*/_search -H 'Content-Type: application/json' -d'
{
  "query": {
    "regexp": {"input": ".*(wget|curl).*"}
  },
  "size": 50
}' | jq '.hits.hits[]._source | select(.input != null) | .input'
```

### Check Attack by Country

```bash
curl -s localhost:9200/honeypot-*/_search -H 'Content-Type: application/json' -d'
{
  "size": 0,
  "aggs": {
    "by_country": {
      "terms": {"field": "geoip.country_name", "size": 20}
    }
  }
}' | jq '.aggregations.by_country.buckets[] | "\(.key): \(.doc_count)"'
```

### Export Attack Data to CSV

```bash
# Using Elasticsearch API
curl -s localhost:9200/honeypot-*/_search?scroll=1m -H 'Content-Type: application/json' -d'
{
  "query": {"match_all": {}},
  "size": 10000
}' | jq -r '.hits.hits[]._source | [
  .["@timestamp"],
  .attacker_ip,
  .username,
  .protocol,
  .geoip.country_name
] | @csv' > attacks.csv
```

### Block High-Threat IPs with iptables

```bash
# Extract high-threat IPs (score > 70)
python3 analysis/ioc_extraction.py --days 7 --output /tmp/iocs.json

# Block IPs
jq -r '.ips[] | select(.threat_score > 70) | .value' /tmp/iocs.json | while read ip; do
  sudo iptables -A INPUT -s $ip -j DROP
  echo "Blocked: $ip"
done

# Save iptables rules
sudo iptables-save > /etc/iptables/rules.v4
```

### Backup Elasticsearch Data

```bash
# Create snapshot repository
curl -X PUT localhost:9200/_snapshot/backup_repo -H 'Content-Type: application/json' -d'
{
  "type": "fs",
  "settings": {
    "location": "/usr/share/elasticsearch/backups"
  }
}'

# Create snapshot
curl -X PUT localhost:9200/_snapshot/backup_repo/snapshot_$(date +%Y%m%d)?wait_for_completion=true

# Restore snapshot
curl -X POST localhost:9200/_snapshot/backup_repo/snapshot_20240122/_restore
```

---

## Troubleshooting

### Elasticsearch Issues

```bash
# Cluster status is yellow/red
curl -s localhost:9200/_cluster/health?pretty
# → Check: Adjust replica settings, check disk space

# Cannot connect to Elasticsearch
docker logs elasticsearch | tail -50
# → Check: JVM heap size, port conflicts, container running

# Slow queries
curl -s localhost:9200/_nodes/stats/indices/search?pretty
# → Check: Index size, query complexity, add more shards

# Out of disk space
du -sh data/elasticsearch/
./scripts/cleanup.sh --days 30
# → Run cleanup script or expand storage
```

### Logstash Issues

```bash
# Pipeline not processing logs
curl -s localhost:9600/_node/stats/pipelines?pretty
# → Check: Pipeline configuration, file permissions, Elasticsearch connectivity

# High CPU usage
docker stats logstash
# → Check: Reduce pipeline workers, increase batch delay

# Grok parse failures
docker logs logstash | grep "_grokparsefailure"
# → Check: Log format matches grok patterns
```

### Honeypot Issues

```bash
# Cowrie not logging
tail -f data/cowrie/logs/cowrie.json
docker logs cowrie | grep -i error
# → Check: File permissions, disk space, container health

# Port not accessible
sudo netstat -tlnp | grep 2222
docker ps | grep cowrie
# → Check: Container running, port mapping, firewall rules

# Session timeout errors
docker logs cowrie | grep -i timeout
# → Check: Increase session timeout in cowrie.cfg
```

### Docker Issues

```bash
# Container keeps restarting
docker ps -a | grep Restarting
docker logs <container-name> --tail 100
# → Check: Resource limits, configuration errors, dependencies

# High memory usage
docker stats --no-stream
# → Adjust: Container memory limits in docker-compose.yml

# Network issues
docker network inspect honeypot_network
# → Check: Network exists, containers connected, IP conflicts
```

---

## Performance Optimization

### Quick Wins

```bash
# 1. Reduce Elasticsearch refresh interval (faster indexing)
curl -X PUT localhost:9200/honeypot-*/_settings -H 'Content-Type: application/json' -d'
{
  "index": {"refresh_interval": "30s"}
}'

# 2. Increase Logstash workers
# Edit infrastructure/logstash/logstash.yml:
# pipeline.workers: 8

# 3. Enable Elasticsearch compression
curl -X PUT localhost:9200/honeypot-*/_settings -H 'Content-Type: application/json' -d'
{
  "index": {"codec": "best_compression"}
}'

# 4. Clear Docker logs
for container in $(docker ps -q); do
  echo "" > $(docker inspect --format='{{.LogPath}}' $container)
done
```

---

## Security Hardening

### Essential Security Commands

```bash
# 1. Restrict Elasticsearch access
sudo ufw allow from 192.168.1.0/24 to any port 9200
sudo ufw deny 9200

# 2. Change default passwords
# Edit .env file:
ES_PASSWORD=<strong-password>
KIBANA_ENCRYPTION_KEY=$(openssl rand -hex 32)

# 3. Enable Elasticsearch authentication
# Edit docker-compose.yml:
# xpack.security.enabled: true

# 4. Review firewall rules
sudo ufw status verbose

# 5. Check for exposed ports
sudo netstat -tuln | grep LISTEN
```

---

## Useful Aliases

Add to `~/.bashrc` or `~/.zshrc`:

```bash
alias hp-deploy='cd ~/honeypot-threat-intelligence && sudo ./scripts/deploy.sh'
alias hp-monitor='cd ~/honeypot-threat-intelligence && ./scripts/monitor.sh'
alias hp-report='cd ~/honeypot-threat-intelligence && ./scripts/generate_report.sh --days 7'
alias hp-clean='cd ~/honeypot-threat-intelligence && ./scripts/cleanup.sh'
alias hp-health='cd ~/honeypot-threat-intelligence && ./scripts/diagnostics.sh'
alias hp-verify='cd ~/honeypot-threat-intelligence && ./scripts/verify_installation.sh'

alias es-health='curl -s localhost:9200/_cluster/health?pretty'
alias es-indices='curl -s localhost:9200/_cat/indices?v'
alias es-count='curl -s localhost:9200/honeypot-*/_count | jq .'

alias hp-logs-cowrie='tail -f ~/honeypot-threat-intelligence/data/cowrie/logs/cowrie.json | jq .'
alias hp-logs-es='docker logs -f elasticsearch'
alias hp-logs-logstash='docker logs -f logstash'
```

---

## Keyboard Shortcuts (Kibana)

| Shortcut | Action |
|----------|--------|
| `Ctrl + /` | Open command palette |
| `Ctrl + F` | Find in page |
| `Ctrl + K` | Quick search |
| `g + d` | Go to Discover |
| `g + h` | Go to Home |
| `g + m` | Go to Management |

---

## Important File Locations

| File/Directory | Purpose |
|----------------|---------|
| `infrastructure/docker-compose.yml` | Container orchestration |
| `infrastructure/elk-stack/logstash.conf` | Log parsing rules |
| `data/cowrie/logs/cowrie.json` | Cowrie attack logs |
| `data/elasticsearch/` | Elasticsearch data |
| `data/geoip/*.mmdb` | GeoIP databases |
| `reports/generated/` | Generated reports |
| `analysis/*.py` | Python analysis scripts |
| `scripts/*.sh` | Automation scripts |
| `.env` | Environment configuration |

---

## Emergency Procedures

### System Under Heavy Load

```bash
# 1. Stop non-critical services
docker-compose stop kibana

# 2. Reduce Logstash workers
# Edit logstash.yml: pipeline.workers: 2

# 3. Increase refresh interval
curl -X PUT localhost:9200/honeypot-*/_settings -d'{"index":{"refresh_interval":"60s"}}'

# 4. Force garbage collection
curl -X POST localhost:9200/_nodes/gc
```

### Elasticsearch Out of Memory

```bash
# 1. Clear field data cache
curl -X POST localhost:9200/_cache/clear?fielddata=true

# 2. Clear query cache
curl -X POST localhost:9200/_cache/clear?query=true

# 3. Restart Elasticsearch
docker-compose restart elasticsearch
```

### Disk Full

```bash
# 1. Emergency cleanup
./scripts/cleanup.sh --days 7

# 2. Delete old indices
curl -X DELETE localhost:9200/honeypot-*-2024.01.*

# 3. Clear Docker logs
docker system prune -af --volumes
```

---

## Makefile Commands

If using the included Makefile:

```bash
make deploy          # Deploy infrastructure
make start           # Start all services
make stop            # Stop all services
make monitor         # Start monitoring
make report          # Generate weekly report
make clean           # Clean old data
make health          # Run health checks
make verify          # Verify installation
make logs SERVICE=elasticsearch  # View logs
```

---

**Quick Reference Version:** 1.0.0
**Last Updated:** 2024-01-22

For detailed information, see:
- [DEPLOYMENT.md](DEPLOYMENT.md) - Full deployment guide
- [USAGE.md](USAGE.md) - Operational procedures
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md) - Detailed troubleshooting
- [ARCHITECTURE.md](ARCHITECTURE.md) - Technical architecture
