# Usage Guide

How to operate and maintain the T-Pot Honeypot Threat Intelligence Infrastructure.

---

## Table of Contents

- [Daily Operations](#daily-operations)
- [Monitoring](#monitoring)
- [Analysis & Reporting](#analysis--reporting)
- [Maintenance](#maintenance)
- [Common Tasks](#common-tasks)

---

## Daily Operations

### Starting the System

```bash
# Method 1: Using deployment script
sudo ./scripts/deploy.sh

# Method 2: Using Make
make deploy

# Method 3: Manual docker-compose
cd infrastructure
docker-compose up -d
```

### Checking System Status

```bash
# Quick status check
make status

# Detailed health check
make health-check

# View all logs
make logs

# View specific service logs
make logs-cowrie
make logs-dionaea
make logs-elasticsearch
```

### Stopping the System

```bash
# Stop all services
make stop

# Stop and remove volumes (DESTRUCTIVE)
docker-compose -f infrastructure/docker-compose.yml down -v
```

---

## Monitoring

### Real-Time Monitoring

```bash
# Start monitoring dashboard (recommended)
./scripts/monitor.sh --interval 10

# With high-severity alerts
./scripts/monitor.sh --interval 10 --alerts
```

**Monitoring Dashboard Output:**
```
╔════════════════════════════════════════════════════════════════╗
║  T-POT HONEYPOT INFRASTRUCTURE - REAL-TIME MONITOR            ║
╚════════════════════════════════════════════════════════════════╝

[SYSTEM HEALTH]
────────────────────────────────────────────────────────────────
Elasticsearch:           RUNNING
Logstash:                RUNNING
Kibana:                  RUNNING
Cowrie:                  RUNNING
Dionaea:                 RUNNING
Suricata:                RUNNING

[ATTACK STATISTICS]
────────────────────────────────────────────────────────────────
Events (Last Hour):                 127
Events (Last 24 Hours):            3,482
Unique Attacker IPs (24h):            43

Cowrie SSH/Telnet (24h):          2,341
Dionaea Multi-Protocol (24h):       987
Suricata IDS Alerts (24h):          154

[TOP ATTACKING COUNTRIES - 24H]
────────────────────────────────────────────────────────────────
China: 1,234
United States: 567
Russia: 432
Germany: 234
Brazil: 178
```

### Kibana Dashboards

**Access:** http://localhost:5601

**Available Dashboards:**
1. **Main Dashboard:** Overview of all honeypot activity
2. **Attack Timeline:** Time-series event visualization
3. **Geographic Map:** Attack origin heat map
4. **Protocol Distribution:** Pie chart of targeted services
5. **Top Attackers:** Table of most frequent IPs

**Creating Index Patterns:**
```
1. Navigate to: Stack Management > Index Patterns
2. Create pattern: honeypot-*
3. Time field: @timestamp
4. Save
```

**Importing Dashboards:**
```bash
# Via Kibana UI
1. Navigate to: Stack Management > Saved Objects
2. Click "Import"
3. Select file: dashboards/kibana_export.ndjson
4. Click "Import"
```

---

## Analysis & Reporting

### Manual Analysis

**Extract IOCs (Last 7 Days):**
```bash
python3 analysis/ioc_extraction.py \
  --es-host localhost \
  --es-port 9200 \
  --days 7 \
  --confidence 0.1 \
  --output-json reports/generated/iocs.json \
  --output-csv reports/generated/iocs.csv \
  --output-md reports/generated/ioc_report.md
```

**Geographic Analysis:**
```bash
python3 analysis/geolocation_mapper.py \
  --es-host localhost \
  --days 7 \
  --output-json reports/generated/geo_analysis.json \
  --output-heatmap reports/generated/attack_heatmap.html \
  --output-report reports/generated/geo_report.md
```

**MITRE ATT&CK Mapping:**
```bash
python3 analysis/mitre_attck_mapper.py \
  --es-host localhost \
  --days 7 \
  --output-json reports/generated/mitre_analysis.json \
  --output-navigator reports/generated/attack_navigator.json \
  --output-report reports/generated/mitre_report.md
```

**Threat Feed Generation:**
```bash
python3 analysis/threat_feed_generator.py \
  --ioc-file reports/generated/iocs.json \
  --output-stix reports/generated/threat_feed.stix.json \
  --output-json reports/generated/threat_feed.json \
  --output-csv reports/generated/threat_feed.csv \
  --output-misp reports/generated/threat_feed.misp.json
```

### Automated Reporting

**Generate Weekly Report:**
```bash
# Last 7 days (default)
./scripts/generate_report.sh --days 7

# Last 30 days
./scripts/generate_report.sh --days 30
```

**Output Files:**
- `executive_report_TIMESTAMP.md` - Executive summary
- `ioc_report_TIMESTAMP.md` - Detailed IOC analysis
- `geo_report_TIMESTAMP.md` - Geographic analysis
- `mitre_report_TIMESTAMP.md` - MITRE ATT&CK analysis
- `threat_feed_TIMESTAMP.stix.json` - STIX 2.1 bundle
- `attack_heatmap_TIMESTAMP.html` - Interactive map

**Schedule Automated Reports:**
```bash
# Add to crontab
crontab -e

# Weekly report every Monday at 2 AM
0 2 * * 1 /path/to/scripts/generate_report.sh --days 7

# Daily report at 1 AM
0 1 * * * /path/to/scripts/generate_report.sh --days 1
```

---

## Maintenance

### Log Rotation

**Elasticsearch Indices:**
```bash
# Delete indices older than 30 days
./scripts/cleanup.sh --days 30

# View all indices
curl http://localhost:9200/_cat/indices/honeypot-*?v
```

**Docker Logs:**
```bash
# Configure log rotation in docker-compose.yml
logging:
  driver: "json-file"
  options:
    max-size: "100m"
    max-file: "3"
```

### Backup & Restore

**Backup Elasticsearch Data:**
```bash
# Create snapshot repository
curl -X PUT "localhost:9200/_snapshot/backup" -H 'Content-Type: application/json' -d'{
  "type": "fs",
  "settings": {
    "location": "/usr/share/elasticsearch/backups"
  }
}'

# Create snapshot
curl -X PUT "localhost:9200/_snapshot/backup/snapshot_$(date +%Y%m%d)?wait_for_completion=true"
```

**Restore from Snapshot:**
```bash
# List snapshots
curl "localhost:9200/_snapshot/backup/_all?pretty"

# Restore
curl -X POST "localhost:9200/_snapshot/backup/snapshot_20240122/_restore"
```

**Backup Analysis Reports:**
```bash
# Compress and archive
tar -czf reports_backup_$(date +%Y%m%d).tar.gz reports/generated/

# Upload to external storage
aws s3 cp reports_backup_*.tar.gz s3://your-bucket/honeypot-backups/
```

### Updates

**Update Docker Images:**
```bash
# Pull latest images
make update

# Or manually
cd infrastructure
docker-compose pull
docker-compose up -d
```

**Update Python Dependencies:**
```bash
pip3 install --upgrade -r requirements.txt
```

**Update GeoIP Databases:**
```bash
# Download new databases from MaxMind
# Place in: infrastructure/elk-stack/geoip/

# Restart Logstash to load new databases
docker-compose restart logstash
```

---

## Common Tasks

### Viewing Recent Attacks

**Via Elasticsearch:**
```bash
# Last 10 attacks
curl -s "localhost:9200/honeypot-*/_search?size=10&sort=@timestamp:desc" | jq '.hits.hits[]._source'
```

**Via Kibana:**
```
1. Navigate to: Discover
2. Select index pattern: honeypot-*
3. Time range: Last 15 minutes
4. Add filters as needed
```

### Querying Specific IOCs

**Search for Specific IP:**
```bash
curl -s "localhost:9200/honeypot-*/_search?q=attacker_ip:192.0.2.1" | jq
```

**Search for Malware Hash:**
```bash
curl -s "localhost:9200/honeypot-*/_search" -H 'Content-Type: application/json' -d'{
  "query": {
    "match": {
      "file_hash": "5d41402abc4b2a76b9719d911017c592"
    }
  }
}'
```

**Search for Specific Country:**
```bash
curl -s "localhost:9200/honeypot-*/_search?q=geoip.country_name:China&size=100" | jq
```

### Exporting Data

**Export to JSON:**
```bash
# All events from last 24 hours
curl -s "localhost:9200/honeypot-*/_search?size=10000&q=@timestamp:[now-24h TO now]" > export.json
```

**Export Specific Fields:**
```bash
curl -s "localhost:9200/honeypot-*/_search" -H 'Content-Type: application/json' -d'{
  "_source": ["@timestamp", "attacker_ip", "username", "password"],
  "size": 1000
}' | jq -r '.hits.hits[]._source' > credentials.json
```

### Testing the Honeypot

**Trigger SSH Attack:**
```bash
# This should be logged
ssh root@localhost -p 2222
# Password: anything

# Verify logged
curl -s "localhost:9200/honeypot-cowrie-*/_search?q=username:root" | jq
```

**Trigger HTTP Attack:**
```bash
# Send web request
curl http://localhost/admin
curl http://localhost/phpmyadmin

# Verify logged
curl -s "localhost:9200/honeypot-dionaea-*/_search?size=5" | jq
```

### Performance Tuning

**Increase Elasticsearch Heap:**
```yaml
# In docker-compose.yml
environment:
  - "ES_JAVA_OPTS=-Xms4g -Xmx4g"  # Change from 2g
```

**Increase Logstash Workers:**
```conf
# In logstash.conf
# Add at top:
pipeline.workers: 8
pipeline.batch.size: 1000
```

**Optimize Index Settings:**
```bash
curl -X PUT "localhost:9200/honeypot-*/_settings" -H 'Content-Type: application/json' -d'{
  "index": {
    "refresh_interval": "30s",
    "number_of_replicas": 0
  }
}'
```

---

## Troubleshooting

### No Events Appearing

**1. Check Honeypots:**
```bash
docker logs cowrie | tail -20
docker exec cowrie ls -la /var/log/cowrie/
```

**2. Check Logstash:**
```bash
curl localhost:9600/_node/stats/pipelines | jq '.pipelines.main.events'
# events.in should be > 0
```

**3. Check Elasticsearch:**
```bash
curl localhost:9200/honeypot-*/_count
# count should be > 0
```

**4. Manual Test:**
```bash
ssh root@localhost -p 2222
# Wait 30 seconds
curl "localhost:9200/honeypot-cowrie-*/_count"
```

### High Resource Usage

**Check Container Stats:**
```bash
docker stats

# Look for high CPU/memory
```

**Reduce Resources:**
```bash
# Edit docker-compose.yml
mem_limit: 1g  # Reduce from 2g
cpus: 1.0      # Reduce from 2.0
```

---

## Integration Examples

### SIEM Integration (Splunk)

**Forwarder Configuration:**
```
[tcpout]
defaultGroup = splunk-indexers

[tcpout:splunk-indexers]
server = splunk.example.com:9997

[monitor:///var/log/honeypot/]
sourcetype = json
index = honeypot
```

### Firewall Integration

**Auto-Block High-Threat IPs:**
```bash
#!/bin/bash
# block_threats.sh

python3 analysis/ioc_extraction.py --days 1 --output-json /tmp/iocs.json

jq -r '.ips[] | select(.threat_score > 70) | .value' /tmp/iocs.json | \
while read ip; do
  iptables -A INPUT -s $ip -j DROP
  echo "Blocked: $ip"
done
```

### MISP Integration

**Upload IOCs to MISP:**
```python
from pymisp import PyMISP
import json

# Load IOCs
with open('iocs.json') as f:
    iocs = json.load(f)

# Connect to MISP
misp = PyMISP('https://misp.local', 'API_KEY', ssl=False)

# Create event
event = misp.new_event(info='Honeypot IOCs - Daily', distribution=3)

# Add IPs
for ip, data in iocs['ips'].items():
    misp.add_attribute(event, type='ip-src', value=ip,
                      comment=f"Threat score: {data['threat_score']}")
```

---

## Best Practices

1. **Regular Monitoring:** Check dashboards daily
2. **Weekly Reports:** Generate threat intelligence reports weekly
3. **Data Retention:** Clean old data monthly
4. **Backup:** Backup reports and critical IOCs
5. **Update:** Keep software and threat feeds updated
6. **Isolation:** Ensure honeypots remain isolated
7. **Legal Compliance:** Follow data protection regulations
8. **Documentation:** Document all customizations

---

## Quick Reference

| Task | Command |
|------|---------|
| **Start** | `make deploy` |
| **Stop** | `make stop` |
| **Status** | `make status` |
| **Monitor** | `make monitor` |
| **Report** | `make report` |
| **Logs** | `make logs` |
| **Cleanup** | `make clean` |
| **Test** | `make test` |
| **Diagnose** | `make diagnose` |

---

**Last Updated:** 2024-01-22
**Version:** 1.0.0
