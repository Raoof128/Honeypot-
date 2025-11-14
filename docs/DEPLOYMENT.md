# Deployment Guide - T-Pot Honeypot Infrastructure

Complete step-by-step deployment guide for production and development environments.

---

## Table of Contents

- [Prerequisites](#prerequisites)
- [Pre-Deployment Checklist](#pre-deployment-checklist)
- [Deployment Methods](#deployment-methods)
- [Post-Deployment Configuration](#post-deployment-configuration)
- [Verification](#verification)
- [Troubleshooting](#troubleshooting)

---

## Prerequisites

### Hardware Requirements

| Component | Minimum | Recommended | Production |
|-----------|---------|-------------|------------|
| **CPU** | 4 cores | 8 cores | 16 cores |
| **RAM** | 16 GB | 32 GB | 64 GB |
| **Disk** | 100 GB | 500 GB SSD | 1 TB NVMe |
| **Network** | 100 Mbps | 1 Gbps | 10 Gbps |

### Software Requirements

```bash
# Ubuntu 20.04+ / Debian 11+
sudo apt update && sudo apt upgrade -y

# Docker Engine
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER

# Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" \
  -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Python 3.8+
sudo apt install -y python3 python3-pip
pip3 install elasticsearch geoip2

# jq (for report generation)
sudo apt install -y jq curl netstat lsof
```

---

## Pre-Deployment Checklist

### 1. Network Configuration

**Firewall Rules:**

```bash
# Allow honeypot ports (inbound from internet)
sudo ufw allow 2222/tcp comment 'Cowrie SSH'
sudo ufw allow 2223/tcp comment 'Cowrie Telnet'
sudo ufw allow 80/tcp comment 'Dionaea HTTP'
sudo ufw allow 443/tcp comment 'Dionaea HTTPS'
sudo ufw allow 21/tcp comment 'Dionaea FTP'
sudo ufw allow 3306/tcp comment 'Dionaea MySQL'
sudo ufw allow 445/tcp comment 'Dionaea SMB'

# Block management ports (inbound from internet)
# ONLY allow from trusted IPs
sudo ufw deny 9200/tcp comment 'Elasticsearch - DENY PUBLIC'
sudo ufw deny 5601/tcp comment 'Kibana - DENY PUBLIC'
sudo ufw deny 64295/tcp comment 'T-Pot Admin - DENY PUBLIC'

# Allow from trusted management IP
sudo ufw allow from YOUR_MANAGEMENT_IP to any port 9200
sudo ufw allow from YOUR_MANAGEMENT_IP to any port 5601

sudo ufw enable
```

### 2. Disk Space

```bash
# Check available disk space
df -h

# Ensure at least 100GB free in project directory
```

### 3. Download GeoIP Databases

```bash
# Create GeoIP directory
mkdir -p infrastructure/elk-stack/geoip

# Download GeoLite2 databases
# Register at: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
# Download: GeoLite2-City.mmdb and GeoLite2-ASN.mmdb

# Place in: infrastructure/elk-stack/geoip/
```

---

## Deployment Methods

### Method 1: Automated Deployment (Recommended)

```bash
# Clone repository
git clone https://github.com/YOUR_USERNAME/honeypot-threat-intelligence.git
cd honeypot-threat-intelligence

# Run deployment script
sudo ./scripts/deploy.sh
```

**Script performs:**
1. System requirement checks
2. Port availability verification
3. Directory creation
4. Docker image pulling
5. Service startup
6. Health checks

### Method 2: Manual Deployment

```bash
# 1. Navigate to infrastructure directory
cd infrastructure

# 2. Create data directories
mkdir -p ../data/{elasticsearch,cowrie/logs,dionaea/logs,suricata/logs,kibana}

# 3. Set permissions
chmod -R 777 ../data/elasticsearch

# 4. Pull Docker images
docker-compose pull

# 5. Start services
docker-compose up -d

# 6. Check status
docker-compose ps

# 7. View logs
docker-compose logs -f
```

### Method 3: Development Mode (Reduced Resources)

```bash
# Use development docker-compose
docker-compose -f infrastructure/docker-compose.dev.yml up -d
```

---

## Post-Deployment Configuration

### 1. Kibana Setup

```bash
# Access Kibana
http://localhost:5601

# Create index patterns:
# - honeypot-cowrie-*
# - honeypot-dionaea-*
# - honeypot-suricata-*
# - honeypot-iocs-*
# - honeypot-alerts-*

# Import dashboards
# Management > Saved Objects > Import
# Select: dashboards/kibana_export.ndjson
```

### 2. Elasticsearch Index Templates

```bash
# Apply index template for proper field mappings
curl -X PUT "http://localhost:9200/_index_template/honeypot-template" \
  -H 'Content-Type: application/json' -d'
{
  "index_patterns": ["honeypot-*"],
  "template": {
    "mappings": {
      "properties": {
        "@timestamp": {"type": "date"},
        "attacker_ip": {"type": "ip"},
        "threat_score": {"type": "integer"},
        "geoip.country_name": {"type": "keyword"},
        "geoip.city_name": {"type": "keyword"}
      }
    }
  }
}'
```

### 3. Verify Data Ingestion

```bash
# Check event count
curl -s http://localhost:9200/honeypot-*/_count | jq

# Query recent events
curl -s http://localhost:9200/honeypot-*/_search?size=5 | jq '.hits.hits[]._source'
```

---

## Verification

### Service Health Checks

```bash
# Elasticsearch
curl http://localhost:9200/_cluster/health?pretty

# Expected: "status": "green" or "yellow"

# Logstash
curl http://localhost:9600/_node/stats?pretty

# Kibana
curl http://localhost:5601/api/status

# Docker containers
docker-compose -f infrastructure/docker-compose.yml ps

# All containers should show "Up" status
```

### Generate Test Events

```bash
# SSH to Cowrie honeypot (should be logged)
ssh root@localhost -p 2222
# Password: root (or any password)

# HTTP request to Dionaea
curl http://localhost/admin

# Check if events appear in Elasticsearch
curl -s "http://localhost:9200/honeypot-*/_search?q=attacker_ip:127.0.0.1" | jq
```

---

## Troubleshooting

### Elasticsearch Not Starting

```bash
# Check logs
docker-compose -f infrastructure/docker-compose.yml logs elasticsearch

# Common issues:
# 1. Insufficient memory
docker stats elasticsearch

# 2. Permission issues
sudo chmod -R 777 data/elasticsearch

# 3. Port conflict
sudo lsof -i :9200
```

### Logstash Parse Errors

```bash
# View Logstash logs
docker-compose -f infrastructure/docker-compose.yml logs logstash

# Test configuration
docker exec -it logstash logstash -t -f /usr/share/logstash/pipeline/logstash.conf
```

### No Events Appearing

```bash
# Check if honeypots are running
docker ps | grep -E 'cowrie|dionaea'

# Check Logstash pipeline
curl http://localhost:9600/_node/stats/pipelines?pretty

# Verify log files exist
docker exec cowrie ls -la /var/log/cowrie/
docker exec dionaea ls -la /var/log/dionaea/
```

### High Resource Usage

```bash
# Monitor resource usage
docker stats

# Reduce Elasticsearch heap size (in docker-compose.yml)
ES_JAVA_OPTS=-Xms1g -Xmx1g  # Default: 2g

# Restart services
docker-compose restart elasticsearch
```

---

## Security Hardening

### 1. Isolate Honeypot Network

```bash
# Ensure honeypots cannot access internal network
# Firewall egress rules
sudo iptables -A FORWARD -i honeypot_net -o internal_net -j DROP
```

### 2. Rate Limiting

```bash
# Prevent resource exhaustion from DDoS
# Add to iptables
sudo iptables -A INPUT -p tcp --dport 2222 -m limit --limit 10/min -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 2222 -j DROP
```

### 3. Log Rotation

```bash
# Configure Docker log rotation
# /etc/docker/daemon.json
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "100m",
    "max-file": "10"
  }
}
```

---

## Next Steps

After successful deployment:

1. ✅ Let honeypots run for 24-48 hours to collect data
2. ✅ Run analysis scripts: `./scripts/generate_report.sh --days 1`
3. ✅ Review Kibana dashboards for visualizations
4. ✅ Set up automated weekly reporting (cron job)
5. ✅ Integrate threat feeds with SIEM/firewall

**Cron Job for Weekly Reports:**

```bash
# Edit crontab
crontab -e

# Add weekly report generation (every Monday at 2 AM)
0 2 * * 1 /path/to/honeypot-threat-intelligence/scripts/generate_report.sh --days 7
```

---

## Support

For issues or questions:
- Check [TROUBLESHOOTING.md](TROUBLESHOOTING.md)
- Review Docker logs: `docker-compose logs -f`
- Open GitHub issue

---

**Deployment Complete!** Your honeypot infrastructure is now operational and collecting threat intelligence.
