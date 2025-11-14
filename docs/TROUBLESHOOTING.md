# Troubleshooting Guide

Common issues and solutions for T-Pot honeypot infrastructure.

---

## Table of Contents

- [Deployment Issues](#deployment-issues)
- [Elasticsearch Problems](#elasticsearch-problems)
- [Logstash Issues](#logstash-issues)
- [Honeypot Services](#honeypot-services)
- [Network Connectivity](#network-connectivity)
- [Performance Issues](#performance-issues)
- [Analysis Script Errors](#analysis-script-errors)

---

## Deployment Issues

### Port Already in Use

**Symptom:**
```
Error: bind: address already in use
```

**Solution:**
```bash
# Identify process using the port
sudo lsof -i :9200

# Kill process or stop service
sudo kill -9 <PID>

# Or modify docker-compose.yml to use different port
ports:
  - "9201:9200"  # Changed from 9200
```

### Insufficient Disk Space

**Symptom:**
```
Error: no space left on device
```

**Solution:**
```bash
# Check disk usage
df -h

# Clean Docker images and volumes
docker system prune -a --volumes

# Increase disk allocation or use external volume
```

### Permission Denied on Elasticsearch

**Symptom:**
```
elasticsearch: Permission denied on /usr/share/elasticsearch/data
```

**Solution:**
```bash
# Set proper permissions
sudo chmod -R 777 data/elasticsearch

# Or change ownership
sudo chown -R 1000:1000 data/elasticsearch
```

---

## Elasticsearch Problems

### Cluster Health Yellow

**Symptom:**
```json
{
  "status": "yellow",
  "unassigned_shards": 5
}
```

**Explanation:** Yellow status in single-node deployment is normal (replicas can't be assigned)

**Solution (Optional):**
```bash
# Disable replicas for indices
curl -X PUT "http://localhost:9200/honeypot-*/_settings" -H 'Content-Type: application/json' -d'
{
  "index": {
    "number_of_replicas": 0
  }
}'
```

### Elasticsearch Won't Start

**Symptom:**
```
max virtual memory areas vm.max_map_count [65530] is too low
```

**Solution:**
```bash
# Increase vm.max_map_count
sudo sysctl -w vm.max_map_count=262144

# Make permanent
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
```

### Elasticsearch Out of Memory

**Symptom:**
```
OutOfMemoryError: Java heap space
```

**Solution:**
```bash
# Reduce heap size in docker-compose.yml
environment:
  - "ES_JAVA_OPTS=-Xms1g -Xmx1g"  # Reduced from 2g

# Restart service
docker-compose restart elasticsearch
```

---

## Logstash Issues

### Logstash Not Parsing Logs

**Symptom:**
No events appearing in Elasticsearch

**Diagnosis:**
```bash
# Check Logstash pipeline stats
curl http://localhost:9600/_node/stats/pipelines?pretty

# Look for:
# - events.in > 0 (receiving events)
# - events.out > 0 (sending to Elasticsearch)
```

**Solution:**
```bash
# Check log file paths
docker exec logstash ls -la /var/log/cowrie/
docker exec logstash ls -la /var/log/dionaea/

# Verify Logstash config syntax
docker exec logstash logstash -t -f /usr/share/logstash/pipeline/logstash.conf

# View Logstash logs
docker-compose logs logstash
```

### GeoIP Enrichment Not Working

**Symptom:**
No `geoip.country_name` field in Elasticsearch

**Solution:**
```bash
# Check if GeoIP databases exist
docker exec logstash ls -la /usr/share/logstash/geoip/

# Download GeoLite2 databases
# Place in: infrastructure/elk-stack/geoip/
# - GeoLite2-City.mmdb
# - GeoLite2-ASN.mmdb

# Restart Logstash
docker-compose restart logstash
```

### Parse Failures

**Symptom:**
```
tags: ["_grokparsefailure"]
```

**Solution:**
```bash
# Check log format matches Logstash configuration
docker exec cowrie tail -f /var/log/cowrie/cowrie.json

# Validate JSON
docker exec cowrie cat /var/log/cowrie/cowrie.json | jq .

# Update Logstash filter if log format changed
```

---

## Honeypot Services

### Cowrie Not Capturing Events

**Symptom:**
SSH connections don't appear in logs

**Diagnosis:**
```bash
# Check if Cowrie is running
docker ps | grep cowrie

# Test SSH connection
ssh root@localhost -p 2222

# Check Cowrie logs
docker-compose logs cowrie

# Verify log file exists
docker exec cowrie ls -la /var/log/cowrie/
```

**Solution:**
```bash
# Restart Cowrie
docker-compose restart cowrie

# Check configuration
docker exec cowrie cat /cowrie/cowrie-git/etc/cowrie.cfg
```

### Dionaea Not Responding

**Symptom:**
HTTP requests to port 80 timeout

**Diagnosis:**
```bash
# Check if Dionaea is running
docker ps | grep dionaea

# Test HTTP connection
curl -v http://localhost:80

# Check Dionaea logs
docker-compose logs dionaea
```

**Solution:**
```bash
# Verify port mapping
docker port dionaea

# Check firewall rules
sudo ufw status

# Restart Dionaea
docker-compose restart dionaea
```

---

## Network Connectivity

### Can't Access Kibana

**Symptom:**
`http://localhost:5601` times out

**Solution:**
```bash
# Check if Kibana is running
docker ps | grep kibana

# Check Kibana status
docker-compose logs kibana

# Verify Elasticsearch connection
curl http://localhost:9200

# Restart Kibana
docker-compose restart kibana

# Check firewall
sudo ufw allow 5601/tcp
```

### Honeypot Ports Not Accessible

**Symptom:**
External connections to port 2222 fail

**Solution:**
```bash
# Check Docker port mapping
docker port cowrie

# Verify firewall rules
sudo ufw status | grep 2222

# Allow port
sudo ufw allow 2222/tcp

# Test locally
telnet localhost 2222
```

---

## Performance Issues

### High CPU Usage

**Symptom:**
```
docker stats shows Elasticsearch at 100% CPU
```

**Solution:**
```bash
# Limit CPU usage in docker-compose.yml
cpus: 2.0  # Limit to 2 cores

# Reduce indexing frequency
# Logstash: batch_size, pipeline.workers

# Optimize Elasticsearch indices
curl -X POST "http://localhost:9200/honeypot-*/_forcemerge?max_num_segments=1"
```

### High Memory Usage

**Symptom:**
System running out of RAM

**Solution:**
```bash
# Reduce Elasticsearch heap
ES_JAVA_OPTS=-Xms1g -Xmx1g

# Reduce Logstash heap
LS_JAVA_OPTS=-Xms512m -Xmx512m

# Limit Docker container memory
mem_limit: 2g

# Clear old indices
curl -X DELETE "http://localhost:9200/honeypot-*-2024.01.01"
```

### Disk Full

**Symptom:**
```
No space left on device
```

**Solution:**
```bash
# Check disk usage
du -sh data/*

# Delete old Elasticsearch indices
curl -X DELETE "http://localhost:9200/honeypot-cowrie-2024.01.*"

# Clean Docker volumes
docker volume prune

# Implement log rotation
# Add to docker-compose.yml:
logging:
  driver: "json-file"
  options:
    max-size: "100m"
    max-file: "3"
```

---

## Analysis Script Errors

### IOC Extraction: Connection Refused

**Symptom:**
```
ConnectionRefusedError: [Errno 111] Connection refused
```

**Solution:**
```bash
# Verify Elasticsearch is running
curl http://localhost:9200

# Check if port is correct
python3 analysis/ioc_extraction.py --es-host localhost --es-port 9200

# Check firewall
sudo ufw allow from 127.0.0.1 to any port 9200
```

### GeoIP: Database Not Found

**Symptom:**
```
FileNotFoundError: GeoLite2-City.mmdb not found
```

**Solution:**
```bash
# Download GeoLite2 databases
# From: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data

# Place in correct location
mkdir -p /usr/share/GeoIP/
mv GeoLite2-City.mmdb /usr/share/GeoIP/

# Or specify custom path
python3 analysis/geolocation_mapper.py --geoip-db /path/to/GeoLite2-City.mmdb
```

### Report Generation: jq Not Found

**Symptom:**
```
command not found: jq
```

**Solution:**
```bash
# Install jq
sudo apt install -y jq

# Verify installation
jq --version
```

---

## Data Issues

### No Events in Elasticsearch

**Symptom:**
```bash
curl http://localhost:9200/honeypot-*/_count
# Returns: {"count": 0}
```

**Diagnosis Checklist:**

1. **Honeypots running?**
   ```bash
   docker ps | grep -E 'cowrie|dionaea'
   ```

2. **Logs being created?**
   ```bash
   docker exec cowrie ls -la /var/log/cowrie/cowrie.json
   ```

3. **Logstash parsing?**
   ```bash
   curl http://localhost:9600/_node/stats/pipelines | jq '.pipelines.main.events'
   ```

4. **Elasticsearch healthy?**
   ```bash
   curl http://localhost:9200/_cluster/health
   ```

### Duplicate Events

**Symptom:**
Same event appears multiple times

**Solution:**
```bash
# Check Logstash sincedb files
# Logstash tracks file positions to avoid duplicates

# Reset sincedb (will re-process all logs)
docker exec logstash rm -f /usr/share/logstash/data/plugins/inputs/file/.sincedb*

# Restart Logstash
docker-compose restart logstash
```

---

## Docker Issues

### Container Keeps Restarting

**Symptom:**
```
docker ps shows container restarting
```

**Solution:**
```bash
# Check container logs
docker-compose logs <container_name>

# Check exit code
docker inspect <container_name> --format='{{.State.ExitCode}}'

# Common exit codes:
# 137: Out of memory (increase memory limit)
# 139: Segmentation fault (check logs)
# 1: General error (check logs)
```

### Docker Compose Not Found

**Symptom:**
```
docker-compose: command not found
```

**Solution:**
```bash
# Try docker compose (newer syntax)
docker compose --version

# Or install docker-compose
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" \
  -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose
```

---

## Getting Help

If issues persist:

1. **Check Logs:**
   ```bash
   docker-compose logs -f
   ```

2. **Verify System Requirements:**
   - RAM: 16GB+ available
   - Disk: 100GB+ free
   - CPU: 4+ cores

3. **Review Documentation:**
   - [DEPLOYMENT.md](DEPLOYMENT.md)
   - [README.md](../README.md)

4. **Community Support:**
   - Open GitHub issue with:
     - Error message
     - Docker logs
     - System specs
     - Steps to reproduce

---

## Quick Diagnostics Script

```bash
#!/bin/bash
# honeypot_diagnostics.sh

echo "=== HONEYPOT DIAGNOSTICS ==="
echo ""

echo "1. Docker Status:"
docker --version
docker-compose --version
echo ""

echo "2. Container Status:"
docker-compose ps
echo ""

echo "3. Elasticsearch Health:"
curl -s http://localhost:9200/_cluster/health | jq
echo ""

echo "4. Event Count:"
curl -s http://localhost:9200/honeypot-*/_count | jq
echo ""

echo "5. Disk Usage:"
df -h .
echo ""

echo "6. Memory Usage:"
free -h
echo ""

echo "7. Logstash Pipeline:"
curl -s http://localhost:9600/_node/stats/pipelines | jq '.pipelines.main.events'
echo ""

echo "=== END DIAGNOSTICS ==="
```

Save as `scripts/diagnostics.sh` and run:
```bash
chmod +x scripts/diagnostics.sh
./scripts/diagnostics.sh
```

---

**Last Updated:** 2024-01-22
