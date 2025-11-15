# Security Hardening Checklist

Comprehensive pre-deployment and ongoing security checklist for honeypot infrastructure.

---

## Table of Contents

- [Pre-Deployment Security](#pre-deployment-security)
- [Network Security](#network-security)
- [Access Control](#access-control)
- [Data Protection](#data-protection)
- [Container Security](#container-security)
- [Monitoring & Logging](#monitoring--logging)
- [Compliance & Legal](#compliance--legal)
- [Ongoing Maintenance](#ongoing-maintenance)

---

## Pre-Deployment Security

### Initial Setup

- [ ] **Review Architecture Documentation**
  - Read [ARCHITECTURE.md](ARCHITECTURE.md)
  - Understand network isolation boundaries
  - Review data flow diagrams

- [ ] **Legal Compliance Check**
  - Read [LEGAL.md](LEGAL.md)
  - Obtain deployment authorization
  - Verify compliance with local laws
  - Document legal justification for deployment

- [ ] **System Requirements**
  - Dedicated server (not production infrastructure)
  - Isolated network segment
  - Sufficient disk space for logs (200+ GB recommended)
  - Regular backup solution in place

### Configuration Review

- [ ] **Environment Variables (.env)**
  - Copy `.env.example` to `.env`
  - Change default passwords (`ES_PASSWORD`, `KIBANA_ENCRYPTION_KEY`)
  - Set `FIREWALL_WHITELIST` to admin IPs only
  - Review all security-related settings

- [ ] **Docker Configuration**
  - Review `docker-compose.yml` resource limits
  - Ensure containers run as non-root (where possible)
  - Verify network isolation (separate networks for honeypots and ELK)

- [ ] **GeoIP Databases**
  - Download latest GeoLite2 databases
  - Verify checksums
  - Set up automatic updates

---

## Network Security

### Firewall Configuration

**CRITICAL: Only honeypot ports should be internet-accessible!**

- [ ] **Allow honeypot ports (public-facing)**
  ```bash
  sudo ufw allow 2222/tcp comment "Cowrie SSH"
  sudo ufw allow 2223/tcp comment "Cowrie Telnet"
  sudo ufw allow 21/tcp comment "Dionaea FTP"
  sudo ufw allow 80/tcp comment "Dionaea HTTP"
  sudo ufw allow 443/tcp comment "Dionaea HTTPS"
  sudo ufw allow 445/tcp comment "Dionaea SMB"
  sudo ufw allow 3306/tcp comment "Dionaea MySQL"
  sudo ufw allow 1433/tcp comment "Dionaea MSSQL"
  sudo ufw allow 5060/udp comment "Dionaea SIP"
  ```

- [ ] **Restrict management ports (admin IPs only)**
  ```bash
  # Replace 192.168.1.0/24 with your admin network
  sudo ufw allow from 192.168.1.0/24 to any port 9200 comment "Elasticsearch"
  sudo ufw allow from 192.168.1.0/24 to any port 5601 comment "Kibana"
  sudo ufw allow from 192.168.1.0/24 to any port 22 comment "SSH Admin"

  # Deny all other access to management ports
  sudo ufw deny 9200
  sudo ufw deny 5601
  ```

- [ ] **Enable firewall**
  ```bash
  sudo ufw enable
  sudo ufw status verbose
  ```

- [ ] **Verify firewall rules**
  - Test management port access from authorized IPs
  - Test management port access from unauthorized IPs (should fail)
  - Test honeypot ports from external network

### Network Isolation

- [ ] **Docker Networks**
  - Verify honeypot network (172.20.0.0/24) is isolated
  - Verify ELK network (172.21.0.0/24) is separate
  - Ensure no direct routing to production networks

- [ ] **Egress Filtering**
  - Honeypots should NOT have unrestricted internet access
  - Block outbound connections from honeypot containers (optional)
  ```bash
  sudo iptables -A FORWARD -s 172.20.0.0/24 -j DROP
  sudo iptables -A FORWARD -s 172.20.0.0/24 -d 172.21.0.0/24 -j ACCEPT
  ```

- [ ] **Rate Limiting**
  - Implement connection rate limiting to prevent resource exhaustion
  ```bash
  sudo iptables -A INPUT -p tcp --dport 2222 -m state --state NEW \
    -m recent --set
  sudo iptables -A INPUT -p tcp --dport 2222 -m state --state NEW \
    -m recent --update --seconds 60 --hitcount 10 -j DROP
  ```

---

## Access Control

### Elasticsearch Security

- [ ] **Enable Elasticsearch Authentication** (Production)
  - Edit `docker-compose.yml`:
  ```yaml
  environment:
    - xpack.security.enabled=true
    - ELASTIC_PASSWORD=${ES_PASSWORD}
  ```

- [ ] **Set Strong Passwords**
  - Minimum 16 characters
  - Use password manager
  - Rotate every 90 days

- [ ] **API Key Access**
  ```bash
  # Create API key for Python scripts
  curl -X POST localhost:9200/_security/api_key \
    -u elastic:${ES_PASSWORD} \
    -H "Content-Type: application/json" -d'
  {
    "name": "honeypot-analysis",
    "role_descriptors": {
      "honeypot_reader": {
        "cluster": ["monitor"],
        "index": [
          {
            "names": ["honeypot-*"],
            "privileges": ["read"]
          }
        ]
      }
    }
  }'
  ```

### Kibana Security

- [ ] **Enable Kibana Encryption**
  ```bash
  # Generate encryption key
  KIBANA_ENCRYPTION_KEY=$(openssl rand -hex 32)
  echo "KIBANA_ENCRYPTION_KEY=$KIBANA_ENCRYPTION_KEY" >> .env
  ```

- [ ] **Configure HTTPS** (Production)
  - Obtain SSL/TLS certificates
  - Configure Kibana to use HTTPS
  - Redirect HTTP to HTTPS

### SSH Access

- [ ] **SSH Hardening (Host System)**
  - Disable password authentication
  - Use SSH keys only
  - Change default SSH port (not 22)
  - Install fail2ban

  ```bash
  # Edit /etc/ssh/sshd_config
  PasswordAuthentication no
  PubkeyAuthentication yes
  Port 2200  # Change from 22
  PermitRootLogin no
  ```

- [ ] **SSH Key Management**
  - Use strong key type (ed25519 or RSA 4096)
  - Passphrase-protect private keys
  - Restrict authorized_keys file permissions
  ```bash
  chmod 600 ~/.ssh/authorized_keys
  chmod 700 ~/.ssh
  ```

---

## Data Protection

### Data Privacy

- [ ] **PII Removal**
  - Enable PII detection: `PII_REMOVAL_ENABLED=true` in `.env`
  - Review captured data regularly
  - Sanitize IPs if required by regulations

- [ ] **Data Anonymization**
  - Consider anonymizing last octet of IPs: `ANONYMIZE_IPS=true`
  - Redact sensitive domains: `ANONYMIZE_DOMAINS=true`

### Data Retention

- [ ] **Define Retention Policies**
  - Elasticsearch indices: 90 days (default)
  - Reports: 180 days (default)
  - Malware samples: 365 days (default)
  - Adjust in `.env` as needed

- [ ] **Automated Cleanup**
  - Enable: `AUTO_CLEANUP_ENABLED=true`
  - Configure schedule: `CLEANUP_SCHEDULE=0 2 * * 0` (weekly)
  - Test cleanup script: `./scripts/cleanup.sh --days 90`

- [ ] **Secure Data Deletion**
  - Verify old indices are deleted
  - Overwrite deleted files (SSD TRIM enabled)
  - Document data destruction procedures

### Backup & Recovery

- [ ] **Elasticsearch Backups**
  - Configure snapshot repository
  - Schedule weekly snapshots
  - Test restore procedure
  - Store backups off-site (encrypted)

- [ ] **Configuration Backups**
  - Back up `.env` (encrypted)
  - Back up docker-compose.yml
  - Back up analysis scripts
  - Version control configurations (git)

---

## Container Security

### Docker Daemon Security

- [ ] **Docker Daemon Configuration**
  ```json
  {
    "live-restore": true,
    "userland-proxy": false,
    "no-new-privileges": true,
    "userns-remap": "default"
  }
  ```

- [ ] **Limit Docker API Access**
  - Do not expose Docker socket over TCP
  - Restrict socket permissions: `chmod 660 /var/run/docker.sock`
  - Use Docker context for remote management

### Container Hardening

- [ ] **Resource Limits**
  - Review memory limits in `docker-compose.yml`
  - Set CPU limits to prevent resource exhaustion
  - Monitor with `docker stats`

- [ ] **Read-Only Filesystems** (where applicable)
  ```yaml
  services:
    honeypot:
      read_only: true
      tmpfs:
        - /tmp
  ```

- [ ] **Capabilities Dropping**
  - Remove unnecessary Linux capabilities
  - Run containers as non-root user ID

- [ ] **Security Scanning**
  - Scan Docker images for vulnerabilities
  ```bash
  docker scan elasticsearch:8.11.1
  ```

- [ ] **Image Verification**
  - Pull official images only
  - Verify image signatures (Docker Content Trust)
  - Review Dockerfiles for suspicious content

---

## Monitoring & Logging

### Security Monitoring

- [ ] **Enable Real-Time Alerts**
  - Configure Slack/Discord webhooks
  - Set alert threshold: `SLACK_ALERT_THRESHOLD=70`
  - Test alert notifications

- [ ] **Monitor for Anomalies**
  - Unusual spike in attack volume
  - Attacks from unexpected countries
  - Malware samples with very high threat scores
  - Successful honeypot compromises (shouldn't happen)

- [ ] **Log Integrity**
  - Enable log immutability (append-only)
  - Sign logs with checksums
  - Send logs to external SIEM (optional)

### Audit Logging

- [ ] **Docker Event Logging**
  ```bash
  docker events --filter 'type=container' --format '{{json .}}'
  ```

- [ ] **Elasticsearch Audit Logging**
  - Enable audit logging for Elasticsearch API calls
  - Monitor for unauthorized access attempts
  - Review audit logs weekly

- [ ] **System Audit Logging**
  - Enable auditd (Linux)
  - Monitor file changes in critical directories
  - Alert on unauthorized access

### Log Management

- [ ] **Log Rotation**
  - Docker logs: max-size 10m, max-file 3
  - System logs: logrotate configured
  - Elasticsearch logs: delete after 7 days

- [ ] **Centralized Logging** (Optional)
  - Forward logs to external SIEM (Splunk, Graylog)
  - Separate logging infrastructure from honeypots
  - Encrypt log transmission (TLS)

---

## Compliance & Legal

### Regulatory Compliance

- [ ] **GDPR Compliance** (EU)
  - Data processing agreement in place
  - Privacy policy documented
  - Right to erasure procedures defined
  - Data breach notification plan

- [ ] **Data Protection** (Australia - APPs)
  - APP 1: Open and transparent management
  - APP 5: Notification of collection
  - APP 11: Security of personal information
  - APP 13: Correction and deletion

### Legal Documentation

- [ ] **Authorization Documentation**
  - Written authorization for honeypot deployment
  - Network owner consent
  - Defined scope of monitoring

- [ ] **Data Collection Policy**
  - Document what data is collected
  - Document purpose of collection
  - Document retention periods
  - Document data sharing policies

- [ ] **Incident Response Plan**
  - Define roles and responsibilities
  - Escalation procedures
  - Evidence preservation procedures
  - Legal notification requirements

### Ethical Considerations

- [ ] **Proportionality**
  - Honeypots collect only attack data (not user data)
  - No active engagement with attackers
  - No deceptive practices beyond honeypot emulation

- [ ] **Transparency**
  - Clearly document honeypot deployment
  - Inform legal team and management
  - Coordinate with security operations

---

## Ongoing Maintenance

### Weekly Tasks

- [ ] **Review Attack Statistics**
  - Run weekly report: `./scripts/generate_report.sh --days 7`
  - Analyze top attacker IPs and countries
  - Review new malware samples

- [ ] **Security Monitoring**
  - Check for failed login attempts to management interfaces
  - Review Elasticsearch audit logs
  - Verify firewall rules are active

- [ ] **Performance Check**
  - Monitor disk space: `df -h`
  - Check Elasticsearch cluster health
  - Review Docker container stats

### Monthly Tasks

- [ ] **Update Software**
  - Update Docker images: `docker-compose pull`
  - Update Python dependencies: `pip install -U -r requirements.txt`
  - Update GeoIP databases

- [ ] **Security Patches**
  - Apply host OS security updates
  - Update Docker engine
  - Review CVEs for used software

- [ ] **Access Review**
  - Review authorized SSH keys
  - Audit Elasticsearch API keys
  - Review firewall whitelist

- [ ] **Backup Verification**
  - Test Elasticsearch snapshot restore
  - Verify configuration backups
  - Confirm off-site backup storage

### Quarterly Tasks

- [ ] **Security Audit**
  - Run security scan: `./scripts/diagnostics.sh`
  - Review all security configurations
  - Penetration test management interfaces
  - Review and update security policies

- [ ] **Password Rotation**
  - Change Elasticsearch password
  - Regenerate Kibana encryption key
  - Update API keys

- [ ] **Compliance Review**
  - Review data retention compliance
  - Update privacy policies if needed
  - Audit data processing activities

- [ ] **Disaster Recovery Test**
  - Simulate server failure
  - Test full restoration from backups
  - Document recovery time

---

## Security Incident Response

### Detection

- [ ] **Indicators of Compromise**
  - Unauthorized access to Kibana/Elasticsearch
  - Unexpected data deletion
  - Container escape attempts
  - Unusual outbound network connections
  - Honeypot data exfiltration

### Response Procedures

1. **Isolate**
   - Disconnect from network
   - Stop affected containers
   - Preserve evidence

2. **Investigate**
   - Review audit logs
   - Analyze attack vectors
   - Identify data impact

3. **Remediate**
   - Patch vulnerabilities
   - Reset credentials
   - Restore from backups

4. **Report**
   - Notify management
   - Legal notification (if required)
   - Document lessons learned

---

## Security Testing

### Pre-Deployment Testing

- [ ] **Vulnerability Scanning**
  ```bash
  # Scan for open ports
  nmap -sS -sV localhost

  # Scan Docker containers
  docker scan <image-name>
  ```

- [ ] **Penetration Testing** (External)
  - Test firewall rules
  - Attempt unauthorized access to Kibana
  - Attempt unauthorized access to Elasticsearch
  - Test for default credentials

- [ ] **Configuration Review**
  - Run verification script: `./scripts/verify_installation.sh`
  - Review all checklist items
  - Document exceptions/risks

### Ongoing Security Testing

- [ ] **Monthly Port Scans**
  - Verify no new services exposed
  - Confirm management ports restricted

- [ ] **Quarterly Penetration Tests**
  - External penetration test
  - Internal security review
  - Social engineering assessment (optional)

---

## Security Checklist Summary

### Critical (Must Complete Before Deployment)

- [ ] ✅ Firewall configured (management ports restricted)
- [ ] ✅ Strong passwords set (ES, Kibana)
- [ ] ✅ Network isolation verified
- [ ] ✅ Legal authorization obtained
- [ ] ✅ SSH hardened (key-only, non-standard port)
- [ ] ✅ Backup solution configured
- [ ] ✅ Monitoring enabled

### High Priority (Complete Within First Week)

- [ ] ✅ Elasticsearch authentication enabled
- [ ] ✅ HTTPS configured for Kibana
- [ ] ✅ Rate limiting implemented
- [ ] ✅ Audit logging enabled
- [ ] ✅ Data retention policies defined
- [ ] ✅ Incident response plan documented

### Medium Priority (Complete Within First Month)

- [ ] ✅ Security scanning automated
- [ ] ✅ Compliance documentation complete
- [ ] ✅ Penetration test conducted
- [ ] ✅ Alert notifications configured
- [ ] ✅ Container security hardening

### Ongoing (Regular Schedule)

- [ ] ✅ Weekly security monitoring
- [ ] ✅ Monthly software updates
- [ ] ✅ Quarterly security audits
- [ ] ✅ Quarterly password rotation

---

## Sign-Off

**Deployment Authorization:**

| Role | Name | Signature | Date |
|------|------|-----------|------|
| **Security Lead** | | | |
| **IT Manager** | | | |
| **Legal Counsel** | | | |
| **System Administrator** | | | |

**Checklist Completion:**

- Deployment Date: _______________
- Completed By: _______________
- Review Date: _______________

---

**Version:** 1.0.0
**Last Updated:** 2024-01-22

For security issues, contact: security@example.com
