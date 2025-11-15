---
name: Bug Report
about: Create a report to help us improve
title: '[BUG] '
labels: bug
assignees: ''
---

## Bug Description

A clear and concise description of what the bug is.

## Steps to Reproduce

1. Go to '...'
2. Run command '....'
3. See error

## Expected Behavior

A clear and concise description of what you expected to happen.

## Actual Behavior

What actually happened instead.

## Environment

**Operating System:**
- OS: [e.g., Ubuntu 22.04]
- Kernel: [e.g., 5.15.0]

**Software Versions:**
- Docker: [e.g., 24.0.0]
- Docker Compose: [e.g., 2.20.0]
- Python: [e.g., 3.9.0]

**Infrastructure:**
- RAM: [e.g., 16GB]
- Disk Space: [e.g., 100GB SSD]
- CPU: [e.g., 4 cores]

## Logs

```
Paste relevant logs here
```

**Elasticsearch Logs:**
```bash
docker logs elasticsearch --tail 50
```

**Logstash Logs:**
```bash
docker logs logstash --tail 50
```

**Other Relevant Logs:**
```
paste here
```

## Screenshots

If applicable, add screenshots to help explain your problem.

## Additional Context

Add any other context about the problem here.

## Troubleshooting Steps Already Tried

- [ ] Checked [TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md)
- [ ] Searched existing issues
- [ ] Ran `make diagnose`
- [ ] Verified system requirements
- [ ] Checked firewall rules
- [ ] Restarted services

## Configuration

**docker-compose.yml modifications:**
```yaml
# Paste any custom modifications
```

**.env file (redacted):**
```bash
# Paste .env (remove sensitive values)
```

---

**Checklist before submitting:**
- [ ] Descriptive title
- [ ] Steps to reproduce included
- [ ] Environment details provided
- [ ] Logs attached
- [ ] Troubleshooting steps attempted
