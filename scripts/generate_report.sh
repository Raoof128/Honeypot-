#!/bin/bash
#
# Automated Threat Intelligence Report Generation
# Generates comprehensive weekly/monthly threat intelligence reports
#
# Usage: ./generate_report.sh [--days N] [--output-dir DIR]
#
# Author: Threat Intelligence Pipeline
# Version: 1.0.0
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
ANALYSIS_DIR="$PROJECT_ROOT/analysis"
OUTPUT_DIR="$PROJECT_ROOT/reports/generated"
DAYS=7
ES_HOST="localhost"
ES_PORT=9200

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --days)
            DAYS="$2"
            shift 2
            ;;
        --output-dir)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --days N             Number of days to analyze (default: 7)"
            echo "  --output-dir DIR     Output directory (default: reports/generated)"
            echo "  --help               Show this help message"
            exit 0
            ;;
        *)
            shift
            ;;
    esac
done

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Timestamp for report
TIMESTAMP=$(date '+%Y-%m-%d_%H%M%S')
REPORT_DATE=$(date '+%Y-%m-%d')

echo -e "${BLUE}"
echo "================================================================"
echo "  THREAT INTELLIGENCE REPORT GENERATION"
echo "  Period: Last $DAYS days"
echo "================================================================"
echo -e "${NC}"

# Step 1: IOC Extraction
echo -e "${YELLOW}[1/5]${NC} Extracting IOCs..."
python3 "$ANALYSIS_DIR/ioc_extraction.py" \
    --es-host "$ES_HOST" \
    --es-port "$ES_PORT" \
    --days "$DAYS" \
    --confidence 0.1 \
    --output-json "$OUTPUT_DIR/iocs_${TIMESTAMP}.json" \
    --output-csv "$OUTPUT_DIR/iocs_${TIMESTAMP}.csv" \
    --output-md "$OUTPUT_DIR/ioc_report_${TIMESTAMP}.md"

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓${NC} IOC extraction complete"
else
    echo -e "${RED}✗${NC} IOC extraction failed"
    exit 1
fi

# Step 2: Geographic Analysis
echo -e "${YELLOW}[2/5]${NC} Performing geographic analysis..."
python3 "$ANALYSIS_DIR/geolocation_mapper.py" \
    --es-host "$ES_HOST" \
    --es-port "$ES_PORT" \
    --days "$DAYS" \
    --output-json "$OUTPUT_DIR/geo_analysis_${TIMESTAMP}.json" \
    --output-heatmap "$OUTPUT_DIR/attack_heatmap_${TIMESTAMP}.html" \
    --output-report "$OUTPUT_DIR/geo_report_${TIMESTAMP}.md"

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓${NC} Geographic analysis complete"
else
    echo -e "${RED}✗${NC} Geographic analysis failed"
    exit 1
fi

# Step 3: MITRE ATT&CK Mapping
echo -e "${YELLOW}[3/5]${NC} Mapping to MITRE ATT&CK framework..."
python3 "$ANALYSIS_DIR/mitre_attck_mapper.py" \
    --es-host "$ES_HOST" \
    --es-port "$ES_PORT" \
    --days "$DAYS" \
    --output-json "$OUTPUT_DIR/mitre_analysis_${TIMESTAMP}.json" \
    --output-navigator "$OUTPUT_DIR/attack_navigator_${TIMESTAMP}.json" \
    --output-report "$OUTPUT_DIR/mitre_report_${TIMESTAMP}.md"

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓${NC} MITRE ATT&CK mapping complete"
else
    echo -e "${RED}✗${NC} MITRE ATT&CK mapping failed"
    exit 1
fi

# Step 4: Threat Feed Generation
echo -e "${YELLOW}[4/5]${NC} Generating threat intelligence feeds..."
python3 "$ANALYSIS_DIR/threat_feed_generator.py" \
    --ioc-file "$OUTPUT_DIR/iocs_${TIMESTAMP}.json" \
    --output-stix "$OUTPUT_DIR/threat_feed_${TIMESTAMP}.stix.json" \
    --output-json "$OUTPUT_DIR/threat_feed_${TIMESTAMP}.json" \
    --output-csv "$OUTPUT_DIR/threat_feed_${TIMESTAMP}.csv" \
    --output-misp "$OUTPUT_DIR/threat_feed_${TIMESTAMP}.misp.json"

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓${NC} Threat feed generation complete"
else
    echo -e "${RED}✗${NC} Threat feed generation failed"
    exit 1
fi

# Step 5: Consolidated Report
echo -e "${YELLOW}[5/5]${NC} Creating consolidated executive report..."

EXEC_REPORT="$OUTPUT_DIR/executive_report_${TIMESTAMP}.md"

cat > "$EXEC_REPORT" << EOF
# Threat Intelligence Executive Report

**Report Date:** $REPORT_DATE
**Analysis Period:** Last $DAYS days
**Generated:** $(date '+%Y-%m-%d %H:%M:%S %Z')

---

## Executive Summary

This report summarizes threat intelligence collected from our multi-honeypot infrastructure over the past $DAYS days. The analysis includes:

- **Indicators of Compromise (IOCs)** extracted from attack sessions
- **Geographic distribution** of attack sources
- **Tactics, Techniques, and Procedures (TTPs)** mapped to MITRE ATT&CK
- **Actionable threat feeds** for defensive integration

---

## Key Metrics

EOF

# Extract key metrics from IOC report
if [ -f "$OUTPUT_DIR/iocs_${TIMESTAMP}.json" ]; then
    total_ips=$(jq -r '.statistics.total_unique_ips // 0' "$OUTPUT_DIR/iocs_${TIMESTAMP}.json")
    total_hashes=$(jq -r '.statistics.total_file_hashes // 0' "$OUTPUT_DIR/iocs_${TIMESTAMP}.json")
    total_creds=$(jq -r '.statistics.total_credentials // 0' "$OUTPUT_DIR/iocs_${TIMESTAMP}.json")
    total_commands=$(jq -r '.statistics.total_commands // 0' "$OUTPUT_DIR/iocs_${TIMESTAMP}.json")

    cat >> "$EXEC_REPORT" << EOF
### Attack Surface

| Metric | Count |
|--------|-------|
| Unique Attacker IPs | $total_ips |
| Malware Samples | $total_hashes |
| Credential Attempts | $total_creds |
| Commands Executed | $total_commands |

EOF
fi

# Extract geographic metrics
if [ -f "$OUTPUT_DIR/geo_analysis_${TIMESTAMP}.json" ]; then
    total_countries=$(jq -r '.statistics.unique_countries // 0' "$OUTPUT_DIR/geo_analysis_${TIMESTAMP}.json")
    attack_corridors=$(jq -r '.statistics.attack_corridors_count // 0' "$OUTPUT_DIR/geo_analysis_${TIMESTAMP}.json")

    cat >> "$EXEC_REPORT" << EOF
### Geographic Distribution

| Metric | Count |
|--------|-------|
| Unique Countries | $total_countries |
| Attack Corridors (High-Risk) | $attack_corridors |

**Top 5 Attacking Countries:**

EOF

    jq -r '.statistics.top_countries[0:5][] | "- \(.[0]): \(.[1]) attacks"' "$OUTPUT_DIR/geo_analysis_${TIMESTAMP}.json" >> "$EXEC_REPORT" 2>/dev/null || echo "- Data not available" >> "$EXEC_REPORT"

    echo "" >> "$EXEC_REPORT"
fi

# Extract MITRE metrics
if [ -f "$OUTPUT_DIR/mitre_analysis_${TIMESTAMP}.json" ]; then
    total_techniques=$(jq -r '.statistics.total_techniques_observed // 0' "$OUTPUT_DIR/mitre_analysis_${TIMESTAMP}.json")
    most_common_tactic=$(jq -r '.statistics.most_common_tactic // "Unknown"' "$OUTPUT_DIR/mitre_analysis_${TIMESTAMP}.json")

    cat >> "$EXEC_REPORT" << EOF
### MITRE ATT&CK Coverage

| Metric | Value |
|--------|-------|
| Techniques Observed | $total_techniques |
| Most Common Tactic | $most_common_tactic |

**Top 5 Techniques:**

EOF

    jq -r '.statistics.top_techniques[0:5][] | "- \(.[0]): \(.[2]) (\(.[1]) occurrences)"' "$OUTPUT_DIR/mitre_analysis_${TIMESTAMP}.json" >> "$EXEC_REPORT" 2>/dev/null || echo "- Data not available" >> "$EXEC_REPORT"

    echo "" >> "$EXEC_REPORT"
fi

# Add detailed report links
cat >> "$EXEC_REPORT" << EOF

---

## Detailed Reports

This executive summary is accompanied by the following detailed analysis reports:

1. **IOC Report:** \`ioc_report_${TIMESTAMP}.md\`
   - Complete list of extracted indicators
   - Top attacker IPs, credentials, and malware hashes

2. **Geographic Analysis:** \`geo_report_${TIMESTAMP}.md\`
   - Country and city-level attack distribution
   - Attack corridor identification
   - Interactive heat map: \`attack_heatmap_${TIMESTAMP}.html\`

3. **MITRE ATT&CK Analysis:** \`mitre_report_${TIMESTAMP}.md\`
   - Technique and tactic breakdown
   - ATT&CK Navigator layer: \`attack_navigator_${TIMESTAMP}.json\`
   - Upload to: https://mitre-attack.github.io/attack-navigator/

4. **Threat Feeds:**
   - STIX 2.1: \`threat_feed_${TIMESTAMP}.stix.json\`
   - JSON: \`threat_feed_${TIMESTAMP}.json\`
   - CSV: \`threat_feed_${TIMESTAMP}.csv\`
   - MISP: \`threat_feed_${TIMESTAMP}.misp.json\`

---

## Recommendations

Based on this analysis, the following defensive actions are recommended:

1. **Network Defense:**
   - Block identified malicious IPs at perimeter firewall
   - Monitor for connections to identified C2 domains
   - Update IDS/IPS signatures with observed attack patterns

2. **Endpoint Protection:**
   - Add malware hashes to EDR/AV blocklists
   - Monitor for execution of observed commands
   - Implement privilege escalation controls

3. **Access Control:**
   - Disable/monitor accounts using observed credential combinations
   - Implement MFA for SSH/remote access
   - Review and strengthen password policies

4. **Threat Hunting:**
   - Search internal logs for indicators from this report
   - Investigate any matches for potential compromise
   - Correlate with other threat intelligence sources

---

## Report Artifacts

All report artifacts are stored in: \`$OUTPUT_DIR\`

**Files Generated:**

EOF

# List all generated files
ls -lh "$OUTPUT_DIR" | grep "$TIMESTAMP" | awk '{print "- " $9 " (" $5 ")"}' >> "$EXEC_REPORT"

cat >> "$EXEC_REPORT" << EOF

---

**Report Generation Time:** $(date '+%Y-%m-%d %H:%M:%S %Z')
**Analysis Period:** $(date -d "$DAYS days ago" '+%Y-%m-%d') to $(date '+%Y-%m-%d')
**Honeypot Infrastructure Version:** 1.0.0

EOF

echo -e "${GREEN}✓${NC} Executive report created"

# Summary
echo ""
echo -e "${GREEN}"
echo "================================================================"
echo "  REPORT GENERATION COMPLETE"
echo "================================================================"
echo -e "${NC}"
echo ""
echo "Reports generated in: $OUTPUT_DIR"
echo ""
echo "Main Reports:"
echo "  • Executive Summary:     executive_report_${TIMESTAMP}.md"
echo "  • IOC Report:            ioc_report_${TIMESTAMP}.md"
echo "  • Geographic Analysis:   geo_report_${TIMESTAMP}.md"
echo "  • MITRE ATT&CK Analysis: mitre_report_${TIMESTAMP}.md"
echo ""
echo "Threat Feeds:"
echo "  • STIX 2.1:  threat_feed_${TIMESTAMP}.stix.json"
echo "  • JSON Feed: threat_feed_${TIMESTAMP}.json"
echo "  • CSV Feed:  threat_feed_${TIMESTAMP}.csv"
echo "  • MISP JSON: threat_feed_${TIMESTAMP}.misp.json"
echo ""
echo "Visualizations:"
echo "  • Attack Heat Map:       attack_heatmap_${TIMESTAMP}.html"
echo "  • ATT&CK Navigator:      attack_navigator_${TIMESTAMP}.json"
echo ""
echo "================================================================"
echo ""
echo "Next Steps:"
echo "  1. Review executive_report_${TIMESTAMP}.md"
echo "  2. Open attack_heatmap_${TIMESTAMP}.html in browser"
echo "  3. Upload attack_navigator_${TIMESTAMP}.json to MITRE ATT&CK Navigator"
echo "  4. Integrate threat feeds into SIEM/EDR platforms"
echo ""
