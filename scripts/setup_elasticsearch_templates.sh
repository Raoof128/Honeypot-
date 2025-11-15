#!/bin/bash
#
# Elasticsearch Index Templates Setup Script
# Loads index templates, lifecycle policies, and component templates
#
# Usage: ./setup_elasticsearch_templates.sh [ES_HOST]
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Default Elasticsearch host
ES_HOST="${1:-localhost:9200}"

echo -e "${BLUE}"
echo "================================================================"
echo "  ELASTICSEARCH INDEX TEMPLATES SETUP"
echo "================================================================"
echo -e "${NC}"

# Wait for Elasticsearch to be ready
echo -e "${YELLOW}[*]${NC} Waiting for Elasticsearch to be ready..."
max_attempts=30
attempt=0

while [ $attempt -lt $max_attempts ]; do
    if curl -s "http://$ES_HOST/_cluster/health" > /dev/null 2>&1; then
        echo -e "${GREEN}[✓]${NC} Elasticsearch is ready"
        break
    fi

    attempt=$((attempt + 1))
    echo "  Attempt $attempt/$max_attempts..."
    sleep 2
done

if [ $attempt -eq $max_attempts ]; then
    echo -e "${RED}[✗]${NC} Elasticsearch is not responding after $max_attempts attempts"
    exit 1
fi

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
TEMPLATES_FILE="$PROJECT_ROOT/infrastructure/elk-stack/index-templates.json"

# Check if templates file exists
if [ ! -f "$TEMPLATES_FILE" ]; then
    echo -e "${RED}[✗]${NC} Templates file not found: $TEMPLATES_FILE"
    exit 1
fi

echo -e "${YELLOW}[*]${NC} Loading templates from: $TEMPLATES_FILE"

# Parse and load component templates
echo -e "${YELLOW}[*]${NC} Loading component templates..."
component_count=$(jq -r '.component_templates | length' "$TEMPLATES_FILE")

for i in $(seq 0 $((component_count - 1))); do
    name=$(jq -r ".component_templates[$i].name" "$TEMPLATES_FILE")
    template=$(jq -c ".component_templates[$i].template" "$TEMPLATES_FILE")

    echo "  Loading component template: $name"

    response=$(curl -s -X PUT "http://$ES_HOST/_component_template/$name" \
        -H 'Content-Type: application/json' \
        -d "{\"template\": $template}")

    if echo "$response" | jq -e '.acknowledged == true' > /dev/null 2>&1; then
        echo -e "${GREEN}  [✓]${NC} Component template '$name' loaded successfully"
    else
        echo -e "${RED}  [✗]${NC} Failed to load component template '$name'"
        echo "  Response: $response"
    fi
done

# Parse and load index templates
echo -e "${YELLOW}[*]${NC} Loading index templates..."
template_count=$(jq -r '.templates | length' "$TEMPLATES_FILE")

for i in $(seq 0 $((template_count - 1))); do
    name=$(jq -r ".templates[$i].name" "$TEMPLATES_FILE")
    index_patterns=$(jq -c ".templates[$i].index_patterns" "$TEMPLATES_FILE")
    priority=$(jq -r ".templates[$i].priority" "$TEMPLATES_FILE")
    template=$(jq -c ".templates[$i].template" "$TEMPLATES_FILE")

    echo "  Loading index template: $name (priority: $priority)"
    echo "    Index patterns: $index_patterns"

    request_body=$(jq -n \
        --argjson patterns "$index_patterns" \
        --argjson prio "$priority" \
        --argjson tmpl "$template" \
        '{index_patterns: $patterns, priority: $prio, template: $tmpl}')

    response=$(curl -s -X PUT "http://$ES_HOST/_index_template/$name" \
        -H 'Content-Type: application/json' \
        -d "$request_body")

    if echo "$response" | jq -e '.acknowledged == true' > /dev/null 2>&1; then
        echo -e "${GREEN}  [✓]${NC} Index template '$name' loaded successfully"
    else
        echo -e "${RED}  [✗]${NC} Failed to load index template '$name'"
        echo "  Response: $response"
    fi
done

# Parse and load lifecycle policies
echo -e "${YELLOW}[*]${NC} Loading index lifecycle policies..."
policy_count=$(jq -r '.index_lifecycle_policies | length' "$TEMPLATES_FILE")

for i in $(seq 0 $((policy_count - 1))); do
    name=$(jq -r ".index_lifecycle_policies[$i].name" "$TEMPLATES_FILE")
    policy=$(jq -c ".index_lifecycle_policies[$i].policy" "$TEMPLATES_FILE")

    echo "  Loading lifecycle policy: $name"

    response=$(curl -s -X PUT "http://$ES_HOST/_ilm/policy/$name" \
        -H 'Content-Type: application/json' \
        -d "{\"policy\": $policy}")

    if echo "$response" | jq -e '.acknowledged == true' > /dev/null 2>&1; then
        echo -e "${GREEN}  [✓]${NC} Lifecycle policy '$name' loaded successfully"
    else
        echo -e "${RED}  [✗]${NC} Failed to load lifecycle policy '$name'"
        echo "  Response: $response"
    fi
done

# Verify templates
echo ""
echo -e "${YELLOW}[*]${NC} Verifying index templates..."
templates=$(curl -s "http://$ES_HOST/_index_template" | jq -r '.index_templates[].name' | grep -c "honeypot-" || echo "0")
echo -e "${GREEN}[✓]${NC} Found $templates honeypot index templates"

echo ""
echo -e "${YELLOW}[*]${NC} Verifying lifecycle policies..."
policies=$(curl -s "http://$ES_HOST/_ilm/policy" | jq -r 'keys[]' | grep -c "honeypot-" || echo "0")
echo -e "${GREEN}[✓]${NC} Found $policies honeypot lifecycle policies"

echo ""
echo -e "${GREEN}"
echo "================================================================"
echo "  ELASTICSEARCH TEMPLATES SETUP COMPLETE"
echo "================================================================"
echo -e "${NC}"
echo "Summary:"
echo "  - Component templates: $component_count"
echo "  - Index templates: $template_count"
echo "  - Lifecycle policies: $policy_count"
echo ""
echo "Templates are now ready. Indices matching honeypot-* will"
echo "automatically use these templates with optimized mappings."
echo ""
