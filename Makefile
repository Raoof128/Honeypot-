.PHONY: help install deploy start stop restart status logs clean test lint format

# Default target
.DEFAULT_GOAL := help

help: ## Show this help message
	@echo "Honeypot Threat Intelligence Infrastructure - Make Commands"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

install: ## Install Python dependencies
	@echo "Installing Python dependencies..."
	pip3 install -r requirements.txt
	@echo "✓ Dependencies installed"

setup: ## Initial setup (install deps, create dirs, set permissions)
	@echo "Running initial setup..."
	@./scripts/setup.sh
	@echo "✓ Setup complete"

validate: ## Validate configurations
	@echo "Validating configurations..."
	@python3 -m py_compile analysis/*.py
	@docker-compose -f infrastructure/docker-compose.yml config > /dev/null
	@echo "✓ Validation complete"

deploy: ## Deploy honeypot infrastructure
	@echo "Deploying infrastructure..."
	@sudo ./scripts/deploy.sh
	@echo "✓ Deployment complete"

start: ## Start all services
	@echo "Starting services..."
	@cd infrastructure && docker-compose up -d
	@echo "✓ Services started"

stop: ## Stop all services
	@echo "Stopping services..."
	@cd infrastructure && docker-compose down
	@echo "✓ Services stopped"

restart: ## Restart all services
	@echo "Restarting services..."
	@cd infrastructure && docker-compose restart
	@echo "✓ Services restarted"

status: ## Show service status
	@cd infrastructure && docker-compose ps

logs: ## Show logs from all services
	@cd infrastructure && docker-compose logs -f

logs-cowrie: ## Show Cowrie logs
	@cd infrastructure && docker-compose logs -f cowrie

logs-dionaea: ## Show Dionaea logs
	@cd infrastructure && docker-compose logs -f dionaea

logs-elasticsearch: ## Show Elasticsearch logs
	@cd infrastructure && docker-compose logs -f elasticsearch

logs-logstash: ## Show Logstash logs
	@cd infrastructure && docker-compose logs -f logstash

monitor: ## Start real-time monitoring dashboard
	@./scripts/monitor.sh --interval 10

report: ## Generate threat intelligence report (7 days)
	@./scripts/generate_report.sh --days 7

report-today: ## Generate report for today
	@./scripts/generate_report.sh --days 1

extract-iocs: ## Extract IOCs from honeypot logs
	@python3 analysis/ioc_extraction.py --days 7

geo-analysis: ## Run geographic analysis
	@python3 analysis/geolocation_mapper.py --days 7

mitre-analysis: ## Run MITRE ATT&CK analysis
	@python3 analysis/mitre_attck_mapper.py --days 7

health-check: ## Check health of all services
	@echo "Checking service health..."
	@curl -s http://localhost:9200/_cluster/health | jq . || echo "✗ Elasticsearch not responding"
	@curl -s http://localhost:5601/api/status | jq . || echo "✗ Kibana not responding"
	@curl -s http://localhost:9600/_node/stats | jq . || echo "✗ Logstash not responding"
	@docker ps --filter "name=cowrie" --filter "status=running" -q || echo "✗ Cowrie not running"
	@echo "✓ Health check complete"

clean: ## Clean up logs and temporary files
	@echo "Cleaning up..."
	@rm -rf reports/generated/*.json reports/generated/*.csv reports/generated/*.md
	@echo "✓ Cleanup complete"

clean-all: ## Clean up everything including Docker volumes (DESTRUCTIVE)
	@echo "WARNING: This will delete all honeypot data!"
	@read -p "Are you sure? [y/N] " -n 1 -r; \
	echo; \
	if [[ $$REPLY =~ ^[Yy]$$ ]]; then \
		cd infrastructure && docker-compose down -v; \
		rm -rf ../data/*; \
		echo "✓ All data cleaned"; \
	fi

test: ## Run unit tests
	@echo "Running tests..."
	@python3 -m pytest tests/ -v
	@echo "✓ Tests complete"

test-coverage: ## Run tests with coverage
	@echo "Running tests with coverage..."
	@python3 -m pytest tests/ --cov=analysis --cov-report=html
	@echo "✓ Coverage report generated in htmlcov/"

lint: ## Lint Python code
	@echo "Linting Python code..."
	@pylint analysis/*.py || true
	@flake8 analysis/*.py || true
	@echo "✓ Linting complete"

format: ## Format Python code with black
	@echo "Formatting Python code..."
	@black analysis/*.py tests/*.py
	@echo "✓ Formatting complete"

backup: ## Backup Elasticsearch indices
	@echo "Backing up Elasticsearch indices..."
	@mkdir -p backups
	@curl -X POST "localhost:9200/_snapshot/backup/snapshot_$$(date +%Y%m%d_%H%M%S)?wait_for_completion=true"
	@echo "✓ Backup complete"

docs: ## Generate documentation
	@echo "Documentation available in docs/ directory"
	@echo "- README.md"
	@echo "- docs/DEPLOYMENT.md"
	@echo "- docs/TROUBLESHOOTING.md"
	@echo "- docs/LEGAL.md"

shell-es: ## Open Elasticsearch container shell
	@docker exec -it elasticsearch bash

shell-logstash: ## Open Logstash container shell
	@docker exec -it logstash bash

shell-cowrie: ## Open Cowrie container shell
	@docker exec -it cowrie bash

shell-dionaea: ## Open Dionaea container shell
	@docker exec -it dionaea bash

update: ## Update Docker images
	@echo "Updating Docker images..."
	@cd infrastructure && docker-compose pull
	@echo "✓ Images updated"

diagnose: ## Run diagnostics
	@echo "Running diagnostics..."
	@bash scripts/diagnostics.sh || echo "Create diagnostics.sh first"
	@echo "✓ Diagnostics complete"
