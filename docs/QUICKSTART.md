# Quick Start Guide

Get started with macOS CoreSigma in 5 minutes.

## Prerequisites Check

```bash
python3 --version  # Should be 3.9+
sudo eslogger --version  # macOS 11.0+ required
```

## Installation

```bash
# Clone and setup
git clone https://github.com/Nebulock-Inc/macos-coresigma.git
cd macos-coresigma
./setup.sh
source venv/bin/activate
```

## Start Elasticsearch

```bash
# Using Docker Compose
docker-compose up -d

# Wait for services
./scripts/start_services.sh
```

## Configure Credentials

Choose one method (Keychain recommended for local development):

```bash
# Option 1: Store in macOS Keychain (recommended)
./scripts/setup_credentials.sh

# Option 2: Create API key (recommended for production)
./scripts/setup_credentials.sh --api-key

# Test authentication
./scripts/setup_credentials.sh --test
```

## Set Up Index Templates

```bash
./scripts/setup_elasticsearch_templates.sh
```

## Collect Events

**ESF Events (requires sudo):**
```bash
sudo python3 collectors/esf_collector.py --output elasticsearch
```

**UL Events:**
```bash
python3 collectors/ul_collector.py --output elasticsearch
```

## Deploy Detection Rules

```bash
python3 scripts/deploy_sigma_rules.py
```

## Create Dashboards

```bash
python3 scripts/create_lens_dashboards_ndjson.py
```

## Access Kibana

Open http://localhost:5601 in your browser.

- **Username**: elastic
- **Password**: changeme (or your configured password)

Navigate to:
- **Security > Alerts** - View triggered detection rules
- **Analytics > Dashboards** - Security dashboards

## Convert a Rule Manually

```bash
# Convert ESF rule to Elasticsearch EQL
sigma convert -t elasticsearch -f eql \
  -p ecs_macos_esf \
  rules/esf/process_execution_suspicious.yml

# Convert UL rule to Lucene
sigma convert -t elasticsearch \
  -p ecs_macos_ul \
  rules/ul/tcc_bypass_attempt.yml
```

## Key Directories

| Directory | Contents |
|-----------|----------|
| `collectors/` | ESF and UL data collectors |
| `rules/esf/` | 38 ESF-based Sigma rules |
| `rules/ul/` | 19 UL-based Sigma rules |
| `scripts/` | Setup and utility scripts |
| `exports/` | Kibana dashboard exports |
| `docs/` | Documentation |

## Next Steps

- Read [INSTALLATION.md](INSTALLATION.md) for detailed setup
- Review [FILTERING_CONFIGURATION.md](FILTERING_CONFIGURATION.md) for tuning
- Check [TROUBLESHOOTING.md](TROUBLESHOOTING.md) if you encounter issues
- Explore rules in `rules/esf/` and `rules/ul/`
