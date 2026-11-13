# Quick Start Guide

Get started with macOS coreSigma on the Docker bench.

## Prerequisites Check

```bash
sw_vers -productVersion   # 13 or later; newer releases support more ESF events (see INSTALLATION.md)
python3 --version         # 3.10 to 3.14 for the tooling (3.13+ only for the optional ClickHouse backend)
docker info > /dev/null && echo "Docker is running"
```

macOS's own `python3` is 3.9, and Homebrew's current `python3` may be 3.15, which pySigma 1.5.1 doesn't run on yet. Install one in range (`brew install python@3.13`); `setup.sh` also finds `python3.10` to `python3.14` on your PATH. For Docker, install Docker Desktop or another Docker runtime with the `docker compose` plugin. Setup downloads from PyPI (`pypi.org`, `files.pythonhosted.org`), and the bench pulls images from `docker.elastic.co`.

## Installation

```bash
# Clone and setup
git clone https://github.com/Nebulock-Inc/macos-coresigma.git
cd macos-coresigma
./setup.sh
source venv/bin/activate
```

## Start Elasticsearch and Kibana

```bash
# Writes .env (bench password, random Kibana keys), starts both, waits until healthy, creates the index templates
./scripts/bench_up.sh elastic
```

## Configure Credentials

```bash
# The bench password from .env
export ES_USER=elastic ES_PASSWORD="$(grep '^ELASTIC_PASSWORD=' .env | cut -d= -f2-)"

# Or store credentials in the macOS Keychain (not visible to the ESF collector under sudo)
./scripts/setup_credentials.sh
./scripts/setup_credentials.sh --test
```

## Collect Events

**ESF Events (requires sudo and Full Disk Access):**
```bash
sudo --preserve-env=ES_USER,ES_PASSWORD,ES_API_KEY /usr/bin/python3 collectors/esf_collector.py --output elasticsearch
```

**UL Events:**
```bash
python3 collectors/ul_collector.py --output elasticsearch
```

## Deploy Detection Rules

```bash
python3 scripts/deploy_sigma_rules.py --enable
```

This creates Kibana detection rules for the 69 rules with output of their own, correlations included (EQL, and ES|QL for the unordered correlations), and enables them.

## Create Dashboards

```bash
python3 scripts/create_lens_dashboards_ndjson.py
```

## Access Kibana

Open http://localhost:5601 in your browser.

- **Username**: elastic
- **Password**: `ELASTIC_PASSWORD` in `.env`

Navigate to:
- **Security > Alerts** - alerts from the detection rules
- **Analytics > Dashboards** - the coreSigma dashboards

## Convert a Rule Manually

```bash
# ESF rule to EQL
sigma convert -t eql -p macos_esf_ecs rules/esf/process_execution_suspicious.yml

# UL rule to Splunk SPL (stack both pipelines when converting ESF and UL rules together)
sigma convert -t splunk -p macos_esf_ecs -p macos_ul_ecs rules/ul/tcc_bypass_attempt.yml
```

## Key Directories

| Directory | Contents |
|-----------|----------|
| `collectors/` | ESF and UL data collectors |
| `rules/esf/` | Sigma rules on ESF events |
| `rules/ul/` | Sigma rules on Unified Log lines |
| `rules/correlation/` | Sigma correlation rules |
| `pipelines/pysigma-pipeline-macos/` | The pySigma plugin |
| `scripts/` | Setup, deployment and bench scripts |
| `exports/` | Kibana dashboard exports |
| `docs/` | Documentation, including the support matrix |

## Next Steps

- Read [INSTALLATION.md](INSTALLATION.md) for detailed setup
- Check [SUPPORT_MATRIX.md](SUPPORT_MATRIX.md) for what each rule was verified on
- Review [TUNING_GUIDE.md](TUNING_GUIDE.md) and [FILTERING_CONFIGURATION.md](FILTERING_CONFIGURATION.md) for tuning
- Check [TROUBLESHOOTING.md](TROUBLESHOOTING.md) if you encounter issues
