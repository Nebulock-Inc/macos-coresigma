# Quick Start Guide

Get started with macOS Sigma Pipelines in 5 minutes.

## Prerequisites Check

```bash
python3 --version  # Should be 3.9+
sudo eslogger --version  # macOS 11.0+ required
```

## Installation

```bash
# Clone and setup
git clone https://github.com/yourusername/macos-sigma-pipelines-new.git
cd macos-sigma-pipelines-new
./setup.sh
source venv/bin/activate
```

## Test the Pipeline

```bash
# Test rule conversion
./scripts/test_pipeline.sh

# Run end-to-end tests (requires Elasticsearch)
python3 tests/test_e2e.py
```

## Collect Events

**ESF Events:**
```bash
sudo python3 collectors/esf_collector.py --output stdout
```

**UL Events:**
```bash
python3 collectors/ul_collector.py --output stdout
```

## Convert a Rule

```bash
# Convert ESF rule to Elasticsearch Lucene
sigma convert -t lucene \
  -p pipelines/macos_esf.yml \
  rules/esf/process_execution_suspicious.yml

# Convert UL rule to Elasticsearch EQL
sigma convert -t eql \
  -p pipelines/macos_ul.yml \
  rules/ul/tcc_unusual_access.yml
```

## Example Workflow

1. **Start Elasticsearch** (Docker):
   ```bash
   docker run -d -p 9200:9200 -e "discovery.type=single-node" -e "xpack.security.enabled=false" docker.elastic.co/elasticsearch/elasticsearch:8.11.0
   ```

2. **Collect Events**:
   ```bash
   sudo python3 collectors/esf_collector.py \
     --output elasticsearch \
     --es-url http://localhost:9200
   ```

3. **Convert Rule**:
   ```bash
   sigma convert -t lucene \
     -p pipelines/macos_esf.yml \
     rules/esf/process_execution_suspicious.yml \
     > query.lucene
   ```

4. **Query Elasticsearch**:
   ```bash
   curl -X GET "localhost:9200/macos-telemetry-esf-*/_search?q=$(cat query.lucene)&pretty"
   ```

## Key Files

- **Pipelines**: `pipelines/macos_esf.yml`, `pipelines/macos_ul.yml`
- **Collectors**: `collectors/esf_collector.py`, `collectors/ul_collector.py`
- **Rules**: `rules/esf/`, `rules/ul/`
- **Tests**: `tests/test_e2e.py`

## Next Steps

- Read [INSTALLATION.md](INSTALLATION.md) for detailed setup
- Review [BLOG_POST.md](BLOG_POST.md) for project overview
- Check sample rules in `rules/` directory

