# macOS CoreSigma

**macOS CoreSigma** is a comprehensive Sigma-based detection framework for macOS Endpoint Security Framework (ESF) and Unified Logging (UL) telemetry. It enables security teams to leverage the Sigma rule format for advanced macOS threat detection and hunting.

## 🎯 Overview

CoreSigma provides:

- **57 Detection Rules** - 38 ESF rules and 19 UL rules covering process execution, file events, authentication, privilege escalation, persistence, and more
- **ECS-Compatible Data Collection** - Collectors that normalize ESF/UL events to Elastic Common Schema (ECS) format
- **Intelligent Filtering** - Reduces log volume by ~98.5% while preserving 100% security-relevant events
- **Kibana Dashboards** - Pre-built security dashboards for real-time monitoring
- **pySigma Integration** - Compatible with the `ecs_macos_esf` pipeline in `pySigma-backend-elasticsearch`

## 🔗 Related Projects

- **[pySigma-backend-elasticsearch](https://github.com/SigmaHQ/pySigma-backend-elasticsearch)** - The pySigma backend with `ecs_macos_esf` pipeline (PR #171)
- **[sigma-specification](https://github.com/SigmaHQ/sigma-specification)** - Sigma taxonomy with macOS ESF logsource (PR #25)

## 🚀 Quick Start

### Prerequisites

- macOS 11.0+ (Big Sur or later)
- Python 3.9+
- Elasticsearch 8.x and Kibana
- Root/sudo access (required for ESF collection via `eslogger`)

### Installation

```bash
# Clone the repository
git clone https://github.com/Nebulock-Inc/macos-coresigma.git
cd macos-coresigma

# Run setup
./setup.sh
source venv/bin/activate

# Start Elasticsearch and Kibana (if using Docker)
docker-compose up -d
```

### Running the ESF Collector

```bash
# With intelligent filtering (recommended - reduces volume by 98.5%)
ES_USER=elastic ES_PASSWORD=changeme sudo python3 collectors/esf_collector.py --output elasticsearch

# Without filtering (all events)
ES_USER=elastic ES_PASSWORD=changeme sudo python3 collectors/esf_collector.py --output elasticsearch --no-filtering
```

### Running the UL Collector

```bash
# Unified Logging collector (no sudo required)
ES_USER=elastic ES_PASSWORD=changeme python3 collectors/ul_collector.py --output elasticsearch
```

### Creating Kibana Dashboards

```bash
# Create security dashboards
ES_USER=elastic ES_PASSWORD=changeme python3 scripts/create_lens_dashboards_ndjson.py
```

## 📁 Directory Structure

```
macos-coresigma/
├── collectors/             # Data collection scripts
│   ├── esf_collector.py   # ESF event collector with ECS normalization
│   └── ul_collector.py    # Unified Logging collector
├── rules/                  # Sigma detection rules
│   ├── esf/               # 38 ESF-based rules
│   └── ul/                # 12 UL-based rules
├── pipelines/             # Sigma pipeline configs (YAML)
│   ├── macos_esf.yml     # ESF pipeline definition
│   └── macos_ul.yml      # UL pipeline definition
├── exports/               # Kibana dashboard exports
├── scripts/               # Utility scripts
├── tests/                 # Test suite
└── docs/                  # Documentation
```

## 🔍 Detection Coverage

### ESF Event Categories

| Category | Event Types | Example Rules |
|----------|-------------|---------------|
| Process Creation | exec, fork, exit | Suspicious process execution, mass termination |
| File Events | create, write, unlink, rename | Persistence creation, sensitive file deletion |
| Authentication | login, logout, setuid, setgid | Privilege escalation, authentication monitoring |
| Memory | mprotect | W+X memory mapping (code injection) |
| Code Signing | cs_invalidated | Code signature invalidation |
| Security Policy | tcc_modify, xprotect, gatekeeper | TCC bypass, malware detection |
| Network | (planned) | Network connection monitoring |

### Sample Rules

- **Process Execution**: Suspicious curl downloads, execution from temp directories
- **Persistence**: LaunchAgent/Daemon creation, kernel extension loading
- **Privilege Escalation**: setuid/setgid to root, sudo usage
- **Defense Evasion**: TCC database modification, code signature invalidation
- **Lateral Movement**: Screen sharing sessions, SSH connections

## 🔧 Field Mappings

CoreSigma maps Sigma taxonomy fields to ECS fields:

| Sigma Field | ECS Field | Description |
|-------------|-----------|-------------|
| `Image` | `process.executable` | Process executable path |
| `CommandLine` | `process.command_line` | Full command line |
| `User` | `process.user.name` | Effective username |
| `ParentImage` | `process.parent.executable` | Parent process path |
| `TargetFilename` | `file.path` | Target file path |
| `esf.event_type` | `esf.event_type` | Numeric ESF event type |
| `event.action` | `event.action` | Event action name |

See [FIELD_NAME_ORIGINS.md](docs/FIELD_NAME_ORIGINS.md) for complete mappings.

## 📊 Intelligent Filtering

The ESF collector implements intelligent filtering to reduce noise:

| Event Type | Filtering Strategy | Reduction |
|------------|-------------------|-----------|
| `open` | Security-relevant paths only | ~99% |
| `close` | Modified files only | ~99% |
| `lookup` | Critical paths only | ~99.9% |
| `mprotect` | W+X permissions only | ~99.6% |
| All others | Full capture | 0% |

**Result**: ~1.98M events/day → ~30K events/day with zero security impact.

See [FILTERING_CONFIGURATION.md](docs/FILTERING_CONFIGURATION.md) for details.

## 🧪 Converting Sigma Rules

Using the pySigma backend with the `ecs_macos_esf` pipeline:

```bash
# Install pySigma with Elasticsearch backend
pip install pysigma-backend-elasticsearch

# Convert a rule to Lucene query
sigma convert -t elasticsearch -p ecs_macos_esf rules/esf/process_execution_suspicious.yml

# Convert to EQL
sigma convert -t elasticsearch -f eql -p ecs_macos_esf rules/esf/macos_tcc_database_modification.yml
```

## 🐳 Docker Deployment

```bash
# Start Elasticsearch and Kibana
docker-compose up -d

# Wait for services to be ready
./scripts/start_services.sh

# Create index patterns and dashboards
./scripts/create_kibana_data_view.sh
ES_USER=elastic ES_PASSWORD=changeme python3 scripts/create_lens_dashboards_ndjson.py
```

## 📚 Documentation

- [Installation Guide](docs/INSTALLATION.md)
- [Quick Start](docs/QUICKSTART.md)
- [Filtering Configuration](docs/FILTERING_CONFIGURATION.md)
- [Kibana Setup](docs/KIBANA_SETUP.md)
- [Troubleshooting](docs/TROUBLESHOOTING.md)
- [pySigma Sync Tracking](docs/PYSIGMA_SYNC_TRACKING.md)

## 🤝 Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Adding New Rules

1. Create a new `.yml` file in `rules/esf/` or `rules/ul/`
2. Follow the Sigma rule specification
3. Use logsource: `product: macos`, `service: endpointsecurity`
4. Test with `sigma convert -p ecs_macos_esf`
5. Submit a PR

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

## 🙏 Acknowledgments

- [SigmaHQ](https://github.com/SigmaHQ) - Sigma specification and pySigma
- [Elastic](https://www.elastic.co/) - ECS specification
- [Apple](https://developer.apple.com/documentation/endpointsecurity) - Endpoint Security Framework

## 📧 Contact

- **Organization**: [Nebulock Inc.](https://github.com/Nebulock-Inc)
- **Issues**: [GitHub Issues](https://github.com/Nebulock-Inc/macos-coresigma/issues)
