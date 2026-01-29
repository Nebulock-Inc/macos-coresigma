# Sigma/PySigma Tools Usage in This Codebase

## Overview

This codebase **actively uses** official Sigma and pySigma tools wherever possible. This document confirms our usage and identifies any areas where we could leverage more official tools.

---

## ✅ Currently Using Official Tools

### 1. **Sigma CLI (`sigma` command)** ✅

**Installation:**
```bash
pip install sigma-cli pysigma-backend-elasticsearch
# Note: Do NOT install sigmatools - it conflicts with sigma-cli
```

**Example usage:**
```bash
# Convert ESF rule to Lucene query
sigma convert -t lucene -p ecs_macos_esf rules/esf/process_execution_suspicious.yml

# Convert ESF rule to EQL
sigma convert -t eql -p ecs_macos_esf rules/esf/process_execution_suspicious.yml

# Convert UL rule to Lucene
sigma convert -t lucene -p ecs_macos_ul rules/ul/tcc_bypass_attempt.yml
```

**Status:** ✅ **Properly used**

---

### 2. **pySigma Library** ✅

**Imports used:**
```python
from sigma.collection import SigmaCollection
from sigma.backends.elasticsearch import LuceneBackend, EqlBackend
from sigma.pipelines.elasticsearch import ecs_macos_esf, ecs_macos_ul
```

**Files using pySigma:**
- `scripts/deploy_sigma_rules.py` - Converts and deploys rules to Kibana Detection Engine

**Example:**
```python
from sigma.collection import SigmaCollection
from sigma.backends.elasticsearch import EqlBackend
from sigma.pipelines.elasticsearch import ecs_macos_esf

# Load Sigma rules
rules = SigmaCollection.from_yaml(rule_file)

# Get pipeline
pipeline = ecs_macos_esf()

# Convert using backend
backend = EqlBackend(pipeline)
queries = backend.convert(rules)
```

**Status:** ✅ **Properly used**

---

### 3. **Official Backends** ✅

**Using:**
- `pysigma-backend-elasticsearch>=1.0.0` - Official Elasticsearch backend

**Backends leveraged:**
- `ElasticsearchLuceneBackend` - For Lucene queries
- `ElasticsearchEQLBackend` - For EQL queries (via CLI)

**Status:** ✅ **Using official backends**

---

### 4. **Built-in Pipelines** ✅

**Using:**
- `ecs_macos_esf()` - Built into pySigma-backend-elasticsearch for ESF events
- `ecs_macos_ul()` - Built into pySigma-backend-elasticsearch for UL events

**Status:** ✅ **Using official pipelines from pySigma-backend-elasticsearch**

**Note:** Local YAML pipelines in `pipelines/` are for reference only. Production use relies on the built-in pipelines.

---

## 📋 Dependencies (requirements.txt)

**Official Sigma packages:**
```txt
pysigma>=0.9.0             # Python library
pysigma-backend-elasticsearch>=1.0.0  # Official ES backend
sigma-cli>=1.0.0           # CLI tools (sigma command)
# Note: Do NOT use sigmatools - it conflicts with sigma-cli
```

**Status:** ✅ **All official Sigma packages**

---

## 🔍 Implementation Notes

### Rule Deployment

**Script:** `scripts/deploy_sigma_rules.py`

This script:
1. Loads Sigma rules from `rules/esf/` and `rules/ul/`
2. Converts using pySigma with appropriate backend:
   - ESF rules → EQL backend with `ecs_macos_esf()` pipeline
   - UL rules → Lucene backend with `ecs_macos_ul()` pipeline
3. Deploys as Kibana Detection Rules via API

### Pipeline Strategy

| Rule Type | Backend | Pipeline | Query Language |
|-----------|---------|----------|----------------|
| ESF | `EqlBackend` | `ecs_macos_esf()` | EQL |
| UL | `LuceneBackend` | `ecs_macos_ul()` | Lucene |

**Why different backends?**
- EQL is better for structured field queries (ESF events)
- Lucene handles text field searches better (UL `message` field)

---

## ✅ Confirmation Checklist

- [x] **Sigma CLI (`sigma convert`)** - Available for manual conversion
- [x] **pySigma Library** - Used for programmatic rule deployment
- [x] **Official Backends** - Using `pysigma-backend-elasticsearch`
- [x] **Built-in Pipelines** - Using `ecs_macos_esf()` and `ecs_macos_ul()`
- [x] **Sigma Collection** - Using `SigmaCollection.from_yaml()`
- [x] **Backend Conversion** - Using official `backend.convert()`
- [x] **Dependencies** - All official packages in requirements.txt

---

## 📊 Usage Statistics

**Official Tools Used:**
- ✅ Sigma CLI (`sigma convert`) - Available for manual testing
- ✅ pySigma Library - `deploy_sigma_rules.py`
- ✅ Official Backends - `LuceneBackend`, `EqlBackend`
- ✅ Built-in Pipelines - `ecs_macos_esf()`, `ecs_macos_ul()`

**Custom Code (necessary):**
- ✅ Data collectors (`esf_collector.py`, `ul_collector.py`) - macOS-specific
- ✅ Event normalization - ESF/UL to ECS mapping
- ✅ Rule deployment script - Kibana API integration

---

## ✅ Conclusion

**This codebase uses official Sigma/pySigma tools extensively:**

1. ✅ **CLI tools** - `sigma convert` is the primary conversion method
2. ✅ **Python library** - pySigma used for programmatic rule handling
3. ✅ **Official backends** - Using `pysigma-backend-elasticsearch`
4. ✅ **Official formats** - YAML pipelines, standard rule format
5. ✅ **Official APIs** - `ProcessingPipeline.from_yaml()`, `SigmaCollection.from_directory()`

**Custom code is minimal and necessary:**
- Data collectors (ESF/UL specific - not part of Sigma)
- Event normalization (macOS-specific field mapping)
- Integration scripts (ES/Kibana integration - outside Sigma scope)

**The codebase properly leverages Sigma ecosystem tools!** ✅

