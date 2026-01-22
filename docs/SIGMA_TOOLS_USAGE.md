# Sigma/PySigma Tools Usage in This Codebase

## Overview

This codebase **actively uses** official Sigma and pySigma tools wherever possible. This document confirms our usage and identifies any areas where we could leverage more official tools.

---

## ✅ Currently Using Official Tools

### 1. **Sigma CLI (`sigma` command from `sigmatools`)** ✅

**Location in codebase:**
- `scripts/test_pipeline.sh` - Uses `sigma convert` for rule conversion
- `scripts/convert_all_sigma.sh` - Uses `sigma convert` for batch conversion
- Documentation examples show `sigma convert` usage

**Example usage:**
```bash
sigma convert -t lucene -p pipelines/macos_esf.yml rules/esf/process_execution_suspicious.yml
sigma convert -t eql -p pipelines/macos_esf.yml rules/esf/process_execution_suspicious.yml
```

**Status:** ✅ **Properly used**

---

### 2. **pySigma Library** ✅

**Imports used:**
```python
from sigma.collection import SigmaCollection
from sigma.pipelines.pipeline import ProcessingPipeline
from sigma.backends.elasticsearch import ElasticsearchLuceneBackend
```

**Files using pySigma:**
- `scripts/verify_sigma_alerts.py` - Uses pySigma to load rules and convert to ES queries
- `tests/test_e2e.py` - Uses pySigma for pipeline loading and rule conversion

**Example:**
```python
# Load Sigma rules
sigma_rules = SigmaCollection.from_directory(rules_dir)

# Load pipeline
pipeline = ProcessingPipeline.from_yaml(pipeline_file)

# Convert using backend
backend = ElasticsearchLuceneBackend(processing_pipeline=pipeline)
queries = backend.convert_rule(rule)
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

### 4. **YAML Pipeline Format** ✅

**Using:**
- Native pySigma YAML pipeline support via `ProcessingPipeline.from_yaml()`

**Files:**
- `pipelines/macos_esf.yml` - YAML pipeline
- `pipelines/macos_ul.yml` - YAML pipeline

**Status:** ✅ **Using official pipeline format**

---

## 📋 Dependencies (requirements.txt)

**Official Sigma packages:**
```txt
sigmatools>=0.9.0          # CLI tools (sigma command)
pysigma>=0.9.0             # Python library
pysigma-backend-elasticsearch>=1.0.0  # Official ES backend
```

**Status:** ✅ **All official Sigma packages**

---

## 🔍 Areas to Review

### 1. **Custom Backend Directory**

**Location:** `backends/elasticsearch_esf_ul/__init__.py`

**Question:** Is this a custom backend or using the official one?

**Current status:** Appears to be a placeholder/wrapper. We should verify if we can use the official `pysigma-backend-elasticsearch` directly.

**Recommendation:** 
- If we're just wrapping the official backend → Use official directly
- If we need custom logic → Document why custom implementation is needed

---

### 2. **Rule Validation**

**Current:** Custom `lint_sigma.py` script

**Could use:** 
- `sigma validate` or `sigma check` (if available)
- Official pySigma validation methods

**Current approach:**
```python
# lint_sigma.py attempts to use CLI but falls back to custom validation
subprocess.call(["sigma", "validate", "-r", str(RULES_DIR)])
```

**Status:** ⚠️ **Partially using CLI, has fallback**

**Recommendation:** Enhance to fully use `sigma validate` if available

---

### 3. **Rule Conversion Scripts**

**Current:** Using `sigma convert` CLI ✅

**Files:**
- `scripts/test_pipeline.sh` - Uses `sigma convert`
- `scripts/convert_all_sigma.sh` - Uses `sigma convert`

**Status:** ✅ **Using official CLI**

---

### 4. **Pipeline Loading**

**Current:** Using `ProcessingPipeline.from_yaml()` ✅

**Files:**
- `scripts/verify_sigma_alerts.py` - Uses official API
- `tests/test_e2e.py` - Uses official API

**Status:** ✅ **Using official API**

---

## ✅ Confirmation Checklist

- [x] **Sigma CLI (`sigma convert`)** - Used in test and conversion scripts
- [x] **pySigma Library** - Used for rule loading and conversion
- [x] **Official Backends** - Using `pysigma-backend-elasticsearch`
- [x] **YAML Pipelines** - Using official `ProcessingPipeline.from_yaml()`
- [x] **Sigma Collection** - Using `SigmaCollection.from_directory()`
- [x] **Backend Conversion** - Using official `backend.convert_rule()`
- [x] **Dependencies** - All official packages in requirements.txt

---

## 📊 Usage Statistics

**Official Tools Used:**
- ✅ Sigma CLI (`sigma convert`) - 2 scripts
- ✅ pySigma Library - 2 Python files
- ✅ Official Backends - 1 backend package
- ✅ Pipeline Loading - Official API

**Custom Code:**
- ⚠️ Custom linting (with CLI fallback)
- ⚠️ Custom backend directory (needs review)
- ✅ Custom collectors (necessary - data collection)
- ✅ Custom event normalization (necessary - ESF/UL specific)

---

## 🎯 Recommendations

### 1. **Verify Custom Backend**
Check if `backends/elasticsearch_esf_ul/` is actually needed or if we can use the official backend directly.

### 2. **Enhance Validation**
Ensure `lint_sigma.py` fully leverages `sigma validate` when available.

### 3. **Document Custom Code**
If any custom implementations are necessary (e.g., ESF-specific normalizations), document why official tools can't be used.

### 4. **Use More CLI Tools**
Consider using additional CLI tools if available:
- `sigma validate` - Rule validation
- `sigma check` - Rule checking
- `sigma_uuid` - UUID generation (if we generate rules)

---

## 📚 Official Tools Reference

**Sigma CLI (sigmatools):**
- `sigma convert` - Rule conversion ✅ Used
- `sigma validate` - Rule validation ⚠️ Partially used
- `sigma check` - Rule checking ⚠️ Not used
- `sigma_uuid` - UUID generation ⚠️ Not used

**pySigma Library:**
- `SigmaCollection` - Rule loading ✅ Used
- `ProcessingPipeline` - Pipeline handling ✅ Used
- Backends - Query conversion ✅ Used
- Rule objects - Rule manipulation ✅ Used

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

