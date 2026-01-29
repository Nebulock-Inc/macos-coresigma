# Contributing to macOS Sigma Pipelines

Thank you for your interest in contributing! This document provides guidelines for contributing to the macOS Sigma Pipelines project.

## Project Structure

```
macos-sigma-pipelines-new/
├── pipelines/              # Sigma pipeline configurations
├── backends/               # Custom pySigma backends
├── collectors/            # Data collection scripts
├── rules/                 # Sigma detection rules
├── tests/                 # Test suite
└── docs/                  # Documentation
```

## How to Contribute

### Reporting Issues

1. Check if the issue already exists
2. Create a new issue with:
   - Clear description of the problem
   - Steps to reproduce
   - Expected vs actual behavior
   - System information (macOS version, Python version)

### Contributing Code

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes
4. Add tests if applicable
5. Ensure all tests pass: `python3 tests/test_e2e.py`
6. Commit with clear messages
7. Push and create a pull request

### Adding New Rules

1. Follow the Sigma rule format
2. Use appropriate field names from the pipeline mappings
3. Include proper logsource definitions
4. Add false positive notes
5. Tag with relevant MITRE ATT&CK techniques

### Improving Pipelines

1. Test field mappings thoroughly
2. Ensure compatibility with existing rules
3. Document new fields and mappings
4. Update test suite

## Code Style

- Python: Follow PEP 8
- YAML: Use 2-space indentation
- Comments: Explain complex logic
- Docstrings: Use for all functions/classes

## Testing

Run tests before submitting:

```bash
python3 tests/test_e2e.py
./scripts/test_pipeline.sh
```

## Questions?

Open an issue or discussion for questions about:
- Field mappings
- Pipeline structure
- Rule creation
- Backend implementation

