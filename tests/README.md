# SecScan Test Suite

Comprehensive test suite for the SecScan multi-language vulnerability scanner.

## Test Structure

```
tests/
├── conftest.py           # Shared fixtures and utilities
├── test_cli.py          # CLI command and argument tests
├── test_scanner.py      # Core scanning logic tests
├── test_parsers.py      # Manifest file parser tests
├── test_integration.py  # Real-world integration tests
├── run_all_tests.sh     # Bash script to run all tests
└── validate_tests.py    # Test validation and coverage analysis
```

## Running Tests

### Run all tests
```bash
pytest

# Or use the comprehensive test runner
./tests/run_all_tests.sh
```

### Run specific test modules
```bash
pytest tests/test_cli.py -v
pytest tests/test_scanner.py -v
pytest tests/test_parsers.py -v
pytest tests/test_integration.py -v
```

### Run with coverage
```bash
pip install pytest-cov
pytest --cov=secscan --cov-report=html
```

### Run performance tests only
```bash
pytest tests/test_integration.py::TestPerformanceBenchmarks -v
```

### Validate test suite
```bash
python tests/validate_tests.py
```

## Test Categories

### CLI Tests (`test_cli.py`)
- Help and version commands
- Directory scanning (current, specific, non-existent)
- Output formats (text, JSON)
- Error handling (corrupted files, permissions)
- Concurrent scanning

### Scanner Tests (`test_scanner.py`)
- Language detection (JavaScript, Python, Go)
- OSV API client functionality
- Vulnerability severity mapping
- Scan result formatting
- Caching behavior

### Parser Tests (`test_parsers.py`)
- **JavaScript**: package.json, package-lock.json, yarn.lock
- **Python**: requirements.txt, Pipfile, Pipfile.lock
- **Go**: go.mod, go.sum
- Edge cases and malformed files

### Integration Tests (`test_integration.py`)
- Real vulnerable projects
- Performance benchmarks
- CI/CD scenarios
- Memory usage
- Error recovery

## Demo Projects

The test suite includes vulnerable demo projects in `demo/vulnerable_projects/`:

- **javascript/**: Contains vulnerable lodash@4.17.20 and axios@0.21.0
- **python/**: Contains vulnerable django==2.2.0 and flask==0.12.2
- **go/**: Contains vulnerable jwt-go@v3.2.0
- **mixed/**: Contains both package.json and requirements.txt
- **empty/**: Empty directory for testing
- **corrupted/**: Contains malformed manifest files

## Running the Demo

```bash
python demo/demo_script.py
```

This will:
1. Scan all three language projects
2. Demonstrate different output formats
3. Show edge case handling
4. Generate an HTML vulnerability report

## Test Requirements

```bash
pip install pytest requests

# Optional for enhanced testing
pip install pytest-cov pytest-timeout psutil
```

## Writing New Tests

1. Add test functions to appropriate test modules
2. Use fixtures from `conftest.py` for common setup
3. Follow naming convention: `test_description_of_test`
4. Include docstrings explaining what is tested
5. Add appropriate markers (@pytest.mark.slow, etc.)

Example:
```python
def test_new_feature(temp_dir, mock_osv_response):
    """Test that new feature works correctly"""
    # Setup
    create_test_file(temp_dir)
    
    # Execute
    result = run_scan(temp_dir)
    
    # Assert
    assert "expected" in result
```

## Continuous Integration

The test suite is designed to work in CI/CD pipelines:

```yaml
# Example GitHub Actions
- name: Run tests
  run: |
    pip install -r requirements.txt
    pip install pytest
    ./tests/run_all_tests.sh
```

## Troubleshooting

### Tests failing due to API rate limits
The tests use mocked API responses by default. If you see rate limit errors, ensure the mocks are properly configured.

### Permission errors on Windows
Some tests check file permissions which may behave differently on Windows. These tests are skipped on Windows platforms.

### Slow tests
Use `-m "not slow"` to skip slow tests during development:
```bash
pytest -m "not slow"
```