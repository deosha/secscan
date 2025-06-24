# Changelog

All notable changes to SecScan will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.4.0] - 2024-01-25

### Added
- **Intelligent Caching System**
  - Multi-level cache structure at ~/.secscan/cache/
    - `vulndb/` for vulnerability database caching
    - `scans/` for previous scan results by project hash
    - `packages/` for package metadata caching
  - Cache management commands:
    - `--cache-dir` to override default cache location
    - `--cache-ttl` to set custom TTL (default: 86400s/24h)
    - `--refresh-cache` to force refresh ignoring TTL
    - `--clear-cache` to remove all cached data
    - `--cache-stats` to show cache size and age statistics
    - `--no-cache` to disable caching for current run
  - `--offline` mode for air-gapped environments
  - Smart caching strategies:
    - SHA256 hashing for cache keys and integrity verification
    - Automatic manifest change detection and cache invalidation
    - TTL-based expiration (24h default, 6h for vulnerability database)
  - Performance optimizations:
    - Batch API requests with parallel processing
    - ThreadPoolExecutor for concurrent API calls
    - 10x+ performance improvement on cached scans

### Enhanced
- Significant performance improvements for repeated scans
- Demo script updated with caching demonstrations
- Documentation updated with caching examples

### Fixed
- Improved API response handling for batch requests

## [1.3.0] - 2024-01-24

### Added
- **Advanced Severity Filtering**
  - `--severity` flag for filtering specific severity levels (comma-separated)
  - `--cvss-min` flag for filtering by minimum CVSS score
  - `--exploitable` flag to show only vulnerabilities with known exploits
  - `--has-fix` flag to show only vulnerabilities with available fixes

- **CI/CD Integration Features**
  - `--ci` flag for minimal, machine-readable output
  - `--fail-on` option with levels: none, low, medium, high, critical, any
  - `--strict` mode to fail on any vulnerability
  - Smart exit codes: 0 (success), 1 (vulnerabilities found), 2 (scan error)
  - Timing information in CI mode

- **Policy Enforcement**
  - `--policy` flag for inline policy strings (e.g., "critical=0,high<=3")
  - `--policy-file` flag for complex JSON policy files
  - Support for max vulnerability counts by severity
  - Age-based vulnerability rules
  - Fix requirement rules
  - Exploitability restrictions

- **Threshold Configuration**
  - `--max-critical` flag to set maximum critical vulnerabilities
  - `--max-high` flag to set maximum high vulnerabilities
  - `--max-total` flag to set maximum total vulnerabilities
  - Violations reported with verbose output

- **Statistics and Reporting**
  - `--stats` flag for detailed scan statistics
  - Visual severity breakdown with bar charts
  - Scan duration timing
  - Fixable vulnerability percentage
  - Exploitable vulnerability count

- **Configuration System**
  - YAML and JSON configuration file support
  - Config commands: `config init`, `config validate`, `config show`
  - Global (~/.secscan/config.yml) and project-level configs
  - Ignore rules for vulnerabilities, packages, and paths
  - Expiration dates for ignore rules
  - CLI arguments override configuration values

### Enhanced
- Vulnerability data now includes CVSS scores and vectors
- Exploit detection from OSV.dev references
- Published date tracking for vulnerabilities
- Demo script updated with advanced feature demonstrations

### Fixed
- Improved error handling for malformed manifests
- Better CVSS score parsing from various formats

## [1.2.0] - 2024-01-20

### Added
- Support for additional manifest formats:
  - JavaScript: package-lock.json (v1 and v2/v3), yarn.lock
  - Python: Pipfile.lock, requirements.txt with pip freeze format
  - Go: go.sum
- Enhanced manifest parsing with version extraction
- Graceful error handling for corrupted JSON files

### Fixed
- TypeError when comparing string vs float CVSS scores
- HTML template curly brace escaping issues
- JSON parsing errors in corrupted manifests

## [1.1.0] - 2024-01-15

### Added
- Multi-language support (JavaScript, Python, Go)
- OSV.dev API integration
- Multiple output formats (text, JSON)
- Language-specific fix commands
- Automatic language detection
- Demo script for testing

### Changed
- Improved error messages
- Enhanced output formatting

## [1.0.0] - 2024-01-10

### Added
- Initial release
- Basic vulnerability scanning
- JavaScript/npm support
- Text output format
- Command-line interface