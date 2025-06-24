# SecScan - Multi-Language Dependency Vulnerability Scanner

[![Python 3.7+](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PyPI version](https://badge.fury.io/py/secscan-cli.svg)](https://badge.fury.io/py/secscan-cli)

A fast, reliable CLI tool that automatically detects and scans dependencies for vulnerabilities in JavaScript, Python, and Go projects using the OSV.dev API.

## Features

### Core Features
- 🔍 **Auto-detection** of project language from manifest files
- 📦 **Multi-language support**: JavaScript (npm), Python (pip), Go modules
- 🛡️ **OSV.dev API** integration for comprehensive vulnerability data
- 📊 **Multiple output formats**: Text, JSON, CSV, Markdown, SARIF
- 🔧 **Language-specific fix commands** for easy remediation

### Advanced Features
- 🎯 **Severity Filtering**: Filter by severity levels or CVSS scores
- 💣 **Exploit Detection**: Identify vulnerabilities with known exploits
- 🚀 **CI/CD Integration**: Smart exit codes and minimal output mode
- 📋 **Policy Enforcement**: Define complex vulnerability policies
- 📊 **Statistics**: Detailed scan metrics with visual charts
- ⚙️ **Configuration Files**: YAML/JSON config with ignore rules
- 🎛️ **Threshold Limits**: Set maximum allowed vulnerabilities
- 💾 **Intelligent Caching**: Multi-level cache for fast repeated scans
- 📡 **Offline Mode**: Work without network using cached data

## Installation

### From PyPI (recommended)

```bash
pip install secscan-cli
```

### From source

```bash
# Clone the repository
git clone https://github.com/deosha/secscan.git
cd secscan

# Install in development mode
pip install -e .
```

## Quick Start

### Basic scan (current directory)
```bash
secscan
```

### Scan specific directory
```bash
secscan /path/to/project
```

### JSON output
```bash
secscan -f json
```

### Common Use Cases

```bash
# CI/CD pipeline - fail on high severity
secscan --ci --fail-on high

# Security audit - show only critical issues with exploits
secscan --severity critical --exploitable

# Development - show fixable vulnerabilities
secscan --has-fix --min-severity medium

# Compliance - enforce policy
secscan --policy "critical=0,high=0" --stats
```

### Command-line options
```
usage: secscan [-h] [-f {text,json,table,csv,markdown,sarif}] [-o OUTPUT]
               [--min-severity {low,medium,high,critical}]
               [--severity SEVERITY] [--cvss-min CVSS_MIN]
               [--exploitable] [--has-fix]
               [--fail-on {none,low,medium,high,critical,any}]
               [--strict] [--ci] [--max-critical MAX_CRITICAL]
               [--max-high MAX_HIGH] [--max-total MAX_TOTAL]
               [--policy POLICY] [--policy-file POLICY_FILE]
               [--stats] [--no-config] [--verbose] [--no-color]
               [--cache-dir PATH] [--cache-ttl SECONDS] [--refresh-cache]
               [--clear-cache] [--cache-stats] [--no-cache] [--offline]
               [-v] [path]

SecScan - Multi-language dependency vulnerability scanner

positional arguments:
  path                  Path to project directory (default: current directory)

options:
  -h, --help            show this help message and exit
  -f {text,json,table,csv,markdown,sarif}, --format {text,json,table,csv,markdown,sarif}
                        Output format
  -o OUTPUT, --output OUTPUT
                        Output file (default: stdout)
  --min-severity {low,medium,high,critical}
                        Minimum severity to report
  --severity SEVERITY   Show only specific severities (comma-separated: critical,high)
  --cvss-min CVSS_MIN   Filter by minimum CVSS score
  --exploitable         Only show vulnerabilities with known exploits
  --has-fix             Only show vulnerabilities with available fixes
  --fail-on {none,low,medium,high,critical,any}
                        Exit with non-zero code if vulnerabilities at or above this level are found
  --strict              Fail on ANY vulnerability regardless of severity
  --ci                  CI-friendly output mode
  --max-critical MAX_CRITICAL
                        Maximum number of critical vulnerabilities allowed
  --max-high MAX_HIGH   Maximum number of high vulnerabilities allowed
  --max-total MAX_TOTAL Maximum total number of vulnerabilities allowed
  --policy POLICY       Policy string (e.g., 'critical=0,high<=3,medium<=10')
  --policy-file POLICY_FILE
                        Path to policy JSON file
  --stats               Show detailed statistics
  --no-config           Ignore configuration files
  --verbose             Verbose output
  --no-color            Disable colored output
  --cache-dir PATH      Override default cache directory (~/.secscan/cache)
  --cache-ttl SECONDS   Override cache TTL (default: 86400s/24h)
  --refresh-cache       Force refresh cache, ignoring TTL
  --clear-cache         Clear all cached data
  --cache-stats         Show cache statistics
  --no-cache            Disable caching for this run
  --offline             Use only cached data, no network calls
  -v, --version         show program's version number and exit
```

## Supported Languages and Files

### JavaScript
- `package.json` - Standard npm package manifest
- `package-lock.json` - npm lock file (v1 and v2/v3 formats)
- `yarn.lock` - Yarn lock file

### Python
- `requirements.txt` - Standard pip requirements (including pip freeze format)
- `Pipfile` - Pipenv manifest
- `Pipfile.lock` - Pipenv lock file
- `pyproject.toml` - Modern Python project file (detection only)
- `setup.py` - Setup tools configuration (detection only)

### Go
- `go.mod` - Go modules file (excludes indirect dependencies)
- `go.sum` - Go checksums file (includes all dependencies)

## Output Example

### Text Format
```
🔍 Security Scan Results for /path/to/project
📦 Language: javascript
📊 Total Dependencies: 42
⚠️  Vulnerable Dependencies: 3

❌ Vulnerabilities Found:

🔴 CRITICAL (1)
  - lodash@4.17.15
    CVE-2021-23337: Command injection in lodash
    Fixed in: 4.17.21
    Fix: npm install lodash@4.17.21

🟠 HIGH (2)
  - axios@0.21.0
    CVE-2021-3749: Denial of Service in axios
    Fixed in: 0.21.2
    Fix: npm install axios@0.21.2
```

### JSON Format
```json
{
  "project_path": "/path/to/project",
  "language": "javascript",
  "summary": {
    "total_dependencies": 42,
    "vulnerable_dependencies": 3
  },
  "vulnerabilities": [
    {
      "dependency": {
        "name": "lodash",
        "version": "4.17.15"
      },
      "vulnerabilities": [
        {
          "id": "CVE-2021-23337",
          "severity": "CRITICAL",
          "summary": "Command injection in lodash",
          "fixed_versions": ["4.17.21"]
        }
      ],
      "fix_command": "npm install lodash@4.17.21"
    }
  ]
}
```

## Advanced Usage

### CI/CD Integration

SecScan is designed for seamless CI/CD integration with smart exit codes:

```bash
# Fail if any HIGH or CRITICAL vulnerabilities found
secscan --ci --fail-on high

# Strict mode - fail on ANY vulnerability
secscan --ci --strict

# Set specific thresholds
secscan --ci --max-critical 0 --max-high 3 --max-total 10
```

Exit codes:
- `0`: No vulnerabilities OR below fail threshold
- `1`: Vulnerabilities at or above fail threshold
- `2`: Scan error

### Filtering Vulnerabilities

```bash
# Show only specific severities
secscan --severity critical,high

# Filter by CVSS score
secscan --cvss-min 7.0

# Show only exploitable vulnerabilities
secscan --exploitable

# Show only vulnerabilities with fixes available
secscan --has-fix

# Combine multiple filters
secscan --has-fix --cvss-min 7.0 --severity critical,high
```

### Policy Enforcement

Define complex vulnerability policies:

```bash
# Inline policy
secscan --policy "critical=0,high<=3,medium<=10"

# Policy file
secscan --policy-file .secscan-policy.json
```

Example policy file:
```json
{
  "rules": {
    "max_critical": 0,
    "max_high": 3,
    "max_cvss_score": 8.0,
    "require_fixes_for": ["critical", "high"],
    "max_age_days": {
      "critical": 7,
      "high": 30
    }
  }
}
```

### Configuration Files

SecScan supports configuration files for persistent settings:

```bash
# Create example configuration
secscan config init

# Validate configuration
secscan config validate

# Show merged configuration
secscan config show
```

Configuration files (`.secscan.yml` or `secscan.config.json`) support:
- Ignore rules for vulnerabilities, packages, and paths
- Severity filtering and scan settings
- Output preferences
- CI/CD configuration

### Statistics and Reporting

```bash
# Show detailed statistics
secscan --stats

# Save results to file
secscan -o results.json -f json

# Generate different formats
secscan -f markdown > report.md
```

### Caching System

SecScan includes an intelligent caching system that significantly improves performance for repeated scans:

```bash
# View cache statistics
secscan --cache-stats

# Clear all cache
secscan --clear-cache

# Force refresh cache (ignore TTL)
secscan /path/to/project --refresh-cache

# Offline mode - use only cached data
secscan /path/to/project --offline

# Custom cache settings
secscan --cache-dir /custom/cache/path --cache-ttl 3600

# Disable caching for current run
secscan /path/to/project --no-cache
```

**Cache Features:**
- **Multi-level structure**: Vulnerability database, scan results, and package metadata
- **Smart invalidation**: Automatically detects manifest changes
- **Offline support**: Work without network access using cached data
- **Performance boost**: 10x+ faster on cached scans
- **TTL-based expiration**: Configurable time-to-live for cache entries
- **Integrity checks**: SHA256 checksums prevent corrupted cache

## How It Works

1. **Language Detection**: SecScan examines the project directory for manifest files to determine the project language
2. **Dependency Parsing**: Extracts dependency information from the appropriate manifest file
3. **Vulnerability Checking**: Queries the OSV.dev API for each dependency to find known vulnerabilities
4. **Filtering**: Applies severity, CVSS, exploit, and fix filters based on options
5. **Policy Checking**: Validates results against defined policies and thresholds
6. **Result Formatting**: Presents findings in the requested format with fix commands

## Requirements

- Python 3.7+
- `requests` library
- `pyyaml` library (for configuration files)
- Internet connection (for OSV.dev API access)

## License

MIT License

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.