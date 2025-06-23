# SecScan - Multi-Language Dependency Vulnerability Scanner

A fast, reliable CLI tool that automatically detects and scans dependencies for vulnerabilities in JavaScript, Python, and Go projects using the OSV.dev API.

## Features

- 🔍 **Auto-detection** of project language from manifest files
- 📦 **Multi-language support**: JavaScript (npm), Python (pip), Go modules
- 🛡️ **OSV.dev API** integration for comprehensive vulnerability data
- 📊 **Unified output format** across all languages
- 🔧 **Language-specific fix commands** for easy remediation
- 📄 **Multiple output formats**: Human-readable text or JSON

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/secscan.git
cd secscan

# Install dependencies
pip install requests
```

## Usage

### Basic scan (current directory)
```bash
python secscan.py
```

### Scan specific directory
```bash
python secscan.py /path/to/project
```

### JSON output
```bash
python secscan.py -f json
```

### Command-line options
```
usage: secscan.py [-h] [-f {text,json}] [-v] [path]

SecScan - Multi-language dependency vulnerability scanner

positional arguments:
  path                  Path to project directory (default: current directory)

options:
  -h, --help            show this help message and exit
  -f {text,json}, --format {text,json}
                        Output format (default: text)
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

## How It Works

1. **Language Detection**: SecScan examines the project directory for manifest files to determine the project language
2. **Dependency Parsing**: Extracts dependency information from the appropriate manifest file
3. **Vulnerability Checking**: Queries the OSV.dev API for each dependency to find known vulnerabilities
4. **Result Formatting**: Presents findings in either human-readable text or JSON format with fix commands

## Requirements

- Python 3.6+
- `requests` library
- Internet connection (for OSV.dev API access)

## License

MIT License

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.