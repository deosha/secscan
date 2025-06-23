#!/usr/bin/env python3
"""
SecScan - A multi-language dependency vulnerability scanner
Supports JavaScript (npm), Python (pip), and Go modules
"""

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional, Tuple
import requests
from dataclasses import dataclass
from enum import Enum
import re


class Language(Enum):
    JAVASCRIPT = "javascript"
    PYTHON = "python"
    GO = "go"
    UNKNOWN = "unknown"


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


@dataclass
class Vulnerability:
    """Represents a vulnerability found in a dependency"""
    id: str
    summary: str
    details: str
    severity: Severity
    affected_versions: List[str]
    fixed_versions: List[str]
    references: List[str]


@dataclass
class Dependency:
    """Represents a project dependency"""
    name: str
    version: str
    language: Language
    vulnerabilities: List[Vulnerability] = None

    def __post_init__(self):
        if self.vulnerabilities is None:
            self.vulnerabilities = []


@dataclass
class ScanResult:
    """Result of scanning a project"""
    project_path: str
    language: Language
    dependencies: List[Dependency]
    vulnerable_count: int
    total_count: int


class LanguageDetector:
    """Detects project language from manifest files"""
    
    MANIFEST_FILES = {
        Language.JAVASCRIPT: ["package.json", "package-lock.json", "yarn.lock"],
        Language.PYTHON: ["requirements.txt", "Pipfile.lock", "Pipfile", "pyproject.toml", "setup.py"],
        Language.GO: ["go.mod", "go.sum"]
    }
    
    @staticmethod
    def detect(path: Path) -> Tuple[Language, Optional[Path]]:
        """Detect language and return manifest file path"""
        for language, manifests in LanguageDetector.MANIFEST_FILES.items():
            for manifest in manifests:
                manifest_path = path / manifest
                if manifest_path.exists():
                    return language, manifest_path
        return Language.UNKNOWN, None


class DependencyParser:
    """Base class for dependency parsers"""
    
    @staticmethod
    def parse_javascript(manifest_path: Path) -> List[Dependency]:
        """Parse JavaScript dependencies based on file type"""
        if manifest_path.name == 'package.json':
            return DependencyParser._parse_package_json(manifest_path)
        elif manifest_path.name == 'package-lock.json':
            return DependencyParser._parse_package_lock_json(manifest_path)
        elif manifest_path.name == 'yarn.lock':
            return DependencyParser._parse_yarn_lock(manifest_path)
        return []
    
    @staticmethod
    def _parse_package_json(manifest_path: Path) -> List[Dependency]:
        """Parse JavaScript dependencies from package.json"""
        dependencies = []
        
        try:
            with open(manifest_path, 'r') as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            print(f"Warning: Invalid JSON in {manifest_path}: {e}", file=sys.stderr)
            return dependencies
        except Exception as e:
            print(f"Warning: Error reading {manifest_path}: {e}", file=sys.stderr)
            return dependencies
        
        # Combine dependencies and devDependencies
        all_deps = {}
        if isinstance(data, dict):
            if 'dependencies' in data and isinstance(data['dependencies'], dict):
                all_deps.update(data['dependencies'])
            if 'devDependencies' in data and isinstance(data['devDependencies'], dict):
                all_deps.update(data['devDependencies'])
        
        for name, version in all_deps.items():
            if isinstance(version, str):
                # Clean version string (remove ^, ~, etc.)
                clean_version = re.sub(r'^[\^~>=<]+', '', version)
                dependencies.append(Dependency(name, clean_version, Language.JAVASCRIPT))
        
        return dependencies
    
    @staticmethod
    def _parse_package_lock_json(manifest_path: Path) -> List[Dependency]:
        """Parse JavaScript dependencies from package-lock.json"""
        dependencies = []
        seen = set()
        
        try:
            with open(manifest_path, 'r') as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            print(f"Warning: Invalid JSON in {manifest_path}: {e}", file=sys.stderr)
            return dependencies
        except Exception as e:
            print(f"Warning: Error reading {manifest_path}: {e}", file=sys.stderr)
            return dependencies
        
        if not isinstance(data, dict):
            return dependencies
        
        # Handle v2/v3 format
        if 'packages' in data and isinstance(data['packages'], dict):
            for pkg_path, pkg_info in data['packages'].items():
                if pkg_path and 'node_modules/' in pkg_path and isinstance(pkg_info, dict):
                    name = pkg_path.split('node_modules/')[-1]
                    version = pkg_info.get('version', 'unknown')
                    if name not in seen:
                        seen.add(name)
                        dependencies.append(Dependency(name, version, Language.JAVASCRIPT))
        
        # Handle v1 format
        elif 'dependencies' in data and isinstance(data['dependencies'], dict):
            for name, info in data['dependencies'].items():
                if isinstance(info, dict):
                    version = info.get('version', 'unknown')
                    if name not in seen:
                        seen.add(name)
                        dependencies.append(Dependency(name, version, Language.JAVASCRIPT))
        
        return dependencies
    
    @staticmethod
    def _parse_yarn_lock(manifest_path: Path) -> List[Dependency]:
        """Parse JavaScript dependencies from yarn.lock"""
        dependencies = []
        seen = set()
        
        with open(manifest_path, 'r') as f:
            content = f.read()
        
        # Parse yarn.lock format
        current_packages = []
        current_version = None
        
        for line in content.split('\n'):
            line = line.rstrip()
            
            # Package declaration line
            if line and not line.startswith(' ') and not line.startswith('#'):
                # Reset for new package
                if current_packages and current_version:
                    for pkg in current_packages:
                        # Extract package name without version spec
                        pkg_name = re.sub(r'@[\^~>=<*\d].*$', '', pkg.strip('"'))
                        if pkg_name not in seen:
                            seen.add(pkg_name)
                            dependencies.append(Dependency(pkg_name, current_version, Language.JAVASCRIPT))
                
                current_packages = [p.strip() for p in line.rstrip(':').split(',')]
                current_version = None
            
            # Version line
            elif line.strip().startswith('version'):
                match = re.search(r'version\s+"([^"]+)"', line)
                if match:
                    current_version = match.group(1)
        
        # Handle last package
        if current_packages and current_version:
            for pkg in current_packages:
                pkg_name = re.sub(r'@[\^~>=<*\d].*$', '', pkg.strip('"'))
                if pkg_name not in seen:
                    seen.add(pkg_name)
                    dependencies.append(Dependency(pkg_name, current_version, Language.JAVASCRIPT))
        
        return dependencies
    
    @staticmethod
    def parse_python(manifest_path: Path) -> List[Dependency]:
        """Parse Python dependencies based on file type"""
        if manifest_path.name == 'requirements.txt':
            return DependencyParser._parse_requirements_txt(manifest_path)
        elif manifest_path.name == 'Pipfile.lock':
            return DependencyParser._parse_pipfile_lock(manifest_path)
        elif manifest_path.name == 'Pipfile':
            return DependencyParser._parse_pipfile(manifest_path)
        elif manifest_path.name in ['pyproject.toml', 'setup.py']:
            # For now, return empty list for these formats
            # Could be extended in the future
            return []
        return []
    
    @staticmethod
    def _parse_requirements_txt(manifest_path: Path) -> List[Dependency]:
        """Parse Python dependencies from requirements.txt (supports pip freeze format)"""
        dependencies = []
        
        with open(manifest_path, 'r') as f:
            lines = f.readlines()
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#') or line.startswith('-'):
                continue
            
            # Handle various requirement formats
            # package==1.0.0 (pip freeze format)
            # package>=1.0.0
            # package~=1.0.0
            # package
            # git+https://... (skip these)
            
            if line.startswith('git+') or line.startswith('http'):
                continue
            
            # Parse package name and version
            match = re.match(r'^([a-zA-Z0-9\-_.]+)\s*([><=~!]=*)\s*([0-9.]+.*)?', line)
            if match:
                name = match.group(1)
                version = match.group(3) if match.group(3) else "unknown"
                dependencies.append(Dependency(name, version, Language.PYTHON))
            else:
                # Package without version
                pkg_name = re.split(r'[><=~!\s]', line)[0]
                if pkg_name:
                    dependencies.append(Dependency(pkg_name, "unknown", Language.PYTHON))
        
        return dependencies
    
    @staticmethod
    def _parse_pipfile_lock(manifest_path: Path) -> List[Dependency]:
        """Parse Python dependencies from Pipfile.lock"""
        dependencies = []
        
        try:
            with open(manifest_path, 'r') as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            print(f"Warning: Invalid JSON in {manifest_path}: {e}", file=sys.stderr)
            return dependencies
        except Exception as e:
            print(f"Warning: Error reading {manifest_path}: {e}", file=sys.stderr)
            return dependencies
        
        if not isinstance(data, dict):
            return dependencies
        
        # Parse default and develop dependencies
        for section in ['default', 'develop']:
            if section in data and isinstance(data[section], dict):
                for name, info in data[section].items():
                    if isinstance(info, dict):
                        version = info.get('version', '').lstrip('==')
                        if not version and 'ref' in info:
                            version = info['ref'][:7]  # Git commit hash
                    else:
                        version = info.lstrip('==') if isinstance(info, str) else "unknown"
                    
                    if version:
                        dependencies.append(Dependency(name, version, Language.PYTHON))
        
        return dependencies
    
    @staticmethod
    def _parse_pipfile(manifest_path: Path) -> List[Dependency]:
        """Parse Python dependencies from Pipfile"""
        dependencies = []
        
        try:
            import toml
        except ImportError:
            # If toml is not available, return empty list
            return dependencies
        
        with open(manifest_path, 'r') as f:
            data = toml.load(f)
        
        # Parse packages and dev-packages
        for section in ['packages', 'dev-packages']:
            if section in data:
                for name, version_spec in data[section].items():
                    if isinstance(version_spec, str):
                        # Clean version string
                        version = re.sub(r'^[><=~*]+', '', version_spec)
                        if not version:
                            version = "unknown"
                    elif isinstance(version_spec, dict):
                        version = version_spec.get('version', 'unknown').lstrip('==')
                    else:
                        version = "unknown"
                    
                    dependencies.append(Dependency(name, version, Language.PYTHON))
        
        return dependencies
    
    @staticmethod
    def parse_go(manifest_path: Path) -> List[Dependency]:
        """Parse Go dependencies based on file type"""
        if manifest_path.name == 'go.mod':
            return DependencyParser._parse_go_mod(manifest_path)
        elif manifest_path.name == 'go.sum':
            return DependencyParser._parse_go_sum(manifest_path)
        return []
    
    @staticmethod
    def _parse_go_mod(manifest_path: Path) -> List[Dependency]:
        """Parse Go dependencies from go.mod"""
        dependencies = []
        
        with open(manifest_path, 'r') as f:
            lines = f.readlines()
        
        in_require = False
        for line in lines:
            line = line.strip()
            
            if line.startswith('require ('):
                in_require = True
                continue
            elif line == ')':
                in_require = False
                continue
            
            if in_require or line.startswith('require '):
                # Parse module path and version
                parts = line.replace('require ', '').split()
                if len(parts) >= 2:
                    name = parts[0]
                    version = parts[1].strip('v')
                    # Handle indirect dependencies marked with // indirect
                    if '// indirect' not in line:
                        dependencies.append(Dependency(name, version, Language.GO))
        
        return dependencies
    
    @staticmethod
    def _parse_go_sum(manifest_path: Path) -> List[Dependency]:
        """Parse Go dependencies from go.sum"""
        dependencies = []
        seen = set()
        
        with open(manifest_path, 'r') as f:
            lines = f.readlines()
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            # go.sum format: module version hash
            # Skip lines with /go.mod suffix (module metadata)
            if '/go.mod' in line:
                continue
            
            parts = line.split()
            if len(parts) >= 2:
                module = parts[0]
                version = parts[1].strip('v')
                
                # Create unique key to avoid duplicates
                key = f"{module}@{version}"
                if key not in seen:
                    seen.add(key)
                    dependencies.append(Dependency(module, version, Language.GO))
        
        return dependencies


class OSVClient:
    """Client for OSV.dev API"""
    
    BASE_URL = "https://api.osv.dev/v1"
    
    @staticmethod
    def check_vulnerability(dependency: Dependency) -> List[Vulnerability]:
        """Check a dependency for vulnerabilities using OSV API"""
        ecosystem = {
            Language.JAVASCRIPT: "npm",
            Language.PYTHON: "PyPI",
            Language.GO: "Go"
        }.get(dependency.language)
        
        if not ecosystem:
            return []
        
        # Query OSV API
        query = {
            "package": {
                "name": dependency.name,
                "ecosystem": ecosystem
            },
            "version": dependency.version
        }
        
        try:
            response = requests.post(
                f"{OSVClient.BASE_URL}/query",
                json=query,
                timeout=10
            )
            response.raise_for_status()
            data = response.json()
            
            vulnerabilities = []
            for vuln in data.get('vulns', []):
                # Extract severity
                severity = Severity.UNKNOWN
                if 'severity' in vuln:
                    for sev in vuln['severity']:
                        if sev['type'] == 'CVSS_V3':
                            # Handle both numeric scores and CVSS vectors
                            score_value = sev.get('score', 0)
                            if isinstance(score_value, str):
                                # Extract score from CVSS vector if present
                                if score_value.startswith('CVSS:'):
                                    # Default to MEDIUM if we can't parse
                                    severity = Severity.MEDIUM
                                else:
                                    try:
                                        score = float(score_value)
                                    except ValueError:
                                        score = 5.0  # Default to medium
                            else:
                                score = float(score_value)
                            
                            # Only apply scoring if we have a numeric score
                            if not isinstance(score_value, str) or not score_value.startswith('CVSS:'):
                                if score >= 9.0:
                                    severity = Severity.CRITICAL
                                elif score >= 7.0:
                                    severity = Severity.HIGH
                                elif score >= 4.0:
                                    severity = Severity.MEDIUM
                                else:
                                    severity = Severity.LOW
                            break
                
                # Extract affected and fixed versions
                affected_versions = []
                fixed_versions = []
                
                for affected in vuln.get('affected', []):
                    if affected['package']['name'] == dependency.name:
                        for range_info in affected.get('ranges', []):
                            for event in range_info.get('events', []):
                                if 'introduced' in event:
                                    affected_versions.append(event['introduced'])
                                if 'fixed' in event:
                                    fixed_versions.append(event['fixed'])
                
                vulnerability = Vulnerability(
                    id=vuln.get('id', 'Unknown'),
                    summary=vuln.get('summary', 'No summary available'),
                    details=vuln.get('details', 'No details available'),
                    severity=severity,
                    affected_versions=affected_versions,
                    fixed_versions=fixed_versions,
                    references=[ref.get('url', '') for ref in vuln.get('references', [])]
                )
                vulnerabilities.append(vulnerability)
            
            return vulnerabilities
            
        except requests.exceptions.RequestException as e:
            print(f"Error checking {dependency.name}: {e}", file=sys.stderr)
            return []


class OutputFormatter:
    """Formats scan results with language-specific fix commands"""
    
    @staticmethod
    def format_results(result: ScanResult, format_type: str = "text") -> str:
        """Format scan results"""
        if format_type == "json":
            return OutputFormatter._format_json(result)
        else:
            return OutputFormatter._format_text(result)
    
    @staticmethod
    def _format_json(result: ScanResult) -> str:
        """Format results as JSON"""
        output = {
            "project_path": result.project_path,
            "language": result.language.value,
            "summary": {
                "total_dependencies": result.total_count,
                "vulnerable_dependencies": result.vulnerable_count
            },
            "vulnerabilities": []
        }
        
        for dep in result.dependencies:
            if dep.vulnerabilities:
                vuln_data = {
                    "dependency": {
                        "name": dep.name,
                        "version": dep.version
                    },
                    "vulnerabilities": [
                        {
                            "id": v.id,
                            "severity": v.severity.value,
                            "summary": v.summary,
                            "fixed_versions": v.fixed_versions
                        } for v in dep.vulnerabilities
                    ],
                    "fix_command": OutputFormatter._get_fix_command(dep, result.language)
                }
                output["vulnerabilities"].append(vuln_data)
        
        return json.dumps(output, indent=2)
    
    @staticmethod
    def _format_text(result: ScanResult) -> str:
        """Format results as human-readable text"""
        lines = []
        lines.append(f"\n🔍 Security Scan Results for {result.project_path}")
        lines.append(f"📦 Language: {result.language.value}")
        lines.append(f"📊 Total Dependencies: {result.total_count}")
        lines.append(f"⚠️  Vulnerable Dependencies: {result.vulnerable_count}")
        
        if result.vulnerable_count == 0:
            lines.append("\n✅ No vulnerabilities found!")
        else:
            lines.append("\n❌ Vulnerabilities Found:")
            
            # Group by severity
            by_severity = {s: [] for s in Severity}
            for dep in result.dependencies:
                for vuln in dep.vulnerabilities:
                    by_severity[vuln.severity].append((dep, vuln))
            
            for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
                vulns = by_severity[severity]
                if vulns:
                    lines.append(f"\n{OutputFormatter._severity_icon(severity)} {severity.value} ({len(vulns)})")
                    for dep, vuln in vulns:
                        lines.append(f"  - {dep.name}@{dep.version}")
                        lines.append(f"    {vuln.id}: {vuln.summary}")
                        if vuln.fixed_versions:
                            lines.append(f"    Fixed in: {', '.join(vuln.fixed_versions)}")
                        lines.append(f"    Fix: {OutputFormatter._get_fix_command(dep, result.language)}")
        
        return "\n".join(lines)
    
    @staticmethod
    def _severity_icon(severity: Severity) -> str:
        """Get icon for severity level"""
        return {
            Severity.CRITICAL: "🔴",
            Severity.HIGH: "🟠",
            Severity.MEDIUM: "🟡",
            Severity.LOW: "🔵",
            Severity.UNKNOWN: "⚪"
        }.get(severity, "⚪")
    
    @staticmethod
    def _get_fix_command(dependency: Dependency, language: Language) -> str:
        """Get language-specific fix command"""
        if dependency.vulnerabilities and dependency.vulnerabilities[0].fixed_versions:
            fixed_version = dependency.vulnerabilities[0].fixed_versions[0]
            
            if language == Language.JAVASCRIPT:
                return f"npm install {dependency.name}@{fixed_version}"
            elif language == Language.PYTHON:
                return f"pip install {dependency.name}=={fixed_version}"
            elif language == Language.GO:
                return f"go get {dependency.name}@v{fixed_version}"
        
        return "No fix available"


class SecScan:
    """Main scanner class"""
    
    def __init__(self):
        self.detector = LanguageDetector()
        self.osv_client = OSVClient()
        self.formatter = OutputFormatter()
    
    def scan(self, path: Path, output_format: str = "text") -> str:
        """Scan a project for vulnerabilities"""
        # Detect language
        language, manifest_path = self.detector.detect(path)
        
        if language == Language.UNKNOWN:
            return "Error: Could not detect project language. No manifest file found."
        
        # Parse dependencies
        if language == Language.JAVASCRIPT:
            dependencies = DependencyParser.parse_javascript(manifest_path)
        elif language == Language.PYTHON:
            dependencies = DependencyParser.parse_python(manifest_path)
        elif language == Language.GO:
            dependencies = DependencyParser.parse_go(manifest_path)
        else:
            dependencies = []
        
        # Check vulnerabilities
        vulnerable_count = 0
        for dep in dependencies:
            vulns = self.osv_client.check_vulnerability(dep)
            dep.vulnerabilities = vulns
            if vulns:
                vulnerable_count += 1
        
        # Create result
        result = ScanResult(
            project_path=str(path),
            language=language,
            dependencies=dependencies,
            vulnerable_count=vulnerable_count,
            total_count=len(dependencies)
        )
        
        # Format and return
        return self.formatter.format_results(result, output_format)


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description="SecScan - Multi-language dependency vulnerability scanner"
    )
    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Path to project directory (default: current directory)"
    )
    parser.add_argument(
        "-f", "--format",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)"
    )
    parser.add_argument(
        "-v", "--version",
        action="version",
        version="SecScan 1.0.0"
    )
    
    args = parser.parse_args()
    
    # Validate path
    path = Path(args.path).resolve()
    if not path.exists():
        print(f"Error: Path {path} does not exist", file=sys.stderr)
        sys.exit(1)
    
    # Run scan
    scanner = SecScan()
    result = scanner.scan(path, args.format)
    print(result)


if __name__ == "__main__":
    main()