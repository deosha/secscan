#!/usr/bin/env python3
"""
SecScan - A multi-language dependency vulnerability scanner
Supports JavaScript (npm), Python (pip), and Go modules
"""

__version__ = "1.4.1"

import argparse
import json
import sys
import time
from pathlib import Path
from typing import List, Optional, Tuple, Dict, Any
import requests
from dataclasses import dataclass
from enum import Enum
import re

# Import configuration module
try:
    from config import ConfigLoader, SecScanConfig, init_config, validate_config, show_config
except ImportError:
    # Fallback if config module is not available
    ConfigLoader = None
    SecScanConfig = None

# Import cache module
try:
    from cache import CacheManager, CachedOSVClient, format_cache_stats
except ImportError:
    CacheManager = None
    CachedOSVClient = None


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
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    has_exploit: bool = False
    published_date: Optional[str] = None


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
    
    def check_vulnerability(self, dependency: Dependency) -> List[Vulnerability]:
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
                # Extract severity and CVSS
                severity = Severity.UNKNOWN
                cvss_score = None
                cvss_vector = None
                
                if 'severity' in vuln:
                    for sev in vuln['severity']:
                        if sev['type'] == 'CVSS_V3':
                            # Handle both numeric scores and CVSS vectors
                            score_value = sev.get('score', 0)
                            if isinstance(score_value, str):
                                # Extract score from CVSS vector if present
                                if score_value.startswith('CVSS:'):
                                    cvss_vector = score_value
                                    # Try to extract score from vector
                                    import re
                                    score_match = re.search(r'/AV:[NLAP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/C:[NLH]/I:[NLH]/A:[NLH]', score_value)
                                    if score_match:
                                        # Default to MEDIUM if we can't calculate
                                        severity = Severity.MEDIUM
                                        cvss_score = 5.0
                                else:
                                    try:
                                        cvss_score = float(score_value)
                                    except ValueError:
                                        cvss_score = 5.0  # Default to medium
                            else:
                                cvss_score = float(score_value)
                            
                            # Only apply scoring if we have a numeric score
                            if cvss_score is not None:
                                if cvss_score >= 9.0:
                                    severity = Severity.CRITICAL
                                elif cvss_score >= 7.0:
                                    severity = Severity.HIGH
                                elif cvss_score >= 4.0:
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
                
                # Check for exploit information
                has_exploit = False
                for ref in vuln.get('references', []):
                    ref_type = ref.get('type', '').lower()
                    if ref_type in ['exploit', 'poc', 'proof_of_concept']:
                        has_exploit = True
                        break
                    # Also check URLs for exploit indicators
                    url = ref.get('url', '').lower()
                    if any(indicator in url for indicator in ['exploit', 'poc', 'proof-of-concept', 'metasploit']):
                        has_exploit = True
                        break
                
                # Extract published date
                published_date = vuln.get('published')
                
                vulnerability = Vulnerability(
                    id=vuln.get('id', 'Unknown'),
                    summary=vuln.get('summary', 'No summary available'),
                    details=vuln.get('details', 'No details available'),
                    severity=severity,
                    affected_versions=affected_versions,
                    fixed_versions=fixed_versions,
                    references=[ref.get('url', '') for ref in vuln.get('references', [])],
                    cvss_score=cvss_score,
                    cvss_vector=cvss_vector,
                    has_exploit=has_exploit,
                    published_date=published_date
                )
                vulnerabilities.append(vulnerability)
            
            return vulnerabilities
            
        except requests.exceptions.RequestException as e:
            print(f"Error checking {dependency.name}: {e}", file=sys.stderr)
            return []


class OutputFormatter:
    """Formats scan results with language-specific fix commands"""
    
    @staticmethod
    def format_results(result: ScanResult, format_type: str = "text", ci_mode: bool = False) -> str:
        """Format scan results"""
        if ci_mode:
            return OutputFormatter._format_ci(result)
        elif format_type == "json":
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
    
    @staticmethod
    def _format_ci(result: ScanResult) -> str:
        """Format results for CI environments"""
        lines = []
        
        # Count by severity
        severity_counts = {s: 0 for s in Severity}
        for dep in result.dependencies:
            for vuln in dep.vulnerabilities:
                severity_counts[vuln.severity] += 1
        
        # Summary line
        severity_summary = []
        if severity_counts[Severity.CRITICAL] > 0:
            severity_summary.append(f"{severity_counts[Severity.CRITICAL]} critical")
        if severity_counts[Severity.HIGH] > 0:
            severity_summary.append(f"{severity_counts[Severity.HIGH]} high")
        if severity_counts[Severity.MEDIUM] > 0:
            severity_summary.append(f"{severity_counts[Severity.MEDIUM]} medium")
        if severity_counts[Severity.LOW] > 0:
            severity_summary.append(f"{severity_counts[Severity.LOW]} low")
        
        if result.vulnerable_count == 0:
            lines.append("secscan: no vulnerabilities found")
        else:
            lines.append(f"secscan: found {sum(severity_counts.values())} vulnerabilities ({', '.join(severity_summary)})")
        
        # Show vulnerabilities
        if result.vulnerable_count > 0:
            lines.append("")
            for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
                for dep in result.dependencies:
                    for vuln in dep.vulnerabilities:
                        if vuln.severity == severity:
                            cvss_info = f" (CVSS: {vuln.cvss_score})" if vuln.cvss_score else ""
                            exploit_info = " [EXPLOIT]" if vuln.has_exploit else ""
                            lines.append(f"{severity.value}: {dep.name}@{dep.version} - {vuln.id}{cvss_info}{exploit_info}")
        
        return "\n".join(lines)
    
    @staticmethod
    def format_stats(result: ScanResult, scan_duration: float = 0) -> str:
        """Format detailed statistics"""
        lines = []
        
        # Count statistics
        severity_counts = {s.value: 0 for s in Severity}
        exploitable_count = 0
        fixable_count = 0
        total_vulns = 0
        
        for dep in result.dependencies:
            for vuln in dep.vulnerabilities:
                severity_counts[vuln.severity.value] += 1
                total_vulns += 1
                if vuln.has_exploit:
                    exploitable_count += 1
                if vuln.fixed_versions:
                    fixable_count += 1
        
        lines.append("📊 Scan Statistics")
        lines.append("=" * 50)
        lines.append(f"📦 Total packages scanned: {result.total_count}")
        lines.append(f"⚠️  Vulnerable packages: {result.vulnerable_count}")
        lines.append(f"🔍 Total vulnerabilities: {total_vulns}")
        if scan_duration > 0:
            lines.append(f"⏱️  Scan duration: {scan_duration:.2f}s")
        
        lines.append("\n📈 Severity Breakdown:")
        for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
            count = severity_counts[severity.value]
            if count > 0:
                bar = "█" * min(count, 50)
                lines.append(f"  {severity.value:8} [{count:3}] {bar}")
        
        lines.append(f"\n🔧 Fixable vulnerabilities: {fixable_count}/{total_vulns} ({fixable_count/total_vulns*100:.1f}%)" if total_vulns > 0 else "\n🔧 Fixable vulnerabilities: 0/0")
        lines.append(f"💣 Exploitable vulnerabilities: {exploitable_count}")
        
        return "\n".join(lines)


class SecScan:
    """Main scanner class"""
    
    def __init__(self, config: Optional[SecScanConfig] = None, cache_manager: Optional[CacheManager] = None):
        self.detector = LanguageDetector()
        self.formatter = OutputFormatter()
        self.config = config or (SecScanConfig() if SecScanConfig else None)
        self.cache_manager = cache_manager
        
        # Use cached client if cache is available
        if cache_manager and CachedOSVClient:
            self.osv_client = CachedOSVClient(cache_manager)
        else:
            self.osv_client = OSVClient()
    
    def scan(self, path: Path, output_format: Optional[str] = None, filters: Optional[Dict[str, Any]] = None) -> Tuple[str, ScanResult]:
        """Scan a project for vulnerabilities
        Returns: (formatted_output, scan_result)
        """
        # Use output format from config if not specified
        if output_format is None and self.config:
            output_format = self.config.output.format
        else:
            output_format = output_format or "text"
        
        filters = filters or {}
        
        # Check if path should be ignored
        if self.config and self.config.should_ignore_path(str(path)):
            error_result = ScanResult(str(path), Language.UNKNOWN, [], 0, 0)
            return f"Path {path} is ignored by configuration", error_result
        
        # Detect language
        language, manifest_path = self.detector.detect(path)
        
        if language == Language.UNKNOWN:
            error_result = ScanResult(str(path), Language.UNKNOWN, [], 0, 0)
            return "Error: Could not detect project language. No manifest file found.", error_result
        
        # Check if language is enabled in config
        if self.config and language.value not in self.config.scan.languages:
            error_result = ScanResult(str(path), language, [], 0, 0)
            return f"Language {language.value} is not enabled in configuration", error_result
        
        # Parse dependencies
        if language == Language.JAVASCRIPT:
            dependencies = DependencyParser.parse_javascript(manifest_path)
        elif language == Language.PYTHON:
            dependencies = DependencyParser.parse_python(manifest_path)
        elif language == Language.GO:
            dependencies = DependencyParser.parse_go(manifest_path)
        else:
            dependencies = []
        
        # Filter dev dependencies if configured
        if self.config and not self.config.scan.include_dev:
            # This would need to be implemented in parsers to track dev deps
            pass
        
        # Apply package ignore rules
        filtered_deps = []
        for dep in dependencies:
            if self.config:
                ignore_reason = self.config.should_ignore_package(dep.name, dep.version)
                if ignore_reason:
                    if self.config.output.verbose:
                        print(f"Ignoring {dep.name}@{dep.version}: {ignore_reason}", file=sys.stderr)
                    continue
            filtered_deps.append(dep)
        
        dependencies = filtered_deps
        
        # Try to use cached scan results if available
        if self.cache_manager and not filters.get('refresh_cache'):
            cached_scan = self.cache_manager.get_scan_cache(manifest_path)
            if cached_scan:
                # Check if dependencies match
                cached_deps = cached_scan.get('dependencies', [])
                current_deps = [(d.name, d.version) for d in dependencies]
                cached_dep_list = [(d['name'], d['version']) for d in cached_deps]
                
                if set(current_deps) == set(cached_dep_list):
                    # Use cached results
                    if filters.get('verbose') or (self.config and self.config.output.verbose):
                        print("Using cached scan results", file=sys.stderr)
                    
                    # Reconstruct dependencies with vulnerabilities
                    dep_map = {f"{d.name}@{d.version}": d for d in dependencies}
                    for cached_dep in cached_deps:
                        key = f"{cached_dep['name']}@{cached_dep['version']}"
                        if key in dep_map:
                            dep_map[key].vulnerabilities = [
                                Vulnerability(**v) for v in cached_dep.get('vulnerabilities', [])
                            ]
                    
                    vulnerable_count = sum(1 for d in dependencies if d.vulnerabilities)
                    
                    result = ScanResult(
                        project_path=str(path),
                        language=language,
                        dependencies=dependencies,
                        vulnerable_count=vulnerable_count,
                        total_count=len(dependencies)
                    )
                    
                    ci_mode = filters.get('ci_mode', False)
                    return self.formatter.format_results(result, output_format, ci_mode), result
        
        # Check vulnerabilities
        vulnerable_count = 0
        offline_mode = filters.get('offline', False)
        use_cache = not filters.get('no_cache', False)
        
        # Prepare for batch processing if using cached client
        if isinstance(self.osv_client, CachedOSVClient):
            # Batch check all dependencies
            packages = []
            ecosystem_map = {
                Language.JAVASCRIPT: "npm",
                Language.PYTHON: "PyPI", 
                Language.GO: "Go"
            }
            ecosystem = ecosystem_map.get(language)
            
            if ecosystem:
                for dep in dependencies:
                    packages.append((ecosystem, dep.name, dep.version))
                
                # Progress callback
                def progress_callback(current, total):
                    if filters.get('verbose') or (self.config and self.config.output.verbose):
                        print(f"\rChecking vulnerabilities: [{current}/{total}]", end='', file=sys.stderr)
                
                # Batch check
                results = self.osv_client.batch_check(
                    packages, use_cache=use_cache, offline=offline_mode,
                    progress_callback=progress_callback if not filters.get('ci_mode') else None
                )
                
                if filters.get('verbose') or (self.config and self.config.output.verbose):
                    print("", file=sys.stderr)  # New line after progress
                
                # Map results back to dependencies
                for dep in dependencies:
                    key = f"{ecosystem}:{dep.name}@{dep.version}"
                    vuln_data = results.get(key, [])
                    
                    # Convert raw vulnerability data to Vulnerability objects
                    vulns = self._process_vuln_data(vuln_data)
                    
                    # Apply filters
                    dep.vulnerabilities = self._filter_vulnerabilities(vulns, filters)
                    if dep.vulnerabilities:
                        vulnerable_count += 1
            else:
                # Fallback to regular checking
                for dep in dependencies:
                    vulns = self.osv_client.check_vulnerability(dep)
                    dep.vulnerabilities = self._process_vulnerabilities(vulns, filters)
                    if dep.vulnerabilities:
                        vulnerable_count += 1
        else:
            # Regular OSV client
            for dep in dependencies:
                vulns = self.osv_client.check_vulnerability(dep)
            
            # Apply all filters
            if vulns:
                filtered_vulns = []
                for vuln in vulns:
                    # Check ignore rules
                    if self.config:
                        ignore_reason = self.config.should_ignore_vulnerability(vuln.id)
                        if ignore_reason:
                            if self.config.output.verbose:
                                print(f"Ignoring {vuln.id}: {ignore_reason}", file=sys.stderr)
                            continue
                    
                    # Filter by minimum severity
                    severity_order = {"unknown": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
                    
                    # Check min_severity from config or filters
                    min_severity = filters.get('min_severity') or (self.config.scan.min_severity if self.config else 'low')
                    min_level = severity_order.get(min_severity.lower(), 0)
                    vuln_level = severity_order.get(vuln.severity.value.lower(), 0)
                    
                    if vuln_level < min_level:
                        continue
                    
                    # Filter by specific severities
                    if 'severities' in filters and vuln.severity.value.lower() not in filters['severities']:
                        continue
                    
                    # Filter by CVSS score
                    if 'cvss_min' in filters and vuln.cvss_score:
                        if vuln.cvss_score < filters['cvss_min']:
                            continue
                    
                    # Filter by exploitable
                    if filters.get('exploitable') and not vuln.has_exploit:
                        continue
                    
                    # Filter by has fix
                    if filters.get('has_fix') and not vuln.fixed_versions:
                        continue
                    
                    filtered_vulns.append(vuln)
                
                vulns = filtered_vulns
            
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
        
        # Cache scan results if caching is enabled
        if self.cache_manager and use_cache and not offline_mode:
            # Prepare cache data
            cache_data = {
                'dependencies': [
                    {
                        'name': dep.name,
                        'version': dep.version,
                        'vulnerabilities': [
                            {
                                'id': v.id,
                                'summary': v.summary,
                                'details': v.details,
                                'severity': v.severity.value,
                                'affected_versions': v.affected_versions,
                                'fixed_versions': v.fixed_versions,
                                'references': v.references,
                                'cvss_score': v.cvss_score,
                                'cvss_vector': v.cvss_vector,
                                'has_exploit': v.has_exploit,
                                'published_date': v.published_date
                            }
                            for v in dep.vulnerabilities
                        ]
                    }
                    for dep in dependencies
                ],
                'scan_time': time.time(),
                'language': language.value
            }
            
            try:
                self.cache_manager.set_scan_cache(manifest_path, cache_data)
            except:
                pass  # Don't fail if caching fails
        
        # Format and return
        ci_mode = filters.get('ci_mode', False)
        return self.formatter.format_results(result, output_format, ci_mode), result
    
    def _process_vuln_data(self, vuln_data: List[Dict[str, Any]]) -> List[Vulnerability]:
        """Convert raw vulnerability data to Vulnerability objects"""
        vulnerabilities = []
        
        for vuln in vuln_data:
            # Extract severity and CVSS
            severity = Severity.UNKNOWN
            cvss_score = None
            cvss_vector = None
            
            if 'severity' in vuln:
                for sev in vuln['severity']:
                    if sev['type'] == 'CVSS_V3':
                        # Handle both numeric scores and CVSS vectors
                        score_value = sev.get('score', 0)
                        if isinstance(score_value, str):
                            if score_value.startswith('CVSS:'):
                                cvss_vector = score_value
                                severity = Severity.MEDIUM
                                cvss_score = 5.0
                            else:
                                try:
                                    cvss_score = float(score_value)
                                except ValueError:
                                    cvss_score = 5.0
                        else:
                            cvss_score = float(score_value)
                        
                        # Apply scoring
                        if cvss_score is not None:
                            if cvss_score >= 9.0:
                                severity = Severity.CRITICAL
                            elif cvss_score >= 7.0:
                                severity = Severity.HIGH
                            elif cvss_score >= 4.0:
                                severity = Severity.MEDIUM
                            else:
                                severity = Severity.LOW
                        break
            
            # Extract affected and fixed versions
            affected_versions = []
            fixed_versions = []
            
            for affected in vuln.get('affected', []):
                for range_info in affected.get('ranges', []):
                    for event in range_info.get('events', []):
                        if 'introduced' in event:
                            affected_versions.append(event['introduced'])
                        if 'fixed' in event:
                            fixed_versions.append(event['fixed'])
            
            # Check for exploit information
            has_exploit = False
            for ref in vuln.get('references', []):
                ref_type = ref.get('type', '').lower()
                if ref_type in ['exploit', 'poc', 'proof_of_concept']:
                    has_exploit = True
                    break
                url = ref.get('url', '').lower()
                if any(indicator in url for indicator in ['exploit', 'poc', 'proof-of-concept', 'metasploit']):
                    has_exploit = True
                    break
            
            # Extract published date
            published_date = vuln.get('published')
            
            vulnerability = Vulnerability(
                id=vuln.get('id', 'Unknown'),
                summary=vuln.get('summary', 'No summary available'),
                details=vuln.get('details', 'No details available'),
                severity=severity,
                affected_versions=affected_versions,
                fixed_versions=fixed_versions,
                references=[ref.get('url', '') for ref in vuln.get('references', [])],
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                has_exploit=has_exploit,
                published_date=published_date
            )
            vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _filter_vulnerabilities(self, vulns: List[Vulnerability], filters: Dict[str, Any]) -> List[Vulnerability]:
        """Apply filters to vulnerabilities"""
        filtered_vulns = []
        
        for vuln in vulns:
            # Check ignore rules
            if self.config:
                ignore_reason = self.config.should_ignore_vulnerability(vuln.id)
                if ignore_reason:
                    if self.config.output.verbose or filters.get('verbose'):
                        print(f"Ignoring {vuln.id}: {ignore_reason}", file=sys.stderr)
                    continue
            
            # Filter by minimum severity
            severity_order = {"unknown": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
            
            # Check min_severity from config or filters
            min_severity = filters.get('min_severity') or (self.config.scan.min_severity if self.config else 'low')
            min_level = severity_order.get(min_severity.lower(), 0)
            vuln_level = severity_order.get(vuln.severity.value.lower(), 0)
            
            if vuln_level < min_level:
                continue
            
            # Filter by specific severities
            if 'severities' in filters and vuln.severity.value.lower() not in filters['severities']:
                continue
            
            # Filter by CVSS score
            if 'cvss_min' in filters and vuln.cvss_score:
                if vuln.cvss_score < filters['cvss_min']:
                    continue
            
            # Filter by exploitable
            if filters.get('exploitable') and not vuln.has_exploit:
                continue
            
            # Filter by has fix
            if filters.get('has_fix') and not vuln.fixed_versions:
                continue
            
            filtered_vulns.append(vuln)
        
        return filtered_vulns


def main():
    """Main CLI entry point"""
    # Check if first argument is 'config' to use subparser
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == 'config':
        # Use subparser for config commands
        parser = argparse.ArgumentParser(
            description="SecScan - Multi-language dependency vulnerability scanner"
        )
        subparsers = parser.add_subparsers(dest="command", help="Commands")
        
        if ConfigLoader:
            config_parser = subparsers.add_parser("config", help="Configuration management")
            config_subparsers = config_parser.add_subparsers(dest="config_command", help="Config commands")
            
            # config init
            init_parser = config_subparsers.add_parser("init", help="Create example configuration file")
            init_parser.add_argument("--path", type=Path, help="Directory to create config in")
            
            # config validate
            validate_parser = config_subparsers.add_parser("validate", help="Validate configuration file")
            validate_parser.add_argument("--file", type=Path, help="Config file to validate")
            
            # config show
            show_parser = config_subparsers.add_parser("show", help="Display merged configuration")
            show_parser.add_argument("--no-config", action="store_true", help="Show default configuration")
        
        if CacheManager:
            cache_parser = subparsers.add_parser("cache", help="Cache management")
            cache_subparsers = cache_parser.add_subparsers(dest="cache_command", help="Cache commands")
            
            # cache warm
            warm_parser = cache_subparsers.add_parser("warm", help="Pre-populate cache with common data")
            warm_parser.add_argument("--ecosystems", nargs="+", choices=["npm", "PyPI", "Go"],
                                   help="Ecosystems to warm (default: all)")
    else:
        # Regular parser for scanning
        parser = argparse.ArgumentParser(
            description="SecScan - Multi-language dependency vulnerability scanner"
        )
        parser.add_argument(
            "path",
            nargs="?",
            default=".",
            help="Path to project directory (default: current directory)"
        )
    # Add common arguments
    parser.add_argument(
        "-f", "--format",
        choices=["text", "json", "table", "csv", "markdown", "sarif"],
        help="Output format"
    )
    parser.add_argument(
        "-o", "--output",
        help="Output file (default: stdout)"
    )
    parser.add_argument(
        "--min-severity",
        choices=["low", "medium", "high", "critical"],
        help="Minimum severity to report"
    )
    parser.add_argument(
        "--severity",
        help="Show only specific severities (comma-separated: critical,high)"
    )
    parser.add_argument(
        "--cvss-min",
        type=float,
        help="Filter by minimum CVSS score"
    )
    parser.add_argument(
        "--exploitable",
        action="store_true",
        help="Only show vulnerabilities with known exploits"
    )
    parser.add_argument(
        "--has-fix",
        action="store_true",
        help="Only show vulnerabilities with available fixes"
    )
    parser.add_argument(
        "--fail-on",
        choices=["none", "low", "medium", "high", "critical", "any"],
        help="Exit with non-zero code if vulnerabilities at or above this level are found"
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Fail on ANY vulnerability regardless of severity"
    )
    parser.add_argument(
        "--ci",
        action="store_true",
        help="CI-friendly output mode"
    )
    parser.add_argument(
        "--max-critical",
        type=int,
        help="Maximum number of critical vulnerabilities allowed"
    )
    parser.add_argument(
        "--max-high",
        type=int,
        help="Maximum number of high vulnerabilities allowed"
    )
    parser.add_argument(
        "--max-total",
        type=int,
        help="Maximum total number of vulnerabilities allowed"
    )
    parser.add_argument(
        "--policy",
        help="Policy string (e.g., 'critical=0,high<=3,medium<=10')"
    )
    parser.add_argument(
        "--policy-file",
        type=Path,
        help="Path to policy JSON file"
    )
    parser.add_argument(
        "--stats",
        action="store_true",
        help="Show detailed statistics"
    )
    # Cache-related arguments
    parser.add_argument(
        "--cache-dir",
        type=Path,
        help="Override default cache location"
    )
    parser.add_argument(
        "--cache-ttl",
        type=int,
        help="Override cache TTL in seconds (default: 24h)"
    )
    parser.add_argument(
        "--refresh-cache",
        action="store_true",
        help="Force refresh ignoring TTL"
    )
    parser.add_argument(
        "--clear-cache",
        action="store_true",
        help="Remove all cached data"
    )
    parser.add_argument(
        "--cache-stats",
        action="store_true",
        help="Show cache size and age"
    )
    parser.add_argument(
        "--no-cache",
        action="store_true",
        help="Disable caching for this run"
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Use only cached data, no network calls"
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=5,
        help="Number of parallel threads (default: 5)"
    )
    parser.add_argument(
        "--no-config",
        action="store_true",
        help="Ignore configuration files"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Verbose output"
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output"
    )
    parser.add_argument(
        "-v", "--version",
        action="version",
        version=f"SecScan {__version__}"
    )
    
    args = parser.parse_args()
    
    # Handle config commands
    if hasattr(args, 'command') and args.command == "config":
        if not ConfigLoader:
            print("Error: Configuration module not available", file=sys.stderr)
            sys.exit(1)
        
        if args.config_command == "init":
            path = Path(args.path) if args.path else Path.cwd()
            success = init_config(path)
            sys.exit(0 if success else 1)
        
        elif args.config_command == "validate":
            success = validate_config(args.file)
            sys.exit(0 if success else 1)
        
        elif args.config_command == "show":
            show_config(no_config=args.no_config)
            sys.exit(0)
        
        else:
            config_parser.print_help()
            sys.exit(1)
    
    # Handle cache commands
    if hasattr(args, 'command') and args.command == "cache":
        if not CacheManager:
            print("Error: Cache module not available", file=sys.stderr)
            sys.exit(1)
        
        cache_manager = CacheManager(cache_dir=args.cache_dir if hasattr(args, 'cache_dir') else None)
        
        if args.cache_command == "warm":
            print("🔥 Warming cache...")
            
            def progress_callback(current, total, message):
                print(f"\r[{current}/{total}] {message}", end='', flush=True)
            
            cache_manager.warm_cache(
                ecosystems=args.ecosystems,
                progress_callback=progress_callback
            )
            print("\n✅ Cache warming complete!")
            sys.exit(0)
        else:
            cache_parser.print_help()
            sys.exit(1)
    
    # Initialize cache manager
    cache_manager = None
    if CacheManager and not args.no_cache:
        cache_manager = CacheManager(
            cache_dir=args.cache_dir,
            ttl=args.cache_ttl
        )
        
        # Handle cache operations
        if args.clear_cache:
            cache_manager.clear_cache()
            print("✅ Cache cleared successfully")
            sys.exit(0)
        
        if args.cache_stats:
            stats = cache_manager.get_cache_stats()
            print(format_cache_stats(stats))
            sys.exit(0)
    
    # Load configuration
    config = None
    if ConfigLoader and not args.no_config:
        loader = ConfigLoader()
        config = loader.load_config()
        
        # Merge CLI arguments with config
        config = loader.merge_with_cli_args(config, args)
        
        # Apply verbose setting
        if config.output.verbose:
            print(f"Loaded configuration from: {', '.join(loader.configs_loaded) if loader.configs_loaded else 'defaults'}", file=sys.stderr)
    
    # Validate path
    path = Path(args.path).resolve()
    if not path.exists():
        print(f"Error: Path {path} does not exist", file=sys.stderr)
        sys.exit(1)
    
    # Build filters from CLI arguments
    filters = {}
    
    # Severity filters
    if args.severity:
        filters['severities'] = [s.strip().lower() for s in args.severity.split(',')]
    if args.min_severity:
        filters['min_severity'] = args.min_severity
    
    # Other filters
    if args.cvss_min:
        filters['cvss_min'] = args.cvss_min
    if args.exploitable:
        filters['exploitable'] = True
    if args.has_fix:
        filters['has_fix'] = True
    if args.ci:
        filters['ci_mode'] = True
    
    # Cache filters
    if args.refresh_cache:
        filters['refresh_cache'] = True
    if args.no_cache:
        filters['no_cache'] = True
    if args.offline:
        filters['offline'] = True
        if args.verbose or (config and config.output.verbose):
            print("⚠️  Running in offline mode - using only cached data", file=sys.stderr)
    if args.verbose:
        filters['verbose'] = True
    
    # Run scan
    start_time = time.time()
    scanner = SecScan(config, cache_manager)
    output, scan_result = scanner.scan(path, args.format, filters)
    scan_duration = time.time() - start_time
    
    # Show statistics if requested
    if args.stats:
        print(OutputFormatter.format_stats(scan_result, scan_duration))
        print()  # Empty line before main output
    
    # Handle CI mode timing
    if args.ci:
        print(f"secscan: scanning project...", file=sys.stderr)
        print(f"secscan: scan completed in {scan_duration:.1f}s", file=sys.stderr)
        print(file=sys.stderr)  # Empty line
    
    # Handle output
    if args.output or (config and config.output.file):
        output_file = Path(args.output or config.output.file)
        try:
            output_file.write_text(output)
            if (config and config.output.verbose) or args.verbose:
                print(f"Results written to {output_file}", file=sys.stderr)
        except Exception as e:
            print(f"Error writing to {output_file}: {e}", file=sys.stderr)
            sys.exit(2)
    else:
        print(output)
    
    # Check policy if specified
    policy_violations = []
    if args.policy or args.policy_file:
        try:
            # Import policy module
            from policy import PolicyRule, PolicyChecker
            
            if args.policy_file:
                policy_rule = PolicyRule.from_file(args.policy_file)
            else:
                policy_rule = PolicyRule.from_string(args.policy)
            
            # Check policy
            all_vulns = []
            for dep in scan_result.dependencies:
                all_vulns.extend(dep.vulnerabilities)
            
            checker = PolicyChecker(policy_rule)
            passes, violations = checker.check_vulnerabilities(all_vulns)
            
            if not passes:
                policy_violations = violations
                if args.verbose or (config and config.output.verbose):
                    print("\n❌ Policy Violations:", file=sys.stderr)
                    for violation in violations:
                        print(f"  - {violation}", file=sys.stderr)
        except Exception as e:
            print(f"Error checking policy: {e}", file=sys.stderr)
            sys.exit(2)
    
    # Check threshold limits
    threshold_violations = []
    severity_counts = {}
    total_vulns = 0
    
    for dep in scan_result.dependencies:
        for vuln in dep.vulnerabilities:
            severity_key = vuln.severity.value.lower()
            severity_counts[severity_key] = severity_counts.get(severity_key, 0) + 1
            total_vulns += 1
    
    if args.max_critical is not None and severity_counts.get('critical', 0) > args.max_critical:
        threshold_violations.append(f"Found {severity_counts.get('critical', 0)} critical vulnerabilities (max: {args.max_critical})")
    
    if args.max_high is not None and severity_counts.get('high', 0) > args.max_high:
        threshold_violations.append(f"Found {severity_counts.get('high', 0)} high vulnerabilities (max: {args.max_high})")
    
    if args.max_total is not None and total_vulns > args.max_total:
        threshold_violations.append(f"Found {total_vulns} total vulnerabilities (max: {args.max_total})")
    
    if threshold_violations and (args.verbose or (config and config.output.verbose)):
        print("\n❌ Threshold Violations:", file=sys.stderr)
        for violation in threshold_violations:
            print(f"  - {violation}", file=sys.stderr)
    
    # Determine exit code
    exit_code = 0
    exit_reason = None
    
    # Check strict mode
    if args.strict and total_vulns > 0:
        exit_code = 1
        exit_reason = "strict mode - any vulnerabilities found"
    
    # Check fail-on level
    elif args.fail_on or (config and config.ci.fail_on != "none"):
        fail_on = args.fail_on or (config.ci.fail_on if config else "none")
        if fail_on == "any" and total_vulns > 0:
            exit_code = 1
            exit_reason = "any vulnerabilities found"
        elif fail_on != "none":
            severity_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
            fail_level = severity_order.get(fail_on.lower(), -1)
            
            for severity in ["critical", "high", "medium", "low"]:
                if severity_counts.get(severity, 0) > 0:
                    if severity_order.get(severity, -1) >= fail_level:
                        exit_code = 1
                        if config and severity in config.ci.exit_codes:
                            exit_code = config.ci.exit_codes[severity]
                        exit_reason = f"{severity} severity vulnerabilities found (--fail-on={fail_on})"
                        break
    
    # Check policy violations
    if policy_violations:
        exit_code = max(exit_code, 1)
        exit_reason = "policy violations"
    
    # Check threshold violations
    if threshold_violations:
        exit_code = max(exit_code, 1)
        exit_reason = "threshold violations"
    
    # Handle CI mode exit message
    if args.ci and exit_code > 0 and exit_reason:
        print(f"\nsecscan: failing due to {exit_reason}", file=sys.stderr)
    elif exit_code > 0 and (args.verbose or (config and config.output.verbose)):
        print(f"\nExiting with code {exit_code} due to {exit_reason}", file=sys.stderr)
    
    sys.exit(exit_code)


if __name__ == "__main__":
    main()