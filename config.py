#!/usr/bin/env python3
"""
Configuration management for SecScan
Handles loading, validation, and merging of configuration from multiple sources
"""

import os
import json
import yaml
import sys
from pathlib import Path
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from datetime import datetime
import re


@dataclass
class IgnoreRule:
    """Represents an ignore rule for vulnerabilities or packages"""
    id: Optional[str] = None
    name: Optional[str] = None
    version: Optional[str] = None
    reason: str = ""
    expires: Optional[str] = None
    pattern: Optional[str] = None
    
    def is_expired(self) -> bool:
        """Check if the ignore rule has expired"""
        if not self.expires:
            return False
        try:
            expiry_date = datetime.strptime(self.expires, "%Y-%m-%d")
            return datetime.now() > expiry_date
        except ValueError:
            return False
    
    def matches_vulnerability(self, vuln_id: str) -> bool:
        """Check if this rule matches a vulnerability ID"""
        if self.id:
            return self.id == vuln_id
        if self.pattern:
            return re.match(self.pattern, vuln_id) is not None
        return False
    
    def matches_package(self, name: str, version: str) -> bool:
        """Check if this rule matches a package"""
        if self.name:
            # Handle glob patterns
            if '*' in self.name:
                pattern = self.name.replace('*', '.*')
                if not re.match(pattern, name):
                    return False
            elif self.name != name:
                return False
            
            # Check version if specified
            if self.version and self.version != '*':
                if '*' in self.version:
                    pattern = self.version.replace('*', '.*')
                    return re.match(pattern, version) is not None
                return self.version == version
            
            return True
        return False


@dataclass
class ScanConfig:
    """Scan configuration settings"""
    min_severity: str = "low"
    include_dev: bool = True
    depth: int = 999  # Max dependency depth
    languages: List[str] = field(default_factory=lambda: ["javascript", "python", "go"])


@dataclass
class OutputConfig:
    """Output configuration settings"""
    format: str = "text"  # text, json, sarif, csv, markdown, table
    file: Optional[str] = None
    verbose: bool = False
    no_color: bool = False


@dataclass
class CIConfig:
    """CI/CD configuration settings"""
    fail_on: str = "none"  # none, low, medium, high, critical
    exit_codes: Dict[str, int] = field(default_factory=lambda: {
        "none": 0,
        "low": 0,
        "medium": 0,
        "high": 1,
        "critical": 2
    })


@dataclass
class CacheConfig:
    """Cache configuration settings"""
    directory: str = "~/.secscan/cache"
    ttl: int = 86400  # 24 hours
    offline: bool = False


@dataclass
class SecScanConfig:
    """Main configuration object"""
    version: int = 1
    ignore: Dict[str, List[Dict[str, Any]]] = field(default_factory=dict)
    scan: ScanConfig = field(default_factory=ScanConfig)
    output: OutputConfig = field(default_factory=OutputConfig)
    ci: CIConfig = field(default_factory=CIConfig)
    cache: CacheConfig = field(default_factory=CacheConfig)
    
    # Processed ignore rules
    _ignore_rules: Optional[Dict[str, List[IgnoreRule]]] = None
    
    def get_ignore_rules(self) -> Dict[str, List[IgnoreRule]]:
        """Get processed ignore rules"""
        if self._ignore_rules is None:
            self._ignore_rules = {
                "vulnerabilities": [],
                "packages": [],
                "paths": []
            }
            
            for category, rules in self.ignore.items():
                if category == "vulnerabilities":
                    for rule in rules:
                        ignore_rule = IgnoreRule(
                            id=rule.get("id"),
                            reason=rule.get("reason", ""),
                            expires=rule.get("expires")
                        )
                        if not ignore_rule.is_expired():
                            self._ignore_rules["vulnerabilities"].append(ignore_rule)
                
                elif category == "packages":
                    for rule in rules:
                        if isinstance(rule, dict):
                            name = rule.get("name", "")
                            version = rule.get("version", "*")
                        else:
                            # Support simple string format
                            if '@' in str(rule):
                                name, version = str(rule).split('@', 1)
                            else:
                                name = str(rule)
                                version = "*"
                        
                        ignore_rule = IgnoreRule(
                            name=name,
                            version=version,
                            reason=rule.get("reason", "") if isinstance(rule, dict) else ""
                        )
                        self._ignore_rules["packages"].append(ignore_rule)
                
                elif category == "paths":
                    for path in rules:
                        self._ignore_rules["paths"].append(IgnoreRule(pattern=str(path)))
        
        return self._ignore_rules
    
    def should_ignore_vulnerability(self, vuln_id: str) -> Optional[str]:
        """Check if a vulnerability should be ignored, returns reason if yes"""
        rules = self.get_ignore_rules()
        for rule in rules.get("vulnerabilities", []):
            if rule.matches_vulnerability(vuln_id):
                return rule.reason
        return None
    
    def should_ignore_package(self, name: str, version: str) -> Optional[str]:
        """Check if a package should be ignored, returns reason if yes"""
        rules = self.get_ignore_rules()
        for rule in rules.get("packages", []):
            if rule.matches_package(name, version):
                return rule.reason
        return None
    
    def should_ignore_path(self, path: str) -> bool:
        """Check if a path should be ignored"""
        rules = self.get_ignore_rules()
        for rule in rules.get("paths", []):
            if rule.pattern:
                # Convert glob pattern to regex
                pattern = rule.pattern.replace('**', '.*').replace('*', '[^/]*')
                if re.match(pattern, path):
                    return True
        return False


class ConfigLoader:
    """Handles loading and merging configuration from multiple sources"""
    
    CONFIG_FILENAMES = [
        ".secscan.yml",
        ".secscan.yaml",
        "secscan.config.json"
    ]
    
    SCHEMA = {
        "type": "object",
        "properties": {
            "version": {"type": "integer", "minimum": 1, "maximum": 1},
            "ignore": {
                "type": "object",
                "properties": {
                    "vulnerabilities": {"type": "array"},
                    "packages": {"type": "array"},
                    "paths": {"type": "array"}
                }
            },
            "scan": {
                "type": "object",
                "properties": {
                    "min_severity": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
                    "include_dev": {"type": "boolean"},
                    "depth": {"type": "integer", "minimum": 1},
                    "languages": {"type": "array", "items": {"type": "string"}}
                }
            },
            "output": {
                "type": "object",
                "properties": {
                    "format": {"type": "string", "enum": ["text", "json", "sarif", "csv", "markdown", "table"]},
                    "file": {"type": ["string", "null"]},
                    "verbose": {"type": "boolean"},
                    "no_color": {"type": "boolean"}
                }
            },
            "ci": {
                "type": "object",
                "properties": {
                    "fail_on": {"type": "string", "enum": ["none", "low", "medium", "high", "critical"]},
                    "exit_codes": {"type": "object"}
                }
            },
            "cache": {
                "type": "object",
                "properties": {
                    "directory": {"type": "string"},
                    "ttl": {"type": "integer", "minimum": 0},
                    "offline": {"type": "boolean"}
                }
            }
        }
    }
    
    def __init__(self):
        self.configs_loaded = []
    
    def load_config(self, path: Optional[Path] = None, no_config: bool = False) -> SecScanConfig:
        """Load configuration from files and return merged config"""
        if no_config:
            return SecScanConfig()
        
        config_data = {}
        
        # Load global config first
        global_config = self._load_global_config()
        if global_config:
            config_data = self._merge_configs(config_data, global_config)
            self.configs_loaded.append("global")
        
        # Load project config
        if path:
            project_config = self._load_project_config(path)
        else:
            project_config = self._load_project_config(Path.cwd())
        
        if project_config:
            config_data = self._merge_configs(config_data, project_config)
            self.configs_loaded.append("project")
        
        # Convert to SecScanConfig object
        return self._dict_to_config(config_data)
    
    def _load_global_config(self) -> Optional[Dict[str, Any]]:
        """Load global configuration from ~/.secscan/config.yml"""
        config_path = Path.home() / ".secscan" / "config.yml"
        if config_path.exists():
            return self._load_yaml_file(config_path)
        return None
    
    def _load_project_config(self, path: Path) -> Optional[Dict[str, Any]]:
        """Load project configuration from current directory"""
        for filename in self.CONFIG_FILENAMES:
            config_path = path / filename
            if config_path.exists():
                if filename.endswith('.json'):
                    return self._load_json_file(config_path)
                else:
                    return self._load_yaml_file(config_path)
        return None
    
    def _load_yaml_file(self, path: Path) -> Optional[Dict[str, Any]]:
        """Load and parse YAML file"""
        try:
            with open(path, 'r') as f:
                data = yaml.safe_load(f)
                self._validate_config(data)
                return data
        except yaml.YAMLError as e:
            print(f"Error parsing YAML config {path}: {e}", file=sys.stderr)
            return None
        except Exception as e:
            print(f"Error loading config {path}: {e}", file=sys.stderr)
            return None
    
    def _load_json_file(self, path: Path) -> Optional[Dict[str, Any]]:
        """Load and parse JSON file"""
        try:
            with open(path, 'r') as f:
                data = json.load(f)
                self._validate_config(data)
                return data
        except json.JSONDecodeError as e:
            print(f"Error parsing JSON config {path}: {e}", file=sys.stderr)
            return None
        except Exception as e:
            print(f"Error loading config {path}: {e}", file=sys.stderr)
            return None
    
    def _validate_config(self, data: Dict[str, Any]) -> None:
        """Validate configuration against schema"""
        # Basic validation - could be enhanced with jsonschema
        if "version" in data and data["version"] != 1:
            raise ValueError(f"Unsupported config version: {data['version']}")
        
        # Validate severity values
        valid_severities = ["low", "medium", "high", "critical"]
        if "scan" in data and "min_severity" in data["scan"]:
            if data["scan"]["min_severity"] not in valid_severities:
                raise ValueError(f"Invalid min_severity: {data['scan']['min_severity']}")
        
        if "ci" in data and "fail_on" in data["ci"]:
            if data["ci"]["fail_on"] not in ["none"] + valid_severities:
                raise ValueError(f"Invalid fail_on: {data['ci']['fail_on']}")
    
    def _merge_configs(self, base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
        """Merge two configuration dictionaries, with override taking precedence"""
        result = base.copy()
        
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._merge_configs(result[key], value)
            else:
                result[key] = value
        
        return result
    
    def _dict_to_config(self, data: Dict[str, Any]) -> SecScanConfig:
        """Convert dictionary to SecScanConfig object"""
        config = SecScanConfig()
        
        if "version" in data:
            config.version = data["version"]
        
        if "ignore" in data:
            config.ignore = data["ignore"]
        
        if "scan" in data:
            scan_data = data["scan"]
            config.scan = ScanConfig(
                min_severity=scan_data.get("min_severity", "low"),
                include_dev=scan_data.get("include_dev", True),
                depth=scan_data.get("depth", 999),
                languages=scan_data.get("languages", ["javascript", "python", "go"])
            )
        
        if "output" in data:
            output_data = data["output"]
            config.output = OutputConfig(
                format=output_data.get("format", "text"),
                file=output_data.get("file"),
                verbose=output_data.get("verbose", False),
                no_color=output_data.get("no_color", False)
            )
        
        if "ci" in data:
            ci_data = data["ci"]
            config.ci = CIConfig(
                fail_on=ci_data.get("fail_on", "none"),
                exit_codes=ci_data.get("exit_codes", CIConfig().exit_codes)
            )
        
        if "cache" in data:
            cache_data = data["cache"]
            config.cache = CacheConfig(
                directory=cache_data.get("directory", "~/.secscan/cache"),
                ttl=cache_data.get("ttl", 86400),
                offline=cache_data.get("offline", False)
            )
        
        return config
    
    def merge_with_cli_args(self, config: SecScanConfig, args) -> SecScanConfig:
        """Merge CLI arguments with configuration, CLI args take precedence"""
        # Override format if specified
        if hasattr(args, 'format') and args.format:
            config.output.format = args.format
        
        # Override min_severity if specified
        if hasattr(args, 'min_severity') and args.min_severity:
            config.scan.min_severity = args.min_severity
        
        # Override fail_on if specified
        if hasattr(args, 'fail_on') and args.fail_on:
            config.ci.fail_on = args.fail_on
        
        # Override verbose if specified
        if hasattr(args, 'verbose') and args.verbose:
            config.output.verbose = args.verbose
        
        # Override no_color if specified
        if hasattr(args, 'no_color') and args.no_color:
            config.output.no_color = args.no_color
        
        # Override output file if specified
        if hasattr(args, 'output') and args.output:
            config.output.file = args.output
        
        return config


def create_example_config() -> str:
    """Generate example configuration file content"""
    return """# SecScan Configuration File
# Place this file as .secscan.yml in your project root

version: 1

# Ignore specific vulnerabilities or packages
ignore:
  vulnerabilities:
    # - id: GHSA-1234-5678-90ab
    #   reason: "False positive - not using affected function"
    #   expires: "2024-12-31"  # Optional expiration date
  
  packages:
    # - name: lodash
    #   version: "4.17.20"
    #   reason: "Cannot upgrade due to breaking changes"
    # - name: "jquery@*"  # Glob pattern support
    #   reason: "Legacy dependency"
  
  paths:
    # - "test/**"  # Don't scan test directories
    # - "**/node_modules/jest/**"

# Scanning configuration
scan:
  min_severity: low      # low, medium, high, critical
  include_dev: true      # Include devDependencies
  depth: 999            # Max dependency depth
  languages:            # Which languages to scan
    - javascript
    - python
    - go

# Output configuration
output:
  format: text          # text, json, sarif, csv, markdown, table
  file: null           # Output file (null for stdout)
  verbose: false
  no_color: false

# CI/CD configuration
ci:
  fail_on: none        # none, low, medium, high, critical
  exit_codes:
    none: 0
    low: 0
    medium: 0
    high: 1
    critical: 2

# Cache configuration
cache:
  directory: "~/.secscan/cache"
  ttl: 86400          # 24 hours in seconds
  offline: false      # Use cached data only
"""


def init_config(path: Path = Path.cwd()) -> bool:
    """Initialize a new configuration file"""
    config_path = path / ".secscan.yml"
    
    if config_path.exists():
        response = input(f"{config_path} already exists. Overwrite? (y/N): ")
        if response.lower() != 'y':
            return False
    
    try:
        config_path.write_text(create_example_config())
        print(f"✅ Created {config_path}")
        return True
    except Exception as e:
        print(f"❌ Error creating config file: {e}", file=sys.stderr)
        return False


def validate_config(path: Optional[Path] = None) -> bool:
    """Validate a configuration file"""
    loader = ConfigLoader()
    
    try:
        if path:
            if path.suffix == '.json':
                config_data = loader._load_json_file(path)
            else:
                config_data = loader._load_yaml_file(path)
        else:
            # Try to load from current directory
            config = loader.load_config()
            if not loader.configs_loaded:
                print("❌ No configuration file found", file=sys.stderr)
                return False
        
        print("✅ Configuration is valid")
        return True
    except Exception as e:
        print(f"❌ Configuration validation failed: {e}", file=sys.stderr)
        return False


def show_config(path: Optional[Path] = None, no_config: bool = False) -> None:
    """Display the merged configuration"""
    loader = ConfigLoader()
    config = loader.load_config(path, no_config)
    
    print("# Merged Configuration")
    print(f"# Loaded from: {', '.join(loader.configs_loaded) if loader.configs_loaded else 'defaults'}")
    print()
    
    # Convert to dict for display
    config_dict = {
        "version": config.version,
        "ignore": config.ignore,
        "scan": {
            "min_severity": config.scan.min_severity,
            "include_dev": config.scan.include_dev,
            "depth": config.scan.depth,
            "languages": config.scan.languages
        },
        "output": {
            "format": config.output.format,
            "file": config.output.file,
            "verbose": config.output.verbose,
            "no_color": config.output.no_color
        },
        "ci": {
            "fail_on": config.ci.fail_on,
            "exit_codes": config.ci.exit_codes
        },
        "cache": {
            "directory": config.cache.directory,
            "ttl": config.cache.ttl,
            "offline": config.cache.offline
        }
    }
    
    print(yaml.dump(config_dict, default_flow_style=False))