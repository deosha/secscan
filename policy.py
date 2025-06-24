#!/usr/bin/env python3
"""
Policy management for SecScan
Handles complex vulnerability policy rules
"""

import json
import re
import sys
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from secscan import Vulnerability, Severity


@dataclass
class PolicyRule:
    """Represents a policy rule for vulnerability management"""
    max_critical: Optional[int] = None
    max_high: Optional[int] = None
    max_medium: Optional[int] = None
    max_low: Optional[int] = None
    max_total: Optional[int] = None
    max_cvss_score: Optional[float] = None
    require_fixes_for: List[str] = field(default_factory=list)
    max_age_days: Dict[str, int] = field(default_factory=dict)
    block_severities: List[str] = field(default_factory=list)
    allow_exploitable: bool = True
    
    @classmethod
    def from_string(cls, policy_str: str) -> 'PolicyRule':
        """Parse policy from string format
        Example: 'critical=0,high<=3,medium<=10,cvss<8.0'
        """
        rule = cls()
        
        # Split by comma
        parts = policy_str.split(',')
        for part in parts:
            part = part.strip()
            
            # Parse max counts
            if '=' in part or '<=' in part or '<' in part:
                match = re.match(r'(\w+)\s*([<>=]+)\s*(\d+(?:\.\d+)?)', part)
                if match:
                    field, op, value = match.groups()
                    
                    if field == 'critical':
                        rule.max_critical = int(value)
                    elif field == 'high':
                        rule.max_high = int(value)
                    elif field == 'medium':
                        rule.max_medium = int(value)
                    elif field == 'low':
                        rule.max_low = int(value)
                    elif field == 'total':
                        rule.max_total = int(value)
                    elif field == 'cvss':
                        rule.max_cvss_score = float(value)
            
            # Parse other rules
            elif part.startswith('no-'):
                severity = part[3:]
                if severity in ['critical', 'high', 'medium', 'low']:
                    rule.block_severities.append(severity)
            elif part == 'no-exploits':
                rule.allow_exploitable = False
        
        return rule
    
    @classmethod
    def from_file(cls, path: Path) -> 'PolicyRule':
        """Load policy from JSON file"""
        with open(path, 'r') as f:
            data = json.load(f)
        
        return cls.from_dict(data.get('rules', {}))
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'PolicyRule':
        """Create policy from dictionary"""
        rule = cls()
        
        rule.max_critical = data.get('max_critical')
        rule.max_high = data.get('max_high')
        rule.max_medium = data.get('max_medium')
        rule.max_low = data.get('max_low')
        rule.max_total = data.get('max_total')
        rule.max_cvss_score = data.get('max_cvss_score')
        rule.require_fixes_for = data.get('require_fixes_for', [])
        rule.max_age_days = data.get('max_age_days', {})
        rule.block_severities = data.get('block_severities', [])
        rule.allow_exploitable = data.get('allow_exploitable', True)
        
        return rule


class PolicyChecker:
    """Checks vulnerabilities against policy rules"""
    
    def __init__(self, rule: PolicyRule):
        self.rule = rule
    
    def check_vulnerabilities(self, vulnerabilities: List[Vulnerability]) -> Tuple[bool, List[str]]:
        """Check vulnerabilities against policy
        Returns: (passes, list of violations)
        """
        violations = []
        
        # Count by severity
        severity_counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'unknown': 0
        }
        
        total_count = 0
        exploitable_count = 0
        no_fix_count = 0
        
        for vuln in vulnerabilities:
            severity_key = vuln.severity.value.lower()
            severity_counts[severity_key] += 1
            total_count += 1
            
            if vuln.has_exploit:
                exploitable_count += 1
            
            if not vuln.fixed_versions:
                no_fix_count += 1
            
            # Check blocked severities
            if severity_key in self.rule.block_severities:
                violations.append(f"Found {severity_key} severity vulnerability {vuln.id} (blocked by policy)")
            
            # Check CVSS score
            if self.rule.max_cvss_score and vuln.cvss_score and vuln.cvss_score > self.rule.max_cvss_score:
                violations.append(f"Vulnerability {vuln.id} has CVSS score {vuln.cvss_score} > {self.rule.max_cvss_score}")
            
            # Check age
            if vuln.published_date and severity_key in self.rule.max_age_days:
                max_age = self.rule.max_age_days[severity_key]
                published = datetime.fromisoformat(vuln.published_date.replace('Z', '+00:00'))
                age_days = (datetime.now(published.tzinfo) - published).days
                if age_days > max_age:
                    violations.append(f"{severity_key.capitalize()} vulnerability {vuln.id} is {age_days} days old (max: {max_age})")
            
            # Check fix requirements
            if severity_key in self.rule.require_fixes_for and not vuln.fixed_versions:
                violations.append(f"{severity_key.capitalize()} vulnerability {vuln.id} has no available fix")
        
        # Check counts
        if self.rule.max_critical is not None and severity_counts['critical'] > self.rule.max_critical:
            violations.append(f"Found {severity_counts['critical']} critical vulnerabilities (max: {self.rule.max_critical})")
        
        if self.rule.max_high is not None and severity_counts['high'] > self.rule.max_high:
            violations.append(f"Found {severity_counts['high']} high vulnerabilities (max: {self.rule.max_high})")
        
        if self.rule.max_medium is not None and severity_counts['medium'] > self.rule.max_medium:
            violations.append(f"Found {severity_counts['medium']} medium vulnerabilities (max: {self.rule.max_medium})")
        
        if self.rule.max_low is not None and severity_counts['low'] > self.rule.max_low:
            violations.append(f"Found {severity_counts['low']} low vulnerabilities (max: {self.rule.max_low})")
        
        if self.rule.max_total is not None and total_count > self.rule.max_total:
            violations.append(f"Found {total_count} total vulnerabilities (max: {self.rule.max_total})")
        
        # Check exploitable
        if not self.rule.allow_exploitable and exploitable_count > 0:
            violations.append(f"Found {exploitable_count} vulnerabilities with known exploits")
        
        return len(violations) == 0, violations
    
    def get_severity_counts(self, vulnerabilities: List[Vulnerability]) -> Dict[str, int]:
        """Get count of vulnerabilities by severity"""
        counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'unknown': 0,
            'total': 0
        }
        
        for vuln in vulnerabilities:
            severity_key = vuln.severity.value.lower()
            counts[severity_key] += 1
            counts['total'] += 1
        
        return counts