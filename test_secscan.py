#!/usr/bin/env python3
"""
Tests for SecScan vulnerability scanner
"""

import unittest
import tempfile
import json
from pathlib import Path
from secscan import (
    Language, LanguageDetector, DependencyParser, 
    Dependency, OutputFormatter, ScanResult, Severity, Vulnerability
)


class TestLanguageDetector(unittest.TestCase):
    """Test language detection"""
    
    def test_detect_javascript(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create package.json
            pkg_path = Path(tmpdir) / "package.json"
            pkg_path.write_text('{"name": "test"}')
            
            language, manifest = LanguageDetector.detect(Path(tmpdir))
            self.assertEqual(language, Language.JAVASCRIPT)
            self.assertEqual(manifest, pkg_path)
    
    def test_detect_python(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create requirements.txt
            req_path = Path(tmpdir) / "requirements.txt"
            req_path.write_text('requests==2.28.0')
            
            language, manifest = LanguageDetector.detect(Path(tmpdir))
            self.assertEqual(language, Language.PYTHON)
            self.assertEqual(manifest, req_path)
    
    def test_detect_go(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create go.mod
            mod_path = Path(tmpdir) / "go.mod"
            mod_path.write_text('module example.com/test')
            
            language, manifest = LanguageDetector.detect(Path(tmpdir))
            self.assertEqual(language, Language.GO)
            self.assertEqual(manifest, mod_path)
    
    def test_detect_unknown(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            language, manifest = LanguageDetector.detect(Path(tmpdir))
            self.assertEqual(language, Language.UNKNOWN)
            self.assertIsNone(manifest)


class TestDependencyParser(unittest.TestCase):
    """Test dependency parsing"""
    
    def test_parse_javascript(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            pkg_path = Path(tmpdir) / "package.json"
            pkg_data = {
                "dependencies": {
                    "express": "^4.18.0",
                    "lodash": "~4.17.21"
                },
                "devDependencies": {
                    "jest": "^29.0.0"
                }
            }
            pkg_path.write_text(json.dumps(pkg_data))
            
            deps = DependencyParser.parse_javascript(pkg_path)
            self.assertEqual(len(deps), 3)
            
            # Check parsed versions
            dep_dict = {d.name: d.version for d in deps}
            self.assertEqual(dep_dict["express"], "4.18.0")
            self.assertEqual(dep_dict["lodash"], "4.17.21")
            self.assertEqual(dep_dict["jest"], "29.0.0")
    
    def test_parse_python(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            req_path = Path(tmpdir) / "requirements.txt"
            req_path.write_text("""
# Comments should be ignored
requests==2.28.0
flask>=2.0.0
numpy~=1.23.0
pandas

# Another comment
django==4.1.0
            """)
            
            deps = DependencyParser.parse_python(req_path)
            self.assertEqual(len(deps), 5)
            
            # Check parsed versions
            dep_dict = {d.name: d.version for d in deps}
            self.assertEqual(dep_dict["requests"], "2.28.0")
            self.assertEqual(dep_dict["flask"], "2.0.0")
            self.assertEqual(dep_dict["numpy"], "1.23.0")
            self.assertEqual(dep_dict["pandas"], "unknown")
            self.assertEqual(dep_dict["django"], "4.1.0")
    
    def test_parse_go(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            mod_path = Path(tmpdir) / "go.mod"
            mod_path.write_text("""
module example.com/test

go 1.19

require (
    github.com/gin-gonic/gin v1.8.1
    github.com/stretchr/testify v1.8.0
)

require github.com/go-sql-driver/mysql v1.6.0
            """)
            
            deps = DependencyParser.parse_go(mod_path)
            self.assertEqual(len(deps), 3)
            
            # Check parsed modules
            dep_dict = {d.name: d.version for d in deps}
            self.assertEqual(dep_dict["github.com/gin-gonic/gin"], "1.8.1")
            self.assertEqual(dep_dict["github.com/stretchr/testify"], "1.8.0")
            self.assertEqual(dep_dict["github.com/go-sql-driver/mysql"], "1.6.0")


class TestOutputFormatter(unittest.TestCase):
    """Test output formatting"""
    
    def test_format_no_vulnerabilities(self):
        result = ScanResult(
            project_path="/test/project",
            language=Language.JAVASCRIPT,
            dependencies=[
                Dependency("express", "4.18.0", Language.JAVASCRIPT),
                Dependency("lodash", "4.17.21", Language.JAVASCRIPT)
            ],
            vulnerable_count=0,
            total_count=2
        )
        
        output = OutputFormatter.format_results(result, "text")
        self.assertIn("No vulnerabilities found", output)
        self.assertIn("Total Dependencies: 2", output)
    
    def test_format_with_vulnerabilities(self):
        vuln = Vulnerability(
            id="CVE-2021-12345",
            summary="Test vulnerability",
            details="Test details",
            severity=Severity.HIGH,
            affected_versions=["4.17.0"],
            fixed_versions=["4.17.21"],
            references=["https://example.com"]
        )
        
        dep = Dependency("lodash", "4.17.0", Language.JAVASCRIPT)
        dep.vulnerabilities = [vuln]
        
        result = ScanResult(
            project_path="/test/project",
            language=Language.JAVASCRIPT,
            dependencies=[dep],
            vulnerable_count=1,
            total_count=1
        )
        
        # Test text format
        text_output = OutputFormatter.format_results(result, "text")
        self.assertIn("CVE-2021-12345", text_output)
        self.assertIn("npm install lodash@4.17.21", text_output)
        self.assertIn("HIGH", text_output)
        
        # Test JSON format
        json_output = OutputFormatter.format_results(result, "json")
        data = json.loads(json_output)
        self.assertEqual(data["summary"]["vulnerable_dependencies"], 1)
        self.assertEqual(len(data["vulnerabilities"]), 1)
        self.assertEqual(data["vulnerabilities"][0]["fix_command"], "npm install lodash@4.17.21")
    
    def test_severity_grouping(self):
        deps = []
        severities = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
        
        for i, sev in enumerate(severities):
            vuln = Vulnerability(
                id=f"CVE-2021-{i}",
                summary=f"Test {sev.value}",
                details="Details",
                severity=sev,
                affected_versions=["1.0.0"],
                fixed_versions=["2.0.0"],
                references=[]
            )
            dep = Dependency(f"package{i}", "1.0.0", Language.JAVASCRIPT)
            dep.vulnerabilities = [vuln]
            deps.append(dep)
        
        result = ScanResult(
            project_path="/test",
            language=Language.JAVASCRIPT,
            dependencies=deps,
            vulnerable_count=4,
            total_count=4
        )
        
        output = OutputFormatter.format_results(result, "text")
        
        # Check severity order
        critical_pos = output.find("CRITICAL")
        high_pos = output.find("HIGH")
        medium_pos = output.find("MEDIUM")
        low_pos = output.find("LOW")
        
        self.assertTrue(critical_pos < high_pos < medium_pos < low_pos)


if __name__ == "__main__":
    unittest.main()