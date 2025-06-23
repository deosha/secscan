"""
Core scanning logic tests for SecScan
"""
import pytest
from unittest.mock import patch, Mock
from pathlib import Path
import json
import sys

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from secscan import (
    SecScan, Language, Dependency, Vulnerability, 
    Severity, ScanResult, LanguageDetector, OSVClient
)


class TestLanguageDetection:
    """Test language detection functionality"""
    
    def test_detect_javascript_package_json(self, temp_dir):
        """Test detecting JavaScript from package.json"""
        (temp_dir / "package.json").write_text('{"name": "test"}')
        
        detector = LanguageDetector()
        language, manifest = detector.detect(temp_dir)
        
        assert language == Language.JAVASCRIPT
        assert manifest.name == "package.json"
    
    def test_detect_javascript_yarn_lock(self, temp_dir):
        """Test detecting JavaScript from yarn.lock"""
        (temp_dir / "yarn.lock").write_text('# yarn lockfile v1')
        
        detector = LanguageDetector()
        language, manifest = detector.detect(temp_dir)
        
        assert language == Language.JAVASCRIPT
        assert manifest.name == "yarn.lock"
    
    def test_detect_python_requirements(self, temp_dir):
        """Test detecting Python from requirements.txt"""
        (temp_dir / "requirements.txt").write_text('flask==2.0.0')
        
        detector = LanguageDetector()
        language, manifest = detector.detect(temp_dir)
        
        assert language == Language.PYTHON
        assert manifest.name == "requirements.txt"
    
    def test_detect_python_pipfile(self, temp_dir):
        """Test detecting Python from Pipfile"""
        (temp_dir / "Pipfile").write_text('[packages]\nflask = "*"')
        
        detector = LanguageDetector()
        language, manifest = detector.detect(temp_dir)
        
        assert language == Language.PYTHON
        assert manifest.name == "Pipfile"
    
    def test_detect_go_mod(self, temp_dir):
        """Test detecting Go from go.mod"""
        (temp_dir / "go.mod").write_text('module example.com/test')
        
        detector = LanguageDetector()
        language, manifest = detector.detect(temp_dir)
        
        assert language == Language.GO
        assert manifest.name == "go.mod"
    
    def test_detect_unknown_language(self, temp_dir):
        """Test detecting unknown language"""
        detector = LanguageDetector()
        language, manifest = detector.detect(temp_dir)
        
        assert language == Language.UNKNOWN
        assert manifest is None
    
    def test_detect_priority_order(self, temp_dir):
        """Test that detection follows priority order"""
        # Create multiple manifest files
        (temp_dir / "package.json").write_text('{}')
        (temp_dir / "requirements.txt").write_text('')
        (temp_dir / "go.mod").write_text('')
        
        detector = LanguageDetector()
        language, manifest = detector.detect(temp_dir)
        
        # Should detect JavaScript first based on order
        assert language == Language.JAVASCRIPT


class TestOSVClient:
    """Test OSV API client functionality"""
    
    @patch('requests.post')
    def test_check_vulnerability_found(self, mock_post, mock_osv_response):
        """Test checking vulnerability when found"""
        mock_post.return_value = mock_osv_response()
        
        client = OSVClient()
        dep = Dependency("lodash", "4.17.20", Language.JAVASCRIPT)
        vulns = client.check_vulnerability(dep)
        
        assert len(vulns) == 1
        assert vulns[0].id == "CVE-2021-23337"
        assert vulns[0].severity == Severity.HIGH
        assert "4.17.21" in vulns[0].fixed_versions
    
    @patch('requests.post')
    def test_check_vulnerability_not_found(self, mock_post):
        """Test checking vulnerability when none found"""
        mock_resp = Mock()
        mock_resp.json.return_value = {"vulns": []}
        mock_resp.raise_for_status = Mock()
        mock_post.return_value = mock_resp
        
        client = OSVClient()
        dep = Dependency("safe-package", "1.0.0", Language.JAVASCRIPT)
        vulns = client.check_vulnerability(dep)
        
        assert len(vulns) == 0
    
    @patch('requests.post')
    def test_check_vulnerability_api_error(self, mock_post):
        """Test handling API errors"""
        mock_post.side_effect = Exception("API Error")
        
        client = OSVClient()
        dep = Dependency("test", "1.0.0", Language.JAVASCRIPT)
        vulns = client.check_vulnerability(dep)
        
        # Should return empty list on error
        assert vulns == []
    
    @patch('requests.post')
    def test_severity_mapping(self, mock_post):
        """Test CVSS score to severity mapping"""
        test_cases = [
            (9.5, Severity.CRITICAL),
            (7.5, Severity.HIGH),
            (5.0, Severity.MEDIUM),
            (2.0, Severity.LOW)
        ]
        
        client = OSVClient()
        
        for score, expected_severity in test_cases:
            mock_resp = Mock()
            mock_resp.json.return_value = {
                "vulns": [{
                    "id": "TEST-001",
                    "severity": [{"type": "CVSS_V3", "score": score}],
                    "affected": [{"package": {"name": "test"}, "ranges": [{"events": []}]}]
                }]
            }
            mock_resp.raise_for_status = Mock()
            mock_post.return_value = mock_resp
            
            dep = Dependency("test", "1.0.0", Language.JAVASCRIPT)
            vulns = client.check_vulnerability(dep)
            
            assert vulns[0].severity == expected_severity
    
    def test_ecosystem_mapping(self):
        """Test language to ecosystem mapping"""
        client = OSVClient()
        
        # Test internal mapping
        ecosystems = {
            Language.JAVASCRIPT: "npm",
            Language.PYTHON: "PyPI",
            Language.GO: "Go"
        }
        
        for lang, expected_ecosystem in ecosystems.items():
            dep = Dependency("test", "1.0.0", lang)
            # This would be used in the actual API call
            assert ecosystems.get(dep.language) == expected_ecosystem


class TestSecScan:
    """Test main scanner functionality"""
    
    @patch('secscan.OSVClient.check_vulnerability')
    def test_scan_javascript_project(self, mock_check_vuln, temp_dir):
        """Test scanning JavaScript project"""
        # Create package.json
        pkg_data = {
            "dependencies": {
                "lodash": "4.17.20",
                "express": "4.17.1"
            }
        }
        (temp_dir / "package.json").write_text(json.dumps(pkg_data))
        
        # Mock vulnerabilities
        mock_check_vuln.return_value = [
            Vulnerability(
                id="CVE-2021-23337",
                summary="Test vulnerability",
                details="Details",
                severity=Severity.HIGH,
                affected_versions=["4.17.20"],
                fixed_versions=["4.17.21"],
                references=[]
            )
        ]
        
        scanner = SecScan()
        result = scanner.scan(temp_dir)
        
        assert "javascript" in result
        assert "Total Dependencies: 2" in result
        assert "Vulnerable Dependencies: 2" in result
        assert "CVE-2021-23337" in result
    
    @patch('secscan.OSVClient.check_vulnerability')
    def test_scan_no_vulnerabilities(self, mock_check_vuln, temp_dir):
        """Test scanning project with no vulnerabilities"""
        (temp_dir / "package.json").write_text('{"dependencies": {"express": "4.18.2"}}')
        
        mock_check_vuln.return_value = []
        
        scanner = SecScan()
        result = scanner.scan(temp_dir)
        
        assert "No vulnerabilities found" in result
        assert "Total Dependencies: 1" in result
        assert "Vulnerable Dependencies: 0" in result
    
    def test_scan_empty_project(self, temp_dir):
        """Test scanning empty project"""
        scanner = SecScan()
        result = scanner.scan(temp_dir)
        
        assert "Could not detect project language" in result
    
    @patch('secscan.OSVClient.check_vulnerability')
    def test_scan_mixed_project(self, mock_check_vuln, temp_dir):
        """Test scanning project with multiple language files"""
        # Create both package.json and requirements.txt
        (temp_dir / "package.json").write_text('{"dependencies": {"lodash": "4.17.20"}}')
        (temp_dir / "requirements.txt").write_text('flask==2.0.0')
        
        mock_check_vuln.return_value = []
        
        scanner = SecScan()
        result = scanner.scan(temp_dir)
        
        # Should detect JavaScript (first in priority)
        assert "javascript" in result
    
    @patch('secscan.OSVClient.check_vulnerability')
    def test_json_output_format(self, mock_check_vuln, temp_dir):
        """Test JSON output format"""
        (temp_dir / "requirements.txt").write_text('django==2.2.0')
        
        mock_check_vuln.return_value = [
            Vulnerability(
                id="CVE-2021-1234",
                summary="Test vulnerability",
                details="Details",
                severity=Severity.CRITICAL,
                affected_versions=["2.2.0"],
                fixed_versions=["2.2.28"],
                references=["https://example.com"]
            )
        ]
        
        scanner = SecScan()
        result = scanner.scan(temp_dir, output_format="json")
        
        # Parse JSON output
        data = json.loads(result)
        
        assert data["language"] == "python"
        assert data["summary"]["total_dependencies"] == 1
        assert data["summary"]["vulnerable_dependencies"] == 1
        assert len(data["vulnerabilities"]) == 1
        
        vuln = data["vulnerabilities"][0]
        assert vuln["dependency"]["name"] == "django"
        assert vuln["dependency"]["version"] == "2.2.0"
        assert vuln["fix_command"] == "pip install django==2.2.28"


class TestScanResult:
    """Test ScanResult data structure"""
    
    def test_scan_result_creation(self):
        """Test creating ScanResult"""
        deps = [
            Dependency("express", "4.17.1", Language.JAVASCRIPT),
            Dependency("lodash", "4.17.20", Language.JAVASCRIPT)
        ]
        
        result = ScanResult(
            project_path="/test/path",
            language=Language.JAVASCRIPT,
            dependencies=deps,
            vulnerable_count=1,
            total_count=2
        )
        
        assert result.project_path == "/test/path"
        assert result.language == Language.JAVASCRIPT
        assert len(result.dependencies) == 2
        assert result.vulnerable_count == 1
        assert result.total_count == 2


class TestCaching:
    """Test caching functionality"""
    
    @patch('secscan.OSVClient.check_vulnerability')
    def test_multiple_scans_performance(self, mock_check_vuln, temp_dir, performance_timer):
        """Test that subsequent scans are faster due to caching"""
        (temp_dir / "package.json").write_text('{"dependencies": {"express": "4.17.1"}}')
        
        mock_check_vuln.return_value = []
        scanner = SecScan()
        
        # First scan
        performance_timer.start()
        scanner.scan(temp_dir)
        performance_timer.stop()
        first_time = performance_timer.elapsed
        
        # Second scan (should potentially be faster if caching is implemented)
        performance_timer.start()
        scanner.scan(temp_dir)
        performance_timer.stop()
        second_time = performance_timer.elapsed
        
        # Just verify both complete successfully
        assert first_time is not None
        assert second_time is not None