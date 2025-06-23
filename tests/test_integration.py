"""
Integration tests for SecScan with real-world scenarios
"""
import pytest
import json
import time
from pathlib import Path
from unittest.mock import patch, Mock
import subprocess
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from secscan import SecScan, Language


class TestRealWorldProjects:
    """Test with real-world project configurations"""
    
    def test_scan_vulnerable_javascript_project(self, cli_runner):
        """Test scanning JavaScript project with known vulnerabilities"""
        js_project = Path(__file__).parent.parent / "demo/vulnerable_projects/javascript"
        
        if js_project.exists():
            result = cli_runner([str(js_project)])
            
            assert result.returncode == 0
            assert "javascript" in result.stdout.lower()
            
            # Should find vulnerabilities in lodash 4.17.20 and axios 0.21.0
            assert "lodash" in result.stdout or "4.17.20" in result.stdout
            assert "axios" in result.stdout or "0.21.0" in result.stdout
    
    def test_scan_vulnerable_python_project(self, cli_runner):
        """Test scanning Python project with known vulnerabilities"""
        py_project = Path(__file__).parent.parent / "demo/vulnerable_projects/python"
        
        if py_project.exists():
            result = cli_runner([str(py_project)])
            
            assert result.returncode == 0
            assert "python" in result.stdout.lower()
            
            # Should find vulnerabilities in django 2.2.0 and flask 0.12.2
            assert "django" in result.stdout.lower() or "2.2.0" in result.stdout
            assert "flask" in result.stdout.lower() or "0.12.2" in result.stdout
    
    def test_scan_vulnerable_go_project(self, cli_runner):
        """Test scanning Go project with known vulnerabilities"""
        go_project = Path(__file__).parent.parent / "demo/vulnerable_projects/go"
        
        if go_project.exists():
            result = cli_runner([str(go_project)])
            
            assert result.returncode == 0
            assert "go" in result.stdout.lower()
            
            # Should find vulnerability in jwt-go v3.2.0
            assert "jwt-go" in result.stdout or "3.2.0" in result.stdout
    
    def test_scan_mixed_project(self, cli_runner):
        """Test scanning project with multiple language files"""
        mixed_project = Path(__file__).parent.parent / "demo/vulnerable_projects/mixed"
        
        if mixed_project.exists():
            result = cli_runner([str(mixed_project)])
            
            assert result.returncode == 0
            # Should detect one language (JavaScript has priority)
            assert "javascript" in result.stdout.lower() or "python" in result.stdout.lower()
    
    def test_scan_corrupted_project(self, cli_runner):
        """Test scanning project with corrupted manifest"""
        corrupted_project = Path(__file__).parent.parent / "demo/vulnerable_projects/corrupted"
        
        if corrupted_project.exists():
            result = cli_runner([str(corrupted_project)])
            
            # Should handle error gracefully
            assert result.returncode == 0 or "Error" in result.stderr


class TestOutputFormats:
    """Test different output formats"""
    
    def test_json_output_integration(self, cli_runner):
        """Test JSON output with real project"""
        js_project = Path(__file__).parent.parent / "demo/vulnerable_projects/javascript"
        
        if js_project.exists():
            result = cli_runner([str(js_project), "-f", "json"])
            
            assert result.returncode == 0
            
            # Validate JSON structure
            data = json.loads(result.stdout)
            assert isinstance(data, dict)
            assert "project_path" in data
            assert "language" in data
            assert "summary" in data
            assert "vulnerabilities" in data
            
            # Check data integrity
            assert data["language"] == "javascript"
            assert data["summary"]["total_dependencies"] > 0
    
    def test_text_output_formatting(self, cli_runner):
        """Test text output formatting"""
        py_project = Path(__file__).parent.parent / "demo/vulnerable_projects/python"
        
        if py_project.exists():
            result = cli_runner([str(py_project), "-f", "text"])
            
            assert result.returncode == 0
            
            # Check for formatting elements
            assert "🔍" in result.stdout  # Search icon
            assert "📦" in result.stdout  # Package icon
            assert "📊" in result.stdout  # Chart icon
            
            # Check for severity indicators if vulnerabilities found
            if "Vulnerabilities Found" in result.stdout:
                # Should have severity levels
                assert any(severity in result.stdout for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"])


class TestPerformanceBenchmarks:
    """Performance benchmark tests"""
    
    def test_large_project_performance(self, temp_dir, performance_timer):
        """Test performance with large number of dependencies"""
        # Create a large package.json
        large_deps = {}
        for i in range(100):
            large_deps[f"package-{i}"] = f"1.{i}.0"
        
        pkg_data = {
            "name": "large-project",
            "dependencies": large_deps
        }
        
        pkg_file = temp_dir / "package.json"
        with open(pkg_file, 'w') as f:
            json.dump(pkg_data, f)
        
        # Mock API responses to avoid rate limiting
        with patch('requests.post') as mock_post:
            mock_resp = Mock()
            mock_resp.json.return_value = {"vulns": []}
            mock_resp.raise_for_status = Mock()
            mock_post.return_value = mock_resp
            
            scanner = SecScan()
            
            performance_timer.start()
            result = scanner.scan(temp_dir)
            performance_timer.stop()
            
            # Should complete within 30 seconds
            assert performance_timer.elapsed < 30
            assert "Total Dependencies: 100" in result
    
    def test_concurrent_scanning_performance(self, temp_dir, performance_timer):
        """Test performance of concurrent scans"""
        import threading
        
        # Create multiple projects
        projects = []
        for i in range(5):
            proj_dir = temp_dir / f"project_{i}"
            proj_dir.mkdir()
            
            pkg_file = proj_dir / "package.json"
            pkg_file.write_text(f'{{"dependencies": {{"express": "4.17.{i}"}}}}')
            projects.append(proj_dir)
        
        results = []
        
        def scan_project(path):
            scanner = SecScan()
            with patch('requests.post') as mock_post:
                mock_resp = Mock()
                mock_resp.json.return_value = {"vulns": []}
                mock_resp.raise_for_status = Mock()
                mock_post.return_value = mock_resp
                
                result = scanner.scan(path)
                results.append(result)
        
        performance_timer.start()
        
        # Run concurrent scans
        threads = []
        for proj in projects:
            t = threading.Thread(target=scan_project, args=(proj,))
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        performance_timer.stop()
        
        # All scans should complete
        assert len(results) == 5
        # Should complete reasonably fast
        assert performance_timer.elapsed < 10


class TestCICDIntegration:
    """Test CI/CD integration scenarios"""
    
    def test_exit_code_with_vulnerabilities(self, temp_dir, cli_runner):
        """Test exit code when vulnerabilities are found"""
        # Create project with vulnerable dependency
        pkg_file = temp_dir / "package.json"
        pkg_file.write_text('{"dependencies": {"lodash": "4.17.20"}}')
        
        result = cli_runner([str(temp_dir)])
        
        # Should exit with 0 (success) even with vulnerabilities
        # (could be configured to exit with non-zero for CI/CD)
        assert result.returncode == 0
    
    def test_json_output_for_ci_parsing(self, temp_dir, cli_runner):
        """Test JSON output suitable for CI parsing"""
        req_file = temp_dir / "requirements.txt"
        req_file.write_text("django==2.2.0\nflask==0.12.2")
        
        result = cli_runner([str(temp_dir), "-f", "json"])
        
        if result.returncode == 0:
            data = json.loads(result.stdout)
            
            # Check structure for CI tools
            assert isinstance(data["summary"]["vulnerable_dependencies"], int)
            assert isinstance(data["vulnerabilities"], list)
            
            # Each vulnerability should have parseable data
            for vuln in data.get("vulnerabilities", []):
                assert "dependency" in vuln
                assert "fix_command" in vuln
    
    def test_quiet_mode_simulation(self, temp_dir):
        """Test minimal output for CI environments"""
        # Create a simple project
        pkg_file = temp_dir / "package.json"
        pkg_file.write_text('{"dependencies": {"express": "4.17.1"}}')
        
        # Redirect stderr to suppress warnings
        scanner = SecScan()
        with patch('sys.stderr'):
            result = scanner.scan(temp_dir, output_format="json")
        
        # JSON output should be clean for parsing
        data = json.loads(result)
        assert data is not None


class TestErrorRecovery:
    """Test error recovery and resilience"""
    
    @patch('requests.post')
    def test_api_timeout_recovery(self, mock_post, temp_dir):
        """Test recovery from API timeouts"""
        import requests
        
        pkg_file = temp_dir / "package.json"
        pkg_file.write_text('{"dependencies": {"express": "4.17.1", "lodash": "4.17.20"}}')
        
        # Simulate timeout
        mock_post.side_effect = requests.exceptions.Timeout("Connection timeout")
        
        scanner = SecScan()
        result = scanner.scan(temp_dir)
        
        # Should complete scan despite API errors
        assert "Total Dependencies: 2" in result
    
    @patch('requests.post')
    def test_partial_api_failure(self, mock_post, temp_dir):
        """Test handling partial API failures"""
        pkg_file = temp_dir / "package.json"
        pkg_file.write_text('{"dependencies": {"express": "4.17.1", "lodash": "4.17.20"}}')
        
        # First call succeeds, second fails
        mock_resp = Mock()
        mock_resp.json.return_value = {"vulns": []}
        mock_resp.raise_for_status = Mock()
        
        mock_post.side_effect = [mock_resp, Exception("API Error")]
        
        scanner = SecScan()
        result = scanner.scan(temp_dir)
        
        # Should still show results
        assert "Total Dependencies: 2" in result
    
    def test_file_permission_recovery(self, temp_dir):
        """Test recovery from file permission issues"""
        import platform
        
        if platform.system() != "Windows":
            # Create restricted directory
            restricted_dir = temp_dir / "restricted"
            restricted_dir.mkdir()
            
            pkg_file = restricted_dir / "package.json"
            pkg_file.write_text('{"dependencies": {}}')
            
            # Remove read permissions
            os.chmod(restricted_dir, 0o000)
            
            try:
                scanner = SecScan()
                # Should handle permission error gracefully
                with pytest.raises(PermissionError):
                    scanner.scan(restricted_dir)
            finally:
                # Restore permissions
                os.chmod(restricted_dir, 0o755)


class TestMemoryUsage:
    """Test memory usage stays reasonable"""
    
    def test_memory_efficient_parsing(self, temp_dir):
        """Test memory usage with large files"""
        # Create a large package-lock.json
        lock_data = {
            "lockfileVersion": 2,
            "packages": {}
        }
        
        # Add many dependencies
        for i in range(1000):
            lock_data["packages"][f"node_modules/package-{i}"] = {
                "version": f"1.0.{i}",
                "resolved": f"https://registry.npmjs.org/package-{i}/-/package-{i}-1.0.{i}.tgz"
            }
        
        lock_file = temp_dir / "package-lock.json"
        with open(lock_file, 'w') as f:
            json.dump(lock_data, f)
        
        # Should parse without excessive memory usage
        import psutil
        import os
        
        process = psutil.Process(os.getpid())
        memory_before = process.memory_info().rss / 1024 / 1024  # MB
        
        scanner = SecScan()
        with patch('requests.post'):  # Mock API to focus on parsing
            result = scanner.scan(temp_dir)
        
        memory_after = process.memory_info().rss / 1024 / 1024  # MB
        memory_increase = memory_after - memory_before
        
        # Should not use more than 100MB for parsing
        assert memory_increase < 100
        assert "Total Dependencies: 1000" in result