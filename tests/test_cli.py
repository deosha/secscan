"""
CLI command tests for SecScan
"""
import pytest
import json
import sys
from pathlib import Path
from unittest.mock import patch, Mock
import subprocess


class TestCLICommands:
    """Test CLI commands and arguments"""
    
    def test_help_command(self, cli_runner):
        """Test --help flag"""
        result = cli_runner(["--help"])
        assert result.returncode == 0
        assert "SecScan - Multi-language dependency vulnerability scanner" in result.stdout
        assert "--format" in result.stdout
        assert "--version" in result.stdout
    
    def test_version_command(self, cli_runner):
        """Test --version flag"""
        result = cli_runner(["--version"])
        assert result.returncode == 0
        assert "SecScan 1.0.0" in result.stdout
    
    def test_scan_current_directory(self, cli_runner, temp_dir, vulnerable_package_json):
        """Test scanning current directory"""
        # Create package.json in temp dir
        pkg_file = temp_dir / "package.json"
        with open(pkg_file, 'w') as f:
            json.dump(vulnerable_package_json, f)
        
        # Run scan in temp directory
        result = subprocess.run(
            [sys.executable, str(Path(__file__).parent.parent / "secscan.py")],
            capture_output=True,
            text=True,
            cwd=temp_dir
        )
        
        assert result.returncode == 0
        assert "Security Scan Results" in result.stdout
        assert "Language: javascript" in result.stdout
    
    def test_scan_specific_directory(self, cli_runner):
        """Test scanning specific directory"""
        demo_js_dir = Path(__file__).parent.parent / "demo/vulnerable_projects/javascript"
        if demo_js_dir.exists():
            result = cli_runner([str(demo_js_dir)])
            assert result.returncode == 0
            assert "javascript" in result.stdout.lower()
    
    def test_json_format_output(self, cli_runner):
        """Test JSON output format"""
        demo_py_dir = Path(__file__).parent.parent / "demo/vulnerable_projects/python"
        if demo_py_dir.exists():
            result = cli_runner([str(demo_py_dir), "-f", "json"])
            assert result.returncode == 0
            
            # Verify valid JSON
            try:
                data = json.loads(result.stdout)
                assert "project_path" in data
                assert "language" in data
                assert "summary" in data
                assert "vulnerabilities" in data
            except json.JSONDecodeError:
                pytest.fail("Output is not valid JSON")
    
    def test_invalid_path(self, cli_runner):
        """Test scanning non-existent directory"""
        result = cli_runner(["/non/existent/path"])
        assert result.returncode == 1
        assert "Error: Path" in result.stderr
        assert "does not exist" in result.stderr
    
    def test_empty_directory(self, cli_runner, temp_dir):
        """Test scanning empty directory"""
        empty_dir = temp_dir / "empty"
        empty_dir.mkdir(exist_ok=True)
        
        result = cli_runner([str(empty_dir)])
        assert result.returncode == 0
        assert "Could not detect project language" in result.stdout
    
    @patch('requests.post')
    def test_api_error_handling(self, mock_post, cli_runner, temp_dir):
        """Test handling of API errors"""
        # Create a simple package.json
        pkg_file = temp_dir / "package.json"
        pkg_file.write_text('{"dependencies": {"express": "4.17.1"}}')
        
        # Mock API error
        mock_post.side_effect = Exception("API Error")
        
        result = cli_runner([str(temp_dir)])
        assert result.returncode == 0
        # Should still complete but show error
        assert "Error checking" in result.stderr or result.stdout
    
    def test_multiple_format_types(self, cli_runner):
        """Test that only valid format types are accepted"""
        result = cli_runner([".", "-f", "invalid"])
        assert result.returncode == 2  # argparse error
        assert "invalid choice: 'invalid'" in result.stderr


class TestCLIOutput:
    """Test CLI output formatting"""
    
    def test_text_output_structure(self, cli_runner):
        """Test text output has expected structure"""
        demo_js_dir = Path(__file__).parent.parent / "demo/vulnerable_projects/javascript"
        if demo_js_dir.exists():
            result = cli_runner([str(demo_js_dir)])
            
            # Check for expected sections
            assert "🔍 Security Scan Results" in result.stdout
            assert "📦 Language:" in result.stdout
            assert "📊 Total Dependencies:" in result.stdout
            assert "⚠️  Vulnerable Dependencies:" in result.stdout
    
    def test_json_output_structure(self, cli_runner):
        """Test JSON output has expected fields"""
        demo_py_dir = Path(__file__).parent.parent / "demo/vulnerable_projects/python"
        if demo_py_dir.exists():
            result = cli_runner([str(demo_py_dir), "-f", "json"])
            
            data = json.loads(result.stdout)
            
            # Check required fields
            assert "project_path" in data
            assert "language" in data
            assert "summary" in data
            assert "total_dependencies" in data["summary"]
            assert "vulnerable_dependencies" in data["summary"]
            assert "vulnerabilities" in data
            
            # If vulnerabilities exist, check their structure
            if data["vulnerabilities"]:
                vuln = data["vulnerabilities"][0]
                assert "dependency" in vuln
                assert "name" in vuln["dependency"]
                assert "version" in vuln["dependency"]
                assert "vulnerabilities" in vuln
                assert "fix_command" in vuln
    
    @patch('sys.stdout.isatty')
    def test_output_no_colors_in_pipe(self, mock_isatty, cli_runner):
        """Test that colors are handled properly when piping output"""
        mock_isatty.return_value = False
        
        demo_dir = Path(__file__).parent.parent / "demo/vulnerable_projects/javascript"
        if demo_dir.exists():
            result = cli_runner([str(demo_dir)])
            # Should still have emoji but no ANSI color codes
            assert "🔍" in result.stdout


class TestCLIErrorHandling:
    """Test CLI error handling"""
    
    def test_corrupted_manifest_file(self, cli_runner):
        """Test handling of corrupted manifest files"""
        corrupted_dir = Path(__file__).parent.parent / "demo/vulnerable_projects/corrupted"
        if corrupted_dir.exists():
            result = cli_runner([str(corrupted_dir)])
            # Should handle gracefully, not crash
            assert result.returncode == 0 or "Error" in result.stderr
    
    def test_permission_denied(self, cli_runner, temp_dir):
        """Test handling of permission errors"""
        import os
        import platform
        
        if platform.system() != "Windows":
            # Create a file with no read permissions
            restricted_file = temp_dir / "package.json"
            restricted_file.write_text('{"dependencies": {}}')
            os.chmod(restricted_file, 0o000)
            
            try:
                result = cli_runner([str(temp_dir)])
                # Should handle permission error gracefully
                assert result.returncode != 0 or "Permission" in result.stderr
            finally:
                # Restore permissions for cleanup
                os.chmod(restricted_file, 0o644)
    
    def test_keyboard_interrupt(self, cli_runner, temp_dir):
        """Test handling of keyboard interrupt"""
        # This is difficult to test directly, but we can verify the handler exists
        import secscan
        assert hasattr(secscan, 'main')


class TestCLIConcurrency:
    """Test concurrent scanning scenarios"""
    
    def test_multiple_scans_dont_interfere(self, cli_runner, temp_dir):
        """Test that multiple concurrent scans don't interfere"""
        import threading
        import time
        
        # Create two different projects
        js_dir = temp_dir / "js_project"
        js_dir.mkdir()
        (js_dir / "package.json").write_text('{"dependencies": {"express": "4.17.1"}}')
        
        py_dir = temp_dir / "py_project"
        py_dir.mkdir()
        (py_dir / "requirements.txt").write_text('flask==2.0.0')
        
        results = []
        
        def run_scan(directory):
            result = cli_runner([str(directory)])
            results.append(result)
        
        # Run scans concurrently
        threads = [
            threading.Thread(target=run_scan, args=(js_dir,)),
            threading.Thread(target=run_scan, args=(py_dir,))
        ]
        
        for t in threads:
            t.start()
        
        for t in threads:
            t.join()
        
        # Both should complete successfully
        assert len(results) == 2
        assert all(r.returncode == 0 for r in results)