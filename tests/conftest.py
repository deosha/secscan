"""
Shared fixtures and utilities for tests
"""
import pytest
import tempfile
import json
import shutil
from pathlib import Path
from unittest.mock import Mock, patch
import time


@pytest.fixture
def temp_dir():
    """Create a temporary directory for tests"""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def mock_osv_response():
    """Mock OSV API response with vulnerabilities"""
    def _mock_response(vulnerabilities=None):
        if vulnerabilities is None:
            vulnerabilities = [
                {
                    "id": "CVE-2021-23337",
                    "summary": "Command Injection in lodash",
                    "details": "Lodash versions prior to 4.17.21 are vulnerable to Command Injection",
                    "severity": [{
                        "type": "CVSS_V3",
                        "score": 7.2
                    }],
                    "affected": [{
                        "package": {"name": "lodash"},
                        "ranges": [{
                            "events": [
                                {"introduced": "0"},
                                {"fixed": "4.17.21"}
                            ]
                        }]
                    }],
                    "references": [{"url": "https://nvd.nist.gov/vuln/detail/CVE-2021-23337"}]
                }
            ]
        
        mock_resp = Mock()
        mock_resp.json.return_value = {"vulns": vulnerabilities}
        mock_resp.raise_for_status = Mock()
        return mock_resp
    
    return _mock_response


@pytest.fixture
def vulnerable_package_json():
    """Create a package.json with vulnerable dependencies"""
    return {
        "name": "test-vulnerable-js",
        "version": "1.0.0",
        "dependencies": {
            "lodash": "4.17.20",
            "axios": "0.21.0",
            "express": "4.18.2"
        },
        "devDependencies": {
            "jest": "27.0.0"
        }
    }


@pytest.fixture
def vulnerable_requirements_txt():
    """Create a requirements.txt with vulnerable dependencies"""
    return """# Vulnerable Python packages
django==2.2.0
flask==0.12.2
requests==2.25.1
numpy==1.19.0
pandas==1.2.0
"""


@pytest.fixture
def vulnerable_go_mod():
    """Create a go.mod with vulnerable dependencies"""
    return """module github.com/test/vulnerable-go

go 1.19

require (
    github.com/dgrijalva/jwt-go v3.2.0+incompatible
    github.com/gin-gonic/gin v1.7.0
    github.com/stretchr/testify v1.7.0
)

require (
    github.com/go-playground/validator/v10 v10.4.1 // indirect
)
"""


@pytest.fixture
def sample_projects(temp_dir):
    """Create sample project directories with various configurations"""
    projects = {}
    
    # JavaScript project
    js_dir = temp_dir / "javascript"
    js_dir.mkdir()
    projects['javascript'] = js_dir
    
    # Python project
    py_dir = temp_dir / "python"
    py_dir.mkdir()
    projects['python'] = py_dir
    
    # Go project
    go_dir = temp_dir / "go"
    go_dir.mkdir()
    projects['go'] = go_dir
    
    # Mixed project
    mixed_dir = temp_dir / "mixed"
    mixed_dir.mkdir()
    projects['mixed'] = mixed_dir
    
    # Empty project
    empty_dir = temp_dir / "empty"
    empty_dir.mkdir()
    projects['empty'] = empty_dir
    
    # Corrupted project
    corrupted_dir = temp_dir / "corrupted"
    corrupted_dir.mkdir()
    projects['corrupted'] = corrupted_dir
    
    return projects


@pytest.fixture
def mock_requests_post():
    """Mock requests.post for API calls"""
    with patch('requests.post') as mock_post:
        yield mock_post


@pytest.fixture
def capture_output():
    """Capture stdout and stderr"""
    import io
    import sys
    
    class OutputCapture:
        def __init__(self):
            self.stdout = io.StringIO()
            self.stderr = io.StringIO()
            self._stdout = sys.stdout
            self._stderr = sys.stderr
        
        def __enter__(self):
            sys.stdout = self.stdout
            sys.stderr = self.stderr
            return self
        
        def __exit__(self, *args):
            sys.stdout = self._stdout
            sys.stderr = self._stderr
    
    return OutputCapture


@pytest.fixture
def performance_timer():
    """Simple performance timer"""
    class Timer:
        def __init__(self):
            self.start_time = None
            self.end_time = None
        
        def start(self):
            self.start_time = time.time()
        
        def stop(self):
            self.end_time = time.time()
        
        @property
        def elapsed(self):
            if self.start_time and self.end_time:
                return self.end_time - self.start_time
            return None
    
    return Timer()


@pytest.fixture
def cli_runner():
    """Run CLI commands and capture output"""
    def _run_cli(args):
        import subprocess
        import sys
        
        cmd = [sys.executable, "secscan.py"] + args
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent.parent
        )
        return result
    
    return _run_cli


# Utility functions
def create_manifest_file(path: Path, filename: str, content: str):
    """Create a manifest file with given content"""
    file_path = path / filename
    file_path.write_text(content)
    return file_path


def create_json_file(path: Path, filename: str, data: dict):
    """Create a JSON file with given data"""
    file_path = path / filename
    with open(file_path, 'w') as f:
        json.dump(data, f, indent=2)
    return file_path