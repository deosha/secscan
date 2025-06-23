#!/usr/bin/env python3
"""
Test validation script - validates test coverage and quality
"""
import os
import sys
import ast
import json
from pathlib import Path
from collections import defaultdict


class TestValidator:
    """Validates test suite completeness and quality"""
    
    def __init__(self):
        self.tests_dir = Path(__file__).parent
        self.src_file = self.tests_dir.parent / "secscan.py"
        self.issues = []
        self.stats = defaultdict(int)
    
    def validate_all(self):
        """Run all validations"""
        print("🔍 SecScan Test Suite Validation")
        print("=" * 50)
        
        # Check test files exist
        self.check_test_files()
        
        # Analyze test coverage
        self.analyze_test_coverage()
        
        # Check test quality
        self.check_test_quality()
        
        # Validate fixtures
        self.validate_fixtures()
        
        # Check demo projects
        self.check_demo_projects()
        
        # Generate report
        self.generate_report()
    
    def check_test_files(self):
        """Check that all required test files exist"""
        required_files = [
            "conftest.py",
            "test_cli.py",
            "test_scanner.py",
            "test_parsers.py",
            "test_integration.py"
        ]
        
        print("\n📁 Checking test files...")
        for file in required_files:
            file_path = self.tests_dir / file
            if file_path.exists():
                self.stats['test_files'] += 1
                print(f"  ✓ {file}")
            else:
                self.issues.append(f"Missing test file: {file}")
                print(f"  ✗ {file} (missing)")
    
    def analyze_test_coverage(self):
        """Analyze which components are tested"""
        print("\n📊 Analyzing test coverage...")
        
        # Parse source file to find classes and functions
        with open(self.src_file, 'r') as f:
            tree = ast.parse(f.read())
        
        source_items = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                source_items.add(f"class:{node.name}")
            elif isinstance(node, ast.FunctionDef):
                if not node.name.startswith('_'):
                    source_items.add(f"func:{node.name}")
        
        # Check what's tested
        tested_items = set()
        for test_file in self.tests_dir.glob("test_*.py"):
            with open(test_file, 'r') as f:
                content = f.read()
                
                # Look for imports and references
                for item in source_items:
                    item_type, item_name = item.split(':')
                    if item_name in content:
                        tested_items.add(item)
        
        coverage_percent = (len(tested_items) / len(source_items) * 100) if source_items else 0
        self.stats['coverage_percent'] = coverage_percent
        
        print(f"  Source items: {len(source_items)}")
        print(f"  Tested items: {len(tested_items)}")
        print(f"  Coverage: {coverage_percent:.1f}%")
        
        # Report untested items
        untested = source_items - tested_items
        if untested:
            print("\n  ⚠️  Potentially untested components:")
            for item in sorted(untested)[:5]:
                print(f"    - {item}")
            if len(untested) > 5:
                print(f"    ... and {len(untested) - 5} more")
    
    def check_test_quality(self):
        """Check test quality metrics"""
        print("\n🎯 Checking test quality...")
        
        total_tests = 0
        total_assertions = 0
        test_files = list(self.tests_dir.glob("test_*.py"))
        
        for test_file in test_files:
            with open(test_file, 'r') as f:
                content = f.read()
                
            # Count test methods
            test_count = content.count("def test_")
            total_tests += test_count
            
            # Count assertions
            assertion_count = (
                content.count("assert ") +
                content.count("pytest.raises") +
                content.count("pytest.fail")
            )
            total_assertions += assertion_count
            
            print(f"  {test_file.name}: {test_count} tests, {assertion_count} assertions")
        
        self.stats['total_tests'] = total_tests
        self.stats['total_assertions'] = total_assertions
        
        avg_assertions = total_assertions / total_tests if total_tests else 0
        print(f"\n  Total: {total_tests} tests, {total_assertions} assertions")
        print(f"  Average assertions per test: {avg_assertions:.1f}")
        
        if avg_assertions < 1:
            self.issues.append("Low assertion density - tests may not be thorough")
    
    def validate_fixtures(self):
        """Validate test fixtures"""
        print("\n🔧 Validating fixtures...")
        
        conftest_path = self.tests_dir / "conftest.py"
        if conftest_path.exists():
            with open(conftest_path, 'r') as f:
                content = f.read()
            
            # Count fixtures
            fixture_count = content.count("@pytest.fixture")
            self.stats['fixtures'] = fixture_count
            
            print(f"  Found {fixture_count} fixtures")
            
            # Check for important fixtures
            important_fixtures = [
                "temp_dir",
                "mock_osv_response",
                "vulnerable_package_json",
                "cli_runner"
            ]
            
            for fixture in important_fixtures:
                if f"def {fixture}" in content:
                    print(f"  ✓ {fixture}")
                else:
                    print(f"  ⚠️  Missing fixture: {fixture}")
    
    def check_demo_projects(self):
        """Check demo vulnerable projects"""
        print("\n📦 Checking demo projects...")
        
        demo_dir = self.tests_dir.parent / "demo" / "vulnerable_projects"
        if not demo_dir.exists():
            self.issues.append("Demo directory not found")
            return
        
        expected_projects = {
            "javascript": ["package.json"],
            "python": ["requirements.txt"],
            "go": ["go.mod"],
            "mixed": ["package.json", "requirements.txt"],
            "empty": [],
            "corrupted": ["package.json"]
        }
        
        for project, expected_files in expected_projects.items():
            project_dir = demo_dir / project
            if project_dir.exists():
                print(f"  ✓ {project}/")
                for file in expected_files:
                    if (project_dir / file).exists():
                        print(f"    ✓ {file}")
                    else:
                        print(f"    ✗ {file} (missing)")
                        self.issues.append(f"Missing {project}/{file}")
            else:
                print(f"  ✗ {project}/ (missing)")
                self.issues.append(f"Missing demo project: {project}")
    
    def generate_report(self):
        """Generate validation report"""
        print("\n" + "=" * 50)
        print("📋 VALIDATION REPORT")
        print("=" * 50)
        
        # Summary stats
        print("\n📊 Summary Statistics:")
        print(f"  Test files: {self.stats['test_files']}")
        print(f"  Total tests: {self.stats['total_tests']}")
        print(f"  Total assertions: {self.stats['total_assertions']}")
        print(f"  Test fixtures: {self.stats['fixtures']}")
        print(f"  Coverage estimate: {self.stats['coverage_percent']:.1f}%")
        
        # Quality metrics
        print("\n✅ Quality Metrics:")
        if self.stats['total_tests'] > 50:
            print("  ✓ Good test quantity (50+ tests)")
        else:
            print("  ⚠️  Consider adding more tests")
        
        if self.stats['coverage_percent'] > 70:
            print("  ✓ Good coverage estimate")
        else:
            print("  ⚠️  Consider improving test coverage")
        
        # Issues found
        if self.issues:
            print(f"\n⚠️  Issues Found ({len(self.issues)}):")
            for issue in self.issues[:10]:
                print(f"  - {issue}")
            if len(self.issues) > 10:
                print(f"  ... and {len(self.issues) - 10} more")
        else:
            print("\n✅ No major issues found!")
        
        # Recommendations
        print("\n💡 Recommendations:")
        if self.stats['total_tests'] < 100:
            print("  - Add more edge case tests")
        if self.stats['coverage_percent'] < 80:
            print("  - Improve test coverage for untested components")
        if not (self.tests_dir.parent / "demo" / "demo_script.py").exists():
            print("  - Create demo script for showcasing features")
        
        # Save report
        report_data = {
            "stats": dict(self.stats),
            "issues": self.issues,
            "test_files": len(list(self.tests_dir.glob("test_*.py"))),
            "demo_projects": len(list((self.tests_dir.parent / "demo" / "vulnerable_projects").glob("*")))
            if (self.tests_dir.parent / "demo" / "vulnerable_projects").exists() else 0
        }
        
        report_path = self.tests_dir / "validation_report.json"
        with open(report_path, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        print(f"\n📄 Full report saved to: {report_path}")
        
        # Return status
        return len(self.issues) == 0


def main():
    """Run validation"""
    validator = TestValidator()
    success = validator.validate_all()
    
    print("\n" + "=" * 50)
    if success:
        print("✅ TEST SUITE VALIDATION PASSED!")
        sys.exit(0)
    else:
        print("❌ TEST SUITE VALIDATION FAILED - See issues above")
        sys.exit(1)


if __name__ == "__main__":
    main()