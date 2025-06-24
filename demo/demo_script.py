#!/usr/bin/env python3
"""
Demo script for SecScan - shows various features and capabilities
"""
import subprocess
import sys
import json
import time
from pathlib import Path


class SecScanDemo:
    """Demo runner for SecScan"""
    
    def __init__(self):
        self.secscan_path = Path(__file__).parent.parent / "secscan.py"
        self.demo_projects = Path(__file__).parent / "vulnerable_projects"
    
    def run_command(self, args, description):
        """Run a command and display results"""
        print(f"\n{'='*60}")
        print(f"🎯 {description}")
        print(f"{'='*60}")
        print(f"Command: python secscan.py {' '.join(args)}")
        print("-" * 60)
        
        cmd = [sys.executable, str(self.secscan_path)] + args
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        print(result.stdout)
        if result.stderr:
            print("Errors:", result.stderr)
        
        return result
    
    def demo_basic_scans(self):
        """Demonstrate basic scanning across languages"""
        print("\n" + "🚀 " * 20)
        print("SECSCAN DEMO - Multi-Language Vulnerability Scanner")
        print("🚀 " * 20)
        
        # JavaScript scan
        js_project = str(self.demo_projects / "javascript")
        self.run_command(
            [js_project],
            "Scanning JavaScript Project (with vulnerable lodash & axios)"
        )
        time.sleep(1)
        
        # Python scan
        py_project = str(self.demo_projects / "python")
        self.run_command(
            [py_project],
            "Scanning Python Project (with vulnerable Django & Flask)"
        )
        time.sleep(1)
        
        # Go scan
        go_project = str(self.demo_projects / "go")
        self.run_command(
            [go_project],
            "Scanning Go Project (with vulnerable jwt-go)"
        )
        time.sleep(1)
    
    def demo_output_formats(self):
        """Demonstrate different output formats"""
        print("\n\n" + "📄 " * 20)
        print("OUTPUT FORMAT DEMONSTRATIONS")
        print("📄 " * 20)
        
        js_project = str(self.demo_projects / "javascript")
        
        # JSON format
        result = self.run_command(
            [js_project, "-f", "json"],
            "JSON Output Format (machine-readable)"
        )
        
        # Parse and show summary
        if result.returncode == 0:
            try:
                data = json.loads(result.stdout)
                print("\n📊 Parsed Summary:")
                print(f"  - Language: {data['language']}")
                print(f"  - Total Dependencies: {data['summary']['total_dependencies']}")
                print(f"  - Vulnerable: {data['summary']['vulnerable_dependencies']}")
                
                if data['vulnerabilities']:
                    print("\n  Found vulnerabilities in:")
                    for vuln in data['vulnerabilities']:
                        print(f"    - {vuln['dependency']['name']} v{vuln['dependency']['version']}")
            except json.JSONDecodeError:
                pass
    
    def demo_edge_cases(self):
        """Demonstrate edge case handling"""
        print("\n\n" + "⚠️  " * 20)
        print("EDGE CASE DEMONSTRATIONS")
        print("⚠️  " * 20)
        
        # Empty directory
        empty_project = str(self.demo_projects / "empty")
        self.run_command(
            [empty_project],
            "Scanning Empty Directory (no manifest files)"
        )
        
        # Corrupted manifest
        corrupted_project = str(self.demo_projects / "corrupted")
        self.run_command(
            [corrupted_project],
            "Scanning Corrupted Manifest File (Graceful Error Handling)"
        )
        
        # Mixed project
        mixed_project = str(self.demo_projects / "mixed")
        self.run_command(
            [mixed_project],
            "Scanning Mixed Project (JavaScript + Python)"
        )
    
    def demo_advanced_features(self):
        """Demonstrate advanced filtering and CI/CD features"""
        print("\n\n" + "🚀 " * 20)
        print("ADVANCED FEATURES DEMONSTRATIONS")
        print("🚀 " * 20)
        
        js_project = str(self.demo_projects / "javascript")
        py_project = str(self.demo_projects / "python")
        
        # CI Mode
        self.run_command(
            [js_project, "--ci"],
            "CI Mode - Minimal output for CI/CD pipelines"
        )
        time.sleep(1)
        
        # Statistics
        self.run_command(
            [js_project, "--stats", "-f", "text"],
            "Statistics - Detailed scan statistics with timing"
        )
        time.sleep(1)
        
        # Severity Filtering
        self.run_command(
            [js_project, "--severity", "high,critical", "-f", "text"],
            "Severity Filter - Show only HIGH and CRITICAL vulnerabilities"
        )
        time.sleep(1)
        
        # CVSS Score Filtering
        self.run_command(
            [js_project, "--cvss-min", "7.0", "-f", "text"],
            "CVSS Filter - Show only vulnerabilities with CVSS >= 7.0"
        )
        time.sleep(1)
        
        # Exploitable Filter
        self.run_command(
            [js_project, "--exploitable", "-f", "text"],
            "Exploitable - Show only vulnerabilities with known exploits"
        )
        time.sleep(1)
        
        # Has Fix Filter
        self.run_command(
            [js_project, "--has-fix", "-f", "text"],
            "Has Fix - Show only vulnerabilities with available fixes"
        )
        time.sleep(1)
        
        # Fail-On with Exit Codes
        result = self.run_command(
            [js_project, "--fail-on", "medium", "--ci"],
            "Fail-On Medium - Exit with error if MEDIUM+ vulnerabilities found"
        )
        print(f"\n💡 Exit code: {result.returncode} (1 = vulnerabilities found)")
        time.sleep(1)
        
        # Strict Mode
        result = self.run_command(
            [js_project, "--strict", "--ci"],
            "Strict Mode - Fail on ANY vulnerability"
        )
        print(f"\n💡 Exit code: {result.returncode} (1 = any vulnerabilities found)")
        time.sleep(1)
        
        # Threshold Limits
        self.run_command(
            [js_project, "--max-total", "3", "--verbose", "-f", "text"],
            "Threshold - Maximum 3 total vulnerabilities allowed"
        )
        time.sleep(1)
        
        # Policy String
        self.run_command(
            [js_project, "--policy", "medium<=2,cvss<7.0", "--verbose", "-f", "text"],
            "Policy String - Max 2 medium vulnerabilities, CVSS < 7.0"
        )
        time.sleep(1)
        
        # Policy File
        policy = {
            "rules": {
                "max_critical": 0,
                "max_high": 0,
                "max_medium": 5,
                "max_cvss_score": 6.0,
                "require_fixes_for": ["critical", "high"],
                "allow_exploitable": False
            }
        }
        policy_file = Path(__file__).parent / "demo-policy.json"
        policy_file.write_text(json.dumps(policy, indent=2))
        
        self.run_command(
            [js_project, "--policy-file", str(policy_file), "--verbose", "-f", "text"],
            "Policy File - Complex policy rules from JSON file"
        )
        
        # Combined Filters
        self.run_command(
            [js_project, "--has-fix", "--cvss-min", "4.0", "--max-total", "10", "--ci"],
            "Combined Filters - Multiple filters applied together"
        )
        time.sleep(1)
        
        # Python project with many vulnerabilities
        self.run_command(
            [py_project, "--stats", "--max-total", "50", "-f", "text"],
            "Large Scan - Python project with many vulnerabilities"
        )
        
        # Output to file
        output_file = Path(__file__).parent / "scan-results.json"
        self.run_command(
            [js_project, "-o", str(output_file), "-f", "json", "--verbose"],
            "Output to File - Save results as JSON"
        )
        
        if output_file.exists():
            print("\n📄 Saved results preview:")
            with open(output_file) as f:
                data = json.load(f)
                print(json.dumps(data, indent=2)[:300] + "...")
            output_file.unlink()
        
        # Clean up
        policy_file.unlink(missing_ok=True)
    
    def demo_caching_features(self):
        """Demonstrate intelligent caching system"""
        print("\n\n" + "💾 " * 20)
        print("CACHING SYSTEM DEMONSTRATIONS")
        print("💾 " * 20)
        
        js_project = str(self.demo_projects / "javascript")
        
        # Clear cache first
        self.run_command(
            ["--clear-cache"],
            "Clear Cache - Start with clean cache"
        )
        
        # First scan - builds cache
        print("\n⏱️  First scan (building cache)...")
        start = time.time()
        self.run_command(
            [js_project, "-f", "text"],
            "First Scan - Downloads and caches vulnerability data"
        )
        first_duration = time.time() - start
        print(f"Duration: {first_duration:.2f}s")
        
        # Second scan - uses cache
        print("\n⏱️  Second scan (using cache)...")
        start = time.time()
        self.run_command(
            [js_project, "-f", "text"],
            "Second Scan - Uses cached data for instant results"
        )
        second_duration = time.time() - start
        print(f"Duration: {second_duration:.2f}s")
        print(f"🚀 Speed improvement: {first_duration/second_duration:.1f}x faster!")
        
        # Cache stats
        self.run_command(
            ["--cache-stats"],
            "Cache Statistics - View cache size and age"
        )
        
        # Offline mode
        self.run_command(
            [js_project, "--offline", "--ci"],
            "Offline Mode - Use only cached data, no network calls"
        )
        
        # Force refresh
        self.run_command(
            [js_project, "--refresh-cache", "--ci"],
            "Force Refresh - Ignore cache TTL and fetch fresh data"
        )
    
    def generate_html_report(self):
        """Generate an HTML report of all scans"""
        print("\n\n" + "📊 " * 20)
        print("GENERATING HTML REPORT")
        print("📊 " * 20)
        
        html_content = """<!DOCTYPE html>
<html>
<head>
    <title>SecScan Vulnerability Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
        .container {{ background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 3px solid #007bff; padding-bottom: 10px; }}
        h2 {{ color: #555; margin-top: 30px; }}
        .project {{ margin: 20px 0; padding: 20px; background: #f8f9fa; border-radius: 5px; border-left: 4px solid #007bff; }}
        .stats {{ display: flex; gap: 20px; margin: 10px 0; }}
        .stat {{ background: #e9ecef; padding: 10px 20px; border-radius: 5px; }}
        .vulnerable {{ color: #dc3545; font-weight: bold; }}
        .safe {{ color: #28a745; font-weight: bold; }}
        .severity-critical {{ color: #dc3545; }}
        .severity-high {{ color: #fd7e14; }}
        .severity-medium {{ color: #ffc107; }}
        .severity-low {{ color: #007bff; }}
        pre {{ background: #f8f9fa; padding: 15px; border-radius: 5px; overflow-x: auto; }}
        .timestamp {{ color: #6c757d; font-size: 0.9em; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 SecScan Vulnerability Report</h1>
        <p class="timestamp">Generated: {timestamp}</p>
"""
        
        projects = ["javascript", "python", "go"]
        
        for lang in projects:
            project_path = str(self.demo_projects / lang)
            
            # Get JSON output
            cmd = [sys.executable, str(self.secscan_path), project_path, "-f", "json"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                try:
                    data = json.loads(result.stdout)
                    
                    vulnerable_class = "vulnerable" if data['summary']['vulnerable_dependencies'] > 0 else "safe"
                    
                    html_content += f"""
        <div class="project">
            <h2>📦 {lang.capitalize()} Project</h2>
            <div class="stats">
                <div class="stat">Language: <strong>{data['language']}</strong></div>
                <div class="stat">Total Dependencies: <strong>{data['summary']['total_dependencies']}</strong></div>
                <div class="stat">Vulnerable: <span class="{vulnerable_class}">{data['summary']['vulnerable_dependencies']}</span></div>
            </div>
"""
                    
                    if data['vulnerabilities']:
                        html_content += "<h3>Vulnerabilities Found:</h3><ul>"
                        for vuln in data['vulnerabilities']:
                            dep = vuln['dependency']
                            for v in vuln['vulnerabilities']:
                                severity_class = f"severity-{v['severity'].lower()}"
                                html_content += f"""
                <li>
                    <strong>{dep['name']} v{dep['version']}</strong>: 
                    <span class="{severity_class}">{v['severity']}</span> - {v['summary']}
                    <br>Fix: <code>{vuln['fix_command']}</code>
                </li>
"""
                        html_content += "</ul>"
                    else:
                        html_content += '<p class="safe">✅ No vulnerabilities found!</p>'
                    
                    html_content += "</div>"
                    
                except json.JSONDecodeError:
                    html_content += f'<div class="project"><h2>{lang.capitalize()} Project</h2><p>Error parsing results</p></div>'
        
        html_content += """
        <h2>📈 Summary</h2>
        <p>This report was generated by SecScan, a multi-language dependency vulnerability scanner that supports JavaScript (npm), Python (pip), and Go modules.</p>
        <p>For more information, run: <code>python secscan.py --help</code></p>
    </div>
</body>
</html>
"""
        
        # Write HTML report
        report_path = Path(__file__).parent / "vulnerability_report.html"
        report_path.write_text(html_content.format(
            timestamp=time.strftime("%Y-%m-%d %H:%M:%S")
        ))
        
        print(f"\n✅ HTML report generated: {report_path}")
        print(f"   Open in browser: file://{report_path.absolute()}")
    
    def run_full_demo(self):
        """Run the complete demo"""
        print("\n" + "🎬 " * 30)
        print("STARTING SECSCAN COMPREHENSIVE DEMO")
        print("🎬 " * 30)
        
        # Basic scans
        self.demo_basic_scans()
        
        # Output formats
        self.demo_output_formats()
        
        # Edge cases
        self.demo_edge_cases()
        
        # Advanced features
        self.demo_advanced_features()
        
        # Caching features
        self.demo_caching_features()
        
        # Generate report
        self.generate_html_report()
        
        print("\n\n" + "✨ " * 30)
        print("DEMO COMPLETE!")
        print("✨ " * 30)
        print("\nKey Features Demonstrated:")
        print("✅ Multi-language support (JavaScript, Python, Go)")
        print("✅ Automatic language detection")
        print("✅ OSV.dev vulnerability database integration")
        print("✅ Multiple output formats (text, JSON)")
        print("✅ Language-specific fix commands")
        print("✅ Graceful error handling")
        print("✅ HTML report generation")
        print("\n🚀 Advanced Features:")
        print("✅ CI/CD mode with minimal output")
        print("✅ Detailed statistics with timing")
        print("✅ Advanced severity filtering")
        print("✅ CVSS score filtering")
        print("✅ Exploit detection")
        print("✅ Fix availability filtering")
        print("✅ Smart exit codes for CI/CD")
        print("✅ Threshold limits and policies")
        print("✅ Combined filter support")
        print("\n💾 Caching Features:")
        print("✅ Multi-level cache structure (~/.secscan/cache/)")
        print("✅ Intelligent vulnerability database caching")
        print("✅ Scan result caching by manifest hash")
        print("✅ Offline mode support")
        print("✅ Cache management commands")
        print("✅ Automatic cache invalidation")
        print("✅ Significant performance improvements")
        
        print("\nExample Commands:")
        print("  # Basic scan")
        print("  python secscan.py /path/to/project")
        print("\n  # CI/CD integration")
        print("  python secscan.py /path/to/project --ci --fail-on high")
        print("\n  # Advanced filtering")
        print("  python secscan.py /path/to/project --exploitable --cvss-min 7.0")
        print("\n  # Policy enforcement")
        print("  python secscan.py /path/to/project --policy 'critical=0,high<=3'")
        print("\n  # Caching operations")
        print("  python secscan.py /path/to/project --offline  # Use cached data only")
        print("  python secscan.py --cache-stats               # View cache statistics")
        print("  python secscan.py --clear-cache               # Clear all cache")
        print("\nFor help: python secscan.py --help")


if __name__ == "__main__":
    demo = SecScanDemo()
    demo.run_full_demo()