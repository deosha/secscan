#!/usr/bin/env python3
"""
Example implementation of severity filtering feature for SecScan v1.1.0
This shows how to add --min-severity and --fail-on options
"""

# Add to argument parser in main():
parser.add_argument(
    "--min-severity",
    choices=["low", "medium", "high", "critical"],
    default="low",
    help="Minimum severity level to report (default: low)"
)
parser.add_argument(
    "--fail-on",
    choices=["low", "medium", "high", "critical"],
    help="Exit with code 1 if vulnerabilities at or above this severity are found"
)

# Add severity filtering to OutputFormatter class:
def filter_by_severity(result: ScanResult, min_severity: str) -> ScanResult:
    """Filter vulnerabilities by minimum severity level"""
    severity_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    min_level = severity_order.get(min_severity.lower(), 0)
    
    filtered_deps = []
    vulnerable_count = 0
    
    for dep in result.dependencies:
        filtered_vulns = []
        for vuln in dep.vulnerabilities:
            vuln_level = severity_order.get(vuln.severity.value.lower(), 0)
            if vuln_level >= min_level:
                filtered_vulns.append(vuln)
        
        if filtered_vulns:
            dep.vulnerabilities = filtered_vulns
            filtered_deps.append(dep)
            vulnerable_count += 1
        elif not dep.vulnerabilities:
            # Keep deps without vulnerabilities
            filtered_deps.append(dep)
    
    return ScanResult(
        project_path=result.project_path,
        language=result.language,
        dependencies=filtered_deps,
        vulnerable_count=vulnerable_count,
        total_count=result.total_count
    )

# In main(), after scanning:
if args.min_severity:
    result = filter_by_severity(result, args.min_severity)

# Check fail condition:
if args.fail_on:
    severity_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    fail_level = severity_order.get(args.fail_on.lower(), 0)
    
    for dep in result.dependencies:
        for vuln in dep.vulnerabilities:
            vuln_level = severity_order.get(vuln.severity.value.lower(), 0)
            if vuln_level >= fail_level:
                print(f"\n❌ Found {vuln.severity.value} severity vulnerability!", file=sys.stderr)
                sys.exit(1)