#!/bin/bash

# SecScan Comprehensive Test Runner
# This script runs all tests and generates a validation report

echo "=================================================="
echo "🧪 SecScan Test Suite Runner"
echo "=================================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test counters
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0
START_TIME=$(date +%s)

# Create test results directory
RESULTS_DIR="test_results_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$RESULTS_DIR"

# Function to run a test module
run_test_module() {
    local module=$1
    local description=$2
    
    echo -e "\n${BLUE}Running $description...${NC}"
    echo "----------------------------------------"
    
    # Run pytest with coverage
    if python -m pytest "tests/$module" -v --tb=short > "$RESULTS_DIR/${module%.py}_output.txt" 2>&1; then
        echo -e "${GREEN}✓ $description passed${NC}"
        ((PASSED_TESTS++))
    else
        echo -e "${RED}✗ $description failed${NC}"
        ((FAILED_TESTS++))
        echo "  See $RESULTS_DIR/${module%.py}_output.txt for details"
    fi
    ((TOTAL_TESTS++))
}

# Check dependencies
echo "Checking test dependencies..."
python -c "import pytest" 2>/dev/null || {
    echo -e "${RED}Error: pytest not installed. Run: pip install pytest${NC}"
    exit 1
}

# Run individual test modules
run_test_module "test_cli.py" "CLI Tests"
run_test_module "test_scanner.py" "Scanner Core Tests"
run_test_module "test_parsers.py" "Parser Tests"
run_test_module "test_integration.py" "Integration Tests"

# Run performance benchmarks
echo -e "\n${BLUE}Running Performance Benchmarks...${NC}"
echo "----------------------------------------"
python -m pytest tests/test_integration.py::TestPerformanceBenchmarks -v > "$RESULTS_DIR/performance_output.txt" 2>&1

# Check if performance tests passed
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Performance benchmarks passed${NC}"
    
    # Extract performance metrics
    echo -e "\n${YELLOW}Performance Metrics:${NC}"
    grep -E "(test.*performance|elapsed|seconds)" "$RESULTS_DIR/performance_output.txt" | tail -5
else
    echo -e "${RED}✗ Performance benchmarks failed${NC}"
fi

# Test with real vulnerable projects
echo -e "\n${BLUE}Testing with vulnerable demo projects...${NC}"
echo "----------------------------------------"

for lang in javascript python go; do
    if [ -d "demo/vulnerable_projects/$lang" ]; then
        echo -n "Testing $lang project... "
        if python secscan.py "demo/vulnerable_projects/$lang" > "$RESULTS_DIR/demo_${lang}_scan.txt" 2>&1; then
            echo -e "${GREEN}✓${NC}"
        else
            echo -e "${RED}✗${NC}"
        fi
    fi
done

# Generate coverage report if coverage.py is installed
if python -c "import coverage" 2>/dev/null; then
    echo -e "\n${BLUE}Generating coverage report...${NC}"
    echo "----------------------------------------"
    
    python -m coverage run -m pytest tests/ -q
    python -m coverage report > "$RESULTS_DIR/coverage_report.txt"
    python -m coverage html -d "$RESULTS_DIR/coverage_html"
    
    echo "Coverage report saved to $RESULTS_DIR/coverage_report.txt"
    echo "HTML coverage report: $RESULTS_DIR/coverage_html/index.html"
    
    # Show coverage summary
    echo -e "\n${YELLOW}Coverage Summary:${NC}"
    python -m coverage report | grep -E "(TOTAL|secscan\.py)" | tail -2
else
    echo -e "\n${YELLOW}Note: Install coverage.py for code coverage reports: pip install coverage${NC}"
fi

# Memory usage test
echo -e "\n${BLUE}Checking memory usage...${NC}"
echo "----------------------------------------"

if python -c "import psutil" 2>/dev/null; then
    python -c "
import psutil
import os
process = psutil.Process(os.getpid())
print(f'Current memory usage: {process.memory_info().rss / 1024 / 1024:.2f} MB')
"
else
    echo "Install psutil for memory monitoring: pip install psutil"
fi

# Calculate elapsed time
END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))

# Generate final report
REPORT_FILE="$RESULTS_DIR/test_summary.txt"
{
    echo "SecScan Test Suite Summary"
    echo "=========================="
    echo "Date: $(date)"
    echo "Duration: ${ELAPSED} seconds"
    echo ""
    echo "Test Results:"
    echo "-------------"
    echo "Total Test Modules: $TOTAL_TESTS"
    echo "Passed: $PASSED_TESTS"
    echo "Failed: $FAILED_TESTS"
    echo ""
    
    if [ $FAILED_TESTS -eq 0 ]; then
        echo "Status: ALL TESTS PASSED ✅"
    else
        echo "Status: SOME TESTS FAILED ❌"
        echo ""
        echo "Failed modules:"
        grep -l "FAILED" "$RESULTS_DIR"/*_output.txt 2>/dev/null | while read -r file; do
            echo "  - $(basename "$file" _output.txt)"
        done
    fi
    
    echo ""
    echo "Potential Issues Found:"
    echo "----------------------"
    
    # Check for common issues
    grep -h "DeprecationWarning\|FutureWarning" "$RESULTS_DIR"/*.txt 2>/dev/null | sort -u | head -5
    
    # Check for slow tests
    echo ""
    echo "Slow Tests (>1s):"
    grep -h "PASSED.*[1-9][0-9]*\.[0-9][0-9]s" "$RESULTS_DIR"/*.txt 2>/dev/null | sort -k2 -nr | head -5
    
} > "$REPORT_FILE"

# Display summary
echo ""
echo "=================================================="
echo -e "${BLUE}TEST SUITE COMPLETE${NC}"
echo "=================================================="
echo ""
cat "$REPORT_FILE"

echo ""
echo "Full test results saved to: $RESULTS_DIR/"
echo "Test summary: $REPORT_FILE"

# Exit with appropriate code
if [ $FAILED_TESTS -eq 0 ]; then
    exit 0
else
    exit 1
fi