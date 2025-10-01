#!/bin/bash

# JSIMConnect Build Test Suite
# Tests the JSIMConnect (MSFS2020 integration) build process and functionality

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test configuration
TEST_RESULTS_DIR="test_results"
BUILD_DIR="build"

# Create directories
mkdir -p $TEST_RESULTS_DIR $BUILD_DIR

echo -e "${BLUE}=== JSIMConnect Build Test Suite ===${NC}"
echo "Testing JSIMConnect (MSFS2020 integration) build process and functionality"
echo ""

# Function to print section headers
print_section() {
    echo -e "\n${YELLOW}=== $1 ===${NC}"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check required tools
print_section "Checking Required Tools"

REQUIRED_TOOLS=("git" "mvn" "java" "make")
MISSING_TOOLS=()

for tool in "${REQUIRED_TOOLS[@]}"; do
    if command_exists "$tool"; then
        echo -e "${GREEN}✓${NC} $tool found"
    else
        echo -e "${RED}✗${NC} $tool not found"
        MISSING_TOOLS+=("$tool")
    fi
done

if [ ${#MISSING_TOOLS[@]} -ne 0 ]; then
    echo -e "${RED}Missing required tools: ${MISSING_TOOLS[*]}${NC}"
    echo "Please install missing tools before running tests"
    exit 1
fi

# Test 1: Check Git Submodule Status
print_section "Testing Git Submodule Status"

echo "Checking if jsimconnect submodule is properly initialized..."
cd /home/haaken/github-projects/fgcom-mumble

if git submodule status | grep -q "client/radioGUI/lib/jsimconnect"; then
    echo -e "${GREEN}✓${NC} jsimconnect submodule is registered"
    
    # Check if submodule is properly checked out (no - prefix)
    if git submodule status | grep "client/radioGUI/lib/jsimconnect" | grep -q "^ "; then
        echo -e "${GREEN}✓${NC} jsimconnect submodule is properly checked out"
        JSIMCONNECT_SUBMODULE_OK=true
    else
        echo -e "${RED}✗${NC} jsimconnect submodule is not properly checked out"
        JSIMCONNECT_SUBMODULE_OK=false
    fi
else
    echo -e "${RED}✗${NC} jsimconnect submodule is not registered"
    JSIMCONNECT_SUBMODULE_OK=false
fi

# Test 2: Check JSIMConnect Directory Structure
print_section "Testing JSIMConnect Directory Structure"

JSIMCONNECT_DIR="/home/haaken/github-projects/fgcom-mumble/client/radioGUI/lib/jsimconnect"

if [ -d "$JSIMCONNECT_DIR" ]; then
    echo -e "${GREEN}✓${NC} jsimconnect directory exists"
    
    # Check for essential files
    ESSENTIAL_FILES=("pom.xml" "src/main/java" "README.md" "LICENSE")
    for file in "${ESSENTIAL_FILES[@]}"; do
        if [ -e "$JSIMCONNECT_DIR/$file" ]; then
            echo -e "${GREEN}✓${NC} $file exists"
        else
            echo -e "${RED}✗${NC} $file missing"
        fi
    done
    
    JSIMCONNECT_STRUCTURE_OK=true
else
    echo -e "${RED}✗${NC} jsimconnect directory does not exist"
    JSIMCONNECT_STRUCTURE_OK=false
fi

# Test 3: Test Maven Build of JSIMConnect
print_section "Testing Maven Build of JSIMConnect"

if [ "$JSIMCONNECT_STRUCTURE_OK" = true ]; then
    echo "Building jsimconnect with Maven..."
    cd "$JSIMCONNECT_DIR"
    
    # Clean and build
    if mvn clean package -q; then
        echo -e "${GREEN}✓${NC} jsimconnect Maven build successful"
        
        # Check if JAR was created
        if [ -f "target/jsimconnect-0.8.0.jar" ]; then
            echo -e "${GREEN}✓${NC} jsimconnect JAR file created"
            JSIMCONNECT_BUILD_OK=true
        else
            echo -e "${RED}✗${NC} jsimconnect JAR file not created"
            JSIMCONNECT_BUILD_OK=false
        fi
    else
        echo -e "${RED}✗${NC} jsimconnect Maven build failed"
        JSIMCONNECT_BUILD_OK=false
    fi
else
    echo -e "${YELLOW}⚠${NC} Skipping Maven build test - jsimconnect structure not OK"
    JSIMCONNECT_BUILD_OK=false
fi

# Test 4: Test RadioGUI Build with JSIMConnect
print_section "Testing RadioGUI Build with JSIMConnect"

cd /home/haaken/github-projects/fgcom-mumble

echo "Testing RadioGUI build with jsimconnect enabled..."
if make build-radioGUI-with-jsimconnect > /home/haaken/github-projects/fgcom-mumble/test/jsimconnect_build_tests/$TEST_RESULTS_DIR/radiogui_build_with_jsimconnect.log 2>&1; then
    echo -e "${GREEN}✓${NC} RadioGUI build with jsimconnect successful"
    RADIOGUI_BUILD_OK=true
else
    echo -e "${RED}✗${NC} RadioGUI build with jsimconnect failed"
    echo "Build log saved to: /home/haaken/github-projects/fgcom-mumble/test/jsimconnect_build_tests/$TEST_RESULTS_DIR/radiogui_build_with_jsimconnect.log"
    RADIOGUI_BUILD_OK=false
fi

# Test 5: Test RadioGUI Build without JSIMConnect
print_section "Testing RadioGUI Build without JSIMConnect"

echo "Testing RadioGUI build without jsimconnect..."
if make build-radioGUI-without-jsimconnect > /home/haaken/github-projects/fgcom-mumble/test/jsimconnect_build_tests/$TEST_RESULTS_DIR/radiogui_build_without_jsimconnect.log 2>&1; then
    echo -e "${GREEN}✓${NC} RadioGUI build without jsimconnect successful"
    RADIOGUI_BUILD_NO_JSIMCONNECT_OK=true
else
    echo -e "${RED}✗${NC} RadioGUI build without jsimconnect failed"
    echo "Build log saved to: /home/haaken/github-projects/fgcom-mumble/test/jsimconnect_build_tests/$TEST_RESULTS_DIR/radiogui_build_without_jsimconnect.log"
    RADIOGUI_BUILD_NO_JSIMCONNECT_OK=false
fi

# Test 6: Verify Generated JAR Files
print_section "Verifying Generated JAR Files"

RADIOGUI_JAR="/home/haaken/github-projects/fgcom-mumble/client/radioGUI/target/FGCom-mumble-radioGUI-1.2.0-jar-with-dependencies.jar"

if [ -f "$RADIOGUI_JAR" ]; then
    echo -e "${GREEN}✓${NC} RadioGUI JAR file exists"
    
    # Check JAR file size (should be substantial)
    JAR_SIZE=$(stat -c%s "$RADIOGUI_JAR")
    if [ "$JAR_SIZE" -gt 1000000 ]; then  # > 1MB
        echo -e "${GREEN}✓${NC} RadioGUI JAR file size is reasonable ($JAR_SIZE bytes)"
        JAR_FILE_OK=true
    else
        echo -e "${YELLOW}⚠${NC} RadioGUI JAR file size seems small ($JAR_SIZE bytes)"
        JAR_FILE_OK=false
    fi
else
    echo -e "${RED}✗${NC} RadioGUI JAR file does not exist"
    JAR_FILE_OK=false
fi

# Test 7: Test JSIMConnect Dependency Resolution
print_section "Testing JSIMConnect Dependency Resolution"

echo "Testing if jsimconnect dependency can be resolved in Maven..."
cd /home/haaken/github-projects/fgcom-mumble/client/radioGUI

# Test Maven dependency resolution
if mvn dependency:resolve -q > /home/haaken/github-projects/fgcom-mumble/test/jsimconnect_build_tests/$TEST_RESULTS_DIR/maven_dependency_resolution.log 2>&1; then
    echo -e "${GREEN}✓${NC} Maven dependency resolution successful"
    DEPENDENCY_RESOLUTION_OK=true
else
    echo -e "${RED}✗${NC} Maven dependency resolution failed"
    echo "Dependency resolution log saved to: /home/haaken/github-projects/fgcom-mumble/test/jsimconnect_build_tests/$TEST_RESULTS_DIR/maven_dependency_resolution.log"
    DEPENDENCY_RESOLUTION_OK=false
fi

# Test 8: Test JSIMConnect JAR Installation
print_section "Testing JSIMConnect JAR Installation"

echo "Testing if jsimconnect JAR is properly installed in local Maven repository..."
if mvn install:install-file -Dfile=lib/jsimconnect/target/jsimconnect-0.8.0.jar \
    -DgroupId=flightsim \
    -DartifactId=jsimconnect \
    -Dversion=0.8.0 \
    -Dpackaging=jar -q > /home/haaken/github-projects/fgcom-mumble/test/jsimconnect_build_tests/$TEST_RESULTS_DIR/jsimconnect_jar_installation.log 2>&1; then
    echo -e "${GREEN}✓${NC} jsimconnect JAR installation successful"
    JAR_INSTALLATION_OK=true
else
    echo -e "${RED}✗${NC} jsimconnect JAR installation failed"
    echo "Installation log saved to: /home/haaken/github-projects/fgcom-mumble/test/jsimconnect_build_tests/$TEST_RESULTS_DIR/jsimconnect_jar_installation.log"
    JAR_INSTALLATION_OK=false
fi

# Test 9: Test Makefile JSIMConnect Configuration
print_section "Testing Makefile JSIMConnect Configuration"

echo "Testing Makefile jsimconnect configuration..."
cd /home/haaken/github-projects/fgcom-mumble

# Check if ENABLE_JSIMCONNECT variable is properly set
if grep -q "ENABLE_JSIMCONNECT.*true" Makefile; then
    echo -e "${GREEN}✓${NC} ENABLE_JSIMCONNECT is set to true in Makefile"
    MAKEFILE_CONFIG_OK=true
else
    echo -e "${YELLOW}⚠${NC} ENABLE_JSIMCONNECT not found or not set to true in Makefile"
    MAKEFILE_CONFIG_OK=false
fi

# Test 10: Test GitHub Actions Workflow Compatibility
print_section "Testing GitHub Actions Workflow Compatibility"

echo "Testing if the build process matches GitHub Actions workflow expectations..."
if [ -f ".github/workflows/make-release.yml" ]; then
    echo -e "${GREEN}✓${NC} GitHub Actions workflow file exists"
    
    # Check if workflow includes jsimconnect submodule update
    if grep -q "git submodule update.*jsimconnect" .github/workflows/make-release.yml; then
        echo -e "${GREEN}✓${NC} GitHub Actions workflow includes jsimconnect submodule update"
        GITHUB_WORKFLOW_OK=true
    else
        echo -e "${YELLOW}⚠${NC} GitHub Actions workflow may not properly handle jsimconnect submodule"
        GITHUB_WORKFLOW_OK=false
    fi
else
    echo -e "${YELLOW}⚠${NC} GitHub Actions workflow file not found"
    GITHUB_WORKFLOW_OK=false
fi

# Generate Test Report
print_section "Generating Test Report"

cat > /home/haaken/github-projects/fgcom-mumble/test/jsimconnect_build_tests/$TEST_RESULTS_DIR/jsimconnect_build_test_report.html << EOF
<!DOCTYPE html>
<html>
<head>
    <title>JSIMConnect Build Test Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #f0f0f0; padding: 20px; border-radius: 5px; }
        .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
        .success { background-color: #d4edda; border-color: #c3e6cb; }
        .warning { background-color: #fff3cd; border-color: #ffeaa7; }
        .error { background-color: #f8d7da; border-color: #f5c6cb; }
        .info { background-color: #d1ecf1; border-color: #bee5eb; }
        pre { background-color: #f8f9fa; padding: 10px; border-radius: 3px; overflow-x: auto; }
        .test-result { margin: 10px 0; padding: 10px; border-radius: 3px; }
        .pass { background-color: #d4edda; }
        .fail { background-color: #f8d7da; }
        .warn { background-color: #fff3cd; }
    </style>
</head>
<body>
    <div class="header">
        <h1>JSIMConnect Build Test Report</h1>
        <p>Generated on: $(date)</p>
        <p>Test Suite: JSIMConnect Build and Integration</p>
    </div>

    <div class="section info">
        <h2>Test Summary</h2>
        <ul>
            <li><strong>Git Submodule Status:</strong> $([ "$JSIMCONNECT_SUBMODULE_OK" = true ] && echo "PASS" || echo "FAIL")</li>
            <li><strong>Directory Structure:</strong> $([ "$JSIMCONNECT_STRUCTURE_OK" = true ] && echo "PASS" || echo "FAIL")</li>
            <li><strong>Maven Build:</strong> $([ "$JSIMCONNECT_BUILD_OK" = true ] && echo "PASS" || echo "FAIL")</li>
            <li><strong>RadioGUI Build (with jsimconnect):</strong> $([ "$RADIOGUI_BUILD_OK" = true ] && echo "PASS" || echo "FAIL")</li>
            <li><strong>RadioGUI Build (without jsimconnect):</strong> $([ "$RADIOGUI_BUILD_NO_JSIMCONNECT_OK" = true ] && echo "PASS" || echo "FAIL")</li>
            <li><strong>JAR File Generation:</strong> $([ "$JAR_FILE_OK" = true ] && echo "PASS" || echo "FAIL")</li>
            <li><strong>Dependency Resolution:</strong> $([ "$DEPENDENCY_RESOLUTION_OK" = true ] && echo "PASS" || echo "FAIL")</li>
            <li><strong>JAR Installation:</strong> $([ "$JAR_INSTALLATION_OK" = true ] && echo "PASS" || echo "FAIL")</li>
            <li><strong>Makefile Configuration:</strong> $([ "$MAKEFILE_CONFIG_OK" = true ] && echo "PASS" || echo "FAIL")</li>
            <li><strong>GitHub Actions Compatibility:</strong> $([ "$GITHUB_WORKFLOW_OK" = true ] && echo "PASS" || echo "FAIL")</li>
        </ul>
    </div>

    <div class="section">
        <h2>Test Results</h2>
        <div class="test-result $([ "$JSIMCONNECT_SUBMODULE_OK" = true ] && echo "pass" || echo "fail")">
            <strong>Git Submodule Status:</strong> $([ "$JSIMCONNECT_SUBMODULE_OK" = true ] && echo "PASS" || echo "FAIL")
        </div>
        <div class="test-result $([ "$JSIMCONNECT_STRUCTURE_OK" = true ] && echo "pass" || echo "fail")">
            <strong>Directory Structure:</strong> $([ "$JSIMCONNECT_STRUCTURE_OK" = true ] && echo "PASS" || echo "FAIL")
        </div>
        <div class="test-result $([ "$JSIMCONNECT_BUILD_OK" = true ] && echo "pass" || echo "fail")">
            <strong>Maven Build:</strong> $([ "$JSIMCONNECT_BUILD_OK" = true ] && echo "PASS" || echo "FAIL")
        </div>
        <div class="test-result $([ "$RADIOGUI_BUILD_OK" = true ] && echo "pass" || echo "fail")">
            <strong>RadioGUI Build (with jsimconnect):</strong> $([ "$RADIOGUI_BUILD_OK" = true ] && echo "PASS" || echo "FAIL")
        </div>
        <div class="test-result $([ "$RADIOGUI_BUILD_NO_JSIMCONNECT_OK" = true ] && echo "pass" || echo "fail")">
            <strong>RadioGUI Build (without jsimconnect):</strong> $([ "$RADIOGUI_BUILD_NO_JSIMCONNECT_OK" = true ] && echo "PASS" || echo "FAIL")
        </div>
        <div class="test-result $([ "$JAR_FILE_OK" = true ] && echo "pass" || echo "fail")">
            <strong>JAR File Generation:</strong> $([ "$JAR_FILE_OK" = true ] && echo "PASS" || echo "FAIL")
        </div>
        <div class="test-result $([ "$DEPENDENCY_RESOLUTION_OK" = true ] && echo "pass" || echo "fail")">
            <strong>Dependency Resolution:</strong> $([ "$DEPENDENCY_RESOLUTION_OK" = true ] && echo "PASS" || echo "FAIL")
        </div>
        <div class="test-result $([ "$JAR_INSTALLATION_OK" = true ] && echo "pass" || echo "fail")">
            <strong>JAR Installation:</strong> $([ "$JAR_INSTALLATION_OK" = true ] && echo "PASS" || echo "FAIL")
        </div>
        <div class="test-result $([ "$MAKEFILE_CONFIG_OK" = true ] && echo "pass" || echo "fail")">
            <strong>Makefile Configuration:</strong> $([ "$MAKEFILE_CONFIG_OK" = true ] && echo "PASS" || echo "FAIL")
        </div>
        <div class="test-result $([ "$GITHUB_WORKFLOW_OK" = true ] && echo "pass" || echo "fail")">
            <strong>GitHub Actions Compatibility:</strong> $([ "$GITHUB_WORKFLOW_OK" = true ] && echo "PASS" || echo "FAIL")
        </div>
    </div>

    <div class="section">
        <h2>Test Categories</h2>
        <ul>
            <li><strong>Submodule Management:</strong> Git submodule initialization and checkout</li>
            <li><strong>Build Process:</strong> Maven build of jsimconnect library</li>
            <li><strong>Integration:</strong> RadioGUI build with and without jsimconnect</li>
            <li><strong>Dependency Management:</strong> Maven dependency resolution and JAR installation</li>
            <li><strong>Configuration:</strong> Makefile and GitHub Actions workflow compatibility</li>
        </ul>
    </div>

    <div class="section">
        <h2>Build Logs</h2>
        <p>Detailed build logs available:</p>
        <ul>
            <li><a href="radiogui_build_with_jsimconnect.log">RadioGUI Build with JSIMConnect</a></li>
            <li><a href="radiogui_build_without_jsimconnect.log">RadioGUI Build without JSIMConnect</a></li>
            <li><a href="maven_dependency_resolution.log">Maven Dependency Resolution</a></li>
            <li><a href="jsimconnect_jar_installation.log">JSIMConnect JAR Installation</a></li>
        </ul>
    </div>
</body>
</html>
EOF

echo -e "${GREEN}✓${NC} Test report generated: /home/haaken/github-projects/fgcom-mumble/test/jsimconnect_build_tests/$TEST_RESULTS_DIR/jsimconnect_build_test_report.html"

# Final Summary
print_section "Test Suite Summary"

TOTAL_TESTS=10
PASSED_TESTS=0

[ "$JSIMCONNECT_SUBMODULE_OK" = true ] && ((PASSED_TESTS++))
[ "$JSIMCONNECT_STRUCTURE_OK" = true ] && ((PASSED_TESTS++))
[ "$JSIMCONNECT_BUILD_OK" = true ] && ((PASSED_TESTS++))
[ "$RADIOGUI_BUILD_OK" = true ] && ((PASSED_TESTS++))
[ "$RADIOGUI_BUILD_NO_JSIMCONNECT_OK" = true ] && ((PASSED_TESTS++))
[ "$JAR_FILE_OK" = true ] && ((PASSED_TESTS++))
[ "$DEPENDENCY_RESOLUTION_OK" = true ] && ((PASSED_TESTS++))
[ "$JAR_INSTALLATION_OK" = true ] && ((PASSED_TESTS++))
[ "$MAKEFILE_CONFIG_OK" = true ] && ((PASSED_TESTS++))
[ "$GITHUB_WORKFLOW_OK" = true ] && ((PASSED_TESTS++))

echo "Total tests: $TOTAL_TESTS"
echo "Passed: $PASSED_TESTS"
echo "Failed: $((TOTAL_TESTS - PASSED_TESTS))"

if [ "$PASSED_TESTS" -eq "$TOTAL_TESTS" ]; then
    echo -e "\n${GREEN}=== ALL JSIMCONNECT BUILD TESTS PASSED ===${NC}"
    echo "JSIMConnect build process is working correctly!"
    exit 0
else
    echo -e "\n${YELLOW}=== SOME JSIMCONNECT BUILD TESTS FAILED ===${NC}"
    echo "Check the test report for details: /home/haaken/github-projects/fgcom-mumble/test/jsimconnect_build_tests/$TEST_RESULTS_DIR/jsimconnect_build_test_report.html"
    exit 1
fi
