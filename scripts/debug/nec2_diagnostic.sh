#!/bin/bash
# NEC2 Environment Diagnostic Tool
# Run this to identify why NEC2 is failing silently

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $1"; }

echo "======================================="
echo "NEC2 Environment Diagnostic Tool"
echo "======================================="

# Test 1: Basic system information
echo
log_info "System Information:"
echo "OS: $(uname -s -r)"
echo "Architecture: $(uname -m)"
echo "User: $(whoami)"
echo "Home: $HOME"
echo "Current directory: $(pwd)"

# Test 2: NEC2 executable discovery
echo
log_info "NEC2 Executable Discovery:"
if command -v nec2c >/dev/null 2>&1; then
    NEC2_PATH=$(which nec2c)
    log_success "Found nec2c at: $NEC2_PATH"
    echo "File info: $(ls -la "$NEC2_PATH")"
    echo "File type: $(file "$NEC2_PATH")"
    
    # Check if it's a script or binary
    if [ -x "$NEC2_PATH" ]; then
        log_success "nec2c is executable"
    else
        log_error "nec2c is not executable"
    fi
    
    # Test basic execution
    echo
    log_info "Testing NEC2 basic execution..."
    
    # Method 1: Version check
    if nec2c --version >/dev/null 2>&1; then
        log_success "nec2c --version works"
        echo "Version: $(nec2c --version 2>&1 | head -1)"
    elif nec2c -h >/dev/null 2>&1; then
        log_success "nec2c -h works"
    else
        log_warning "nec2c doesn't respond to --version or -h"
        
        # Try running without arguments
        timeout 3 nec2c </dev/null >/dev/null 2>&1 && \
            log_success "nec2c runs without arguments" || \
            log_warning "nec2c doesn't run cleanly without arguments"
    fi
    
else
    log_error "nec2c not found in PATH"
    echo "PATH: $PATH"
    
    # Look for common installation locations
    common_paths=(
        "/usr/bin/nec2c"
        "/usr/local/bin/nec2c"
        "/opt/nec2c/bin/nec2c"
        "$HOME/bin/nec2c"
    )
    
    for path in "${common_paths[@]}"; do
        if [ -f "$path" ]; then
            log_info "Found nec2c at: $path"
        fi
    done
fi

# Test 3: Library dependencies
echo
log_info "Library Dependencies:"
if command -v ldd >/dev/null 2>&1 && [ -n "${NEC2_PATH:-}" ]; then
    echo "Dependencies for $NEC2_PATH:"
    if ldd "$NEC2_PATH" 2>/dev/null; then
        log_success "All libraries found"
    else
        log_error "Library dependency issues detected"
    fi
else
    log_warning "Cannot check library dependencies (ldd not available or nec2c not found)"
fi

# Test 4: Temporary directory tests
echo
log_info "Temporary Directory Tests:"
TEMP_DIR="${TMPDIR:-/tmp}"
echo "Using temp directory: $TEMP_DIR"
echo "Permissions: $(ls -lad "$TEMP_DIR")"
echo "Available space: $(df -h "$TEMP_DIR" | tail -1 | awk '{print $4}')"

# Test file creation
TEST_FILE="$TEMP_DIR/nec2_test_$$"
if touch "$TEST_FILE" 2>/dev/null; then
    log_success "Can create files in temp directory"
    rm -f "$TEST_FILE"
else
    log_error "Cannot create files in temp directory"
fi

# Test 5: Create minimal test case
echo
log_info "Creating minimal NEC2 test case..."

# Create minimal NEC file
MINIMAL_NEC="$TEMP_DIR/minimal_test_$$.nec"
MINIMAL_OUT="$TEMP_DIR/minimal_test_$$.out"

cat > "$MINIMAL_NEC" << 'NEC_EOF'
CM Minimal test antenna - vertical wire
CE
GW 1 1 0 0 0 0 0 1 0.001
GE 0
FR 0 1 0 0 100 0
EX 0 1 1 0 1 0 0
RP 0 37 73 1000 0 0 5 5 0
EN
NEC_EOF

echo "Created test file: $MINIMAL_NEC"
echo "File size: $(wc -c < "$MINIMAL_NEC") bytes"
echo "First few lines:"
head -3 "$MINIMAL_NEC"

# Test 6: Multiple execution methods
echo
log_info "Testing different NEC2 execution methods..."

if [ -n "${NEC2_PATH:-}" ]; then
    # Method 1: Standard flags
    echo "Method 1: nec2c -i input -o output"
    if nec2c -i "$MINIMAL_NEC" -o "$MINIMAL_OUT" 2>&1; then
        if [ -f "$MINIMAL_OUT" ] && [ -s "$MINIMAL_OUT" ]; then
            log_success "Method 1 works - output file created ($(wc -c < "$MINIMAL_OUT") bytes)"
        else
            log_warning "Method 1 ran but no output file or empty file"
        fi
    else
        log_error "Method 1 failed"
    fi
    rm -f "$MINIMAL_OUT"
    
    # Method 2: Without flags
    echo "Method 2: nec2c inputfile"
    cd "$TEMP_DIR"
    SIMPLE_BASE="simple_test_$$"
    cp "$MINIMAL_NEC" "${SIMPLE_BASE}.nec"
    
    if nec2c "${SIMPLE_BASE}.nec" 2>&1; then
        # Check various possible output names
        possible_outputs=(
            "${SIMPLE_BASE}.out"
            "${SIMPLE_BASE}.OUT"
            "${SIMPLE_BASE}.txt"
            "${SIMPLE_BASE}.nec.out"
        )
        
        found_output=false
        for out in "${possible_outputs[@]}"; do
            if [ -f "$out" ] && [ -s "$out" ]; then
                log_success "Method 2 works - found output: $out ($(wc -c < "$out") bytes)"
                found_output=true
                break
            fi
        done
        
        if [ "$found_output" = false ]; then
            log_warning "Method 2 ran but no recognizable output file found"
            echo "Files in directory after run:"
            ls -la "${SIMPLE_BASE}"* 2>/dev/null || echo "No files found"
        fi
    else
        log_error "Method 2 failed"
    fi
    
    # Cleanup
    rm -f "${SIMPLE_BASE}"*
    cd - >/dev/null
    
    # Method 3: Different working directory
    echo "Method 3: Run from different directory"
    mkdir -p "$TEMP_DIR/nec2_test_dir"
    cp "$MINIMAL_NEC" "$TEMP_DIR/nec2_test_dir/"
    
    (
        cd "$TEMP_DIR/nec2_test_dir"
        if nec2c -i "$(basename "$MINIMAL_NEC")" -o "test_output.out" 2>&1; then
            if [ -f "test_output.out" ] && [ -s "test_output.out" ]; then
                log_success "Method 3 works"
            else
                log_warning "Method 3 ran but no output"
            fi
        else
            log_error "Method 3 failed"
        fi
    )
    
    rm -rf "$TEMP_DIR/nec2_test_dir"
    
    # Method 4: Absolute paths
    echo "Method 4: Absolute paths"
    ABS_INPUT=$(realpath "$MINIMAL_NEC")
    ABS_OUTPUT="$TEMP_DIR/abs_test_output_$$.out"
    
    if nec2c -i "$ABS_INPUT" -o "$ABS_OUTPUT" 2>&1; then
        if [ -f "$ABS_OUTPUT" ] && [ -s "$ABS_OUTPUT" ]; then
            log_success "Method 4 works"
        else
            log_warning "Method 4 ran but no output"
        fi
    else
        log_error "Method 4 failed"
    fi
    rm -f "$ABS_OUTPUT"
    
    # Method 5: Environment reset
    echo "Method 5: Clean environment"
    if env -i PATH="$PATH" HOME="$HOME" nec2c -i "$MINIMAL_NEC" -o "$MINIMAL_OUT" 2>&1; then
        if [ -f "$MINIMAL_OUT" ] && [ -s "$MINIMAL_OUT" ]; then
            log_success "Method 5 works"
        else
            log_warning "Method 5 ran but no output"
        fi
    else
        log_error "Method 5 failed"
    fi
    rm -f "$MINIMAL_OUT"
    
else
    log_error "Cannot test execution methods - nec2c not found"
fi

# Test 7: Process and file descriptor limits
echo
log_info "Process and File Limits:"
echo "Open files limit: $(ulimit -n)"
echo "Max processes: $(ulimit -u)"
echo "Current processes: $(ps aux | wc -l)"

# Test 8: Current process status
echo
log_info "Current Process Environment:"
echo "PID: $$"
echo "PPID: $PPID"
echo "Working directory: $(pwd)"
echo "User ID: $(id -u)"
echo "Group ID: $(id -g)"

# Test 9: File system issues
echo
log_info "File System Tests:"

# Test file creation with various names
test_names=(
    "test_$$.nec"
    "t$$.nec"
    "a.nec"
    "TEST.NEC"
    "test.NEC"
)

for name in "${test_names[@]}"; do
    test_file="$TEMP_DIR/$name"
    if echo "test" > "$test_file" 2>/dev/null; then
        log_success "Can create: $name"
        rm -f "$test_file"
    else
        log_error "Cannot create: $name"
    fi
done

# Cleanup
rm -f "$MINIMAL_NEC" "$MINIMAL_OUT"

echo
echo "======================================="
echo "Diagnostic Complete"
echo "======================================="
echo
echo "RECOMMENDATIONS:"
echo "1. If Method 1 works, the issue is in your script's execution context"
echo "2. If no methods work, check NEC2 installation and dependencies"
echo "3. If file creation fails, check permissions and disk space"
echo "4. Compare working conditions with your script's environment"
echo
echo "To debug further, run your script with:"
echo "  bash -x your_script.sh --verbose"
echo "  strace -e trace=file your_script.sh (to see file operations)"
echo "  TMPDIR=/your/custom/temp your_script.sh (to try different temp dir)"
