#!/bin/bash
#
# Run all server tests
# Tests are organized in subdirectories

cd "$(dirname "$0")" || exit 1

echo "=== SERVER TEST EXECUTION ==="
echo "Date: $(date)"
echo "Running all server tests..."
echo

# List of all server test modules
declare -a TEST_MODULES=(
    "atis_module_tests"
    "status_page_module_tests"
)

# Function to run a test module
run_test_module() {
    local module_dir="$1"
    local module_name=$(basename "$module_dir")
    
    echo "=========================================="
    echo "Testing: $module_name"
    echo "=========================================="
    
    if [ ! -d "$module_dir" ]; then
        echo "Module $module_dir not found, skipping..."
        return
    fi
    
    cd "$module_dir" || return 1
    
    # Try to build and run tests
    if [ -f "CMakeLists.txt" ]; then
        if [ -d "build" ]; then
            rm -rf build
        fi
        mkdir -p build && cd build
        if cmake .. && make -j$(nproc) 2>/dev/null; then
            if [ -f "${module_name}" ]; then
                echo "Running $module_name tests..."
                ./${module_name} 2>&1
            fi
        fi
        cd ..
    elif [ -f "Makefile" ]; then
        if make clean && make -j$(nproc) 2>/dev/null; then
            if [ -f "build/${module_name}" ]; then
                echo "Running $module_name tests..."
                ./build/${module_name} 2>&1
            fi
        fi
    fi
    
    cd - > /dev/null
    echo
}

# Run all test modules
for module in "${TEST_MODULES[@]}"; do
    run_test_module "$module"
done

# Also run Lua tests
echo "=========================================="
echo "Running Lua server tests"
echo "=========================================="
for lua_test in *.lua; do
    if [ -f "$lua_test" ]; then
        echo "Running $lua_test..."
        luajit "$lua_test" 2>&1 || true
    fi
done

echo "=== SERVER TESTS COMPLETED ==="

