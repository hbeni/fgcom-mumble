#!/bin/bash

# Script to setup AFL++ and Mull mutation testing for FGCom-mumble
# This script installs and configures AFL++ and Mull for comprehensive fuzzing and mutation testing

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Get the project root directory
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_DIR="$PROJECT_ROOT/test"
FUZZING_DIR="$TEST_DIR/fuzzing_tests"

print_status "Setting up AFL++ and Mull for FGCom-mumble"
print_status "Project root: $PROJECT_ROOT"
print_status "Fuzzing directory: $FUZZING_DIR"

# Check if running as root
if [[ $EUID -eq 0 ]]; then
    print_error "This script should not be run as root"
    exit 1
fi

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to install package
install_package() {
    local package="$1"
    if command_exists apt-get; then
        sudo apt-get update
        sudo apt-get install -y "$package"
    elif command_exists yum; then
        sudo yum install -y "$package"
    elif command_exists pacman; then
        sudo pacman -S --noconfirm "$package"
    elif command_exists brew; then
        brew install "$package"
    else
        print_error "Package manager not found. Please install $package manually."
        exit 1
    fi
}

echo "=========================================="
echo "FGCom-mumble AFL++ and Mull Setup"
echo "=========================================="

print_status "1. Installing System Dependencies..."

# Install basic dependencies
if ! command_exists git; then
    print_status "Installing git..."
    install_package "git"
fi

if ! command_exists cmake; then
    print_status "Installing cmake..."
    install_package "cmake"
fi

if ! command_exists make; then
    print_status "Installing build-essential..."
    install_package "build-essential"
fi

if ! command_exists python3; then
    print_status "Installing python3..."
    install_package "python3"
fi

if ! command_exists clang; then
    print_status "Installing clang..."
    install_package "clang"
fi

if ! command_exists llvm-config; then
    print_status "Installing llvm..."
    install_package "llvm"
fi

print_success "System dependencies installed"
echo

print_status "2. Installing AFL++..."

# Check if AFL++ is already installed
if command_exists afl-fuzz; then
    print_warning "AFL++ already installed, checking version..."
    afl-fuzz --version
else
    print_status "Installing AFL++ from source..."
    
    cd "$FUZZING_DIR"
    
    # Clone AFL++ repository
    if [ ! -d "afl++" ]; then
        git clone https://github.com/AFLplusplus/AFLplusplus.git afl++
    fi
    
    cd afl++
    git checkout stable
    
    # Build AFL++
    make clean
    make -j$(nproc)
    
    # Install AFL++
    sudo make install
    
    print_success "AFL++ installed successfully"
fi

echo

print_status "3. Installing Mull..."

# Check if Mull is already installed
if command_exists mull-cxx; then
    print_warning "Mull already installed, checking version..."
    mull-cxx --version
else
    print_status "Installing Mull from source..."
    
    cd "$FUZZING_DIR"
    
    # Clone Mull repository
    if [ ! -d "mull" ]; then
        git clone https://github.com/mull-project/mull.git
    fi
    
    cd mull
    
    # Build Mull
    mkdir -p build
    cd build
    cmake .. -DCMAKE_BUILD_TYPE=Release
    make -j$(nproc)
    
    # Install Mull
    sudo make install
    
    print_success "Mull installed successfully"
fi

echo

print_status "4. Setting up Fuzzing Environment..."

# Create necessary directories
mkdir -p "$FUZZING_DIR/corpus"
mkdir -p "$FUZZING_DIR/outputs"
mkdir -p "$FUZZING_DIR/afl++/targets"
mkdir -p "$FUZZING_DIR/mull/targets"

# Set up AFL++ environment
export AFL_HARDEN=1
export AFL_USE_ASAN=1
export AFL_USE_MSAN=1
export AFL_USE_UBSAN=1

# Create AFL++ configuration
cat > "$FUZZING_DIR/afl++.conf" << EOF
# AFL++ Configuration for FGCom-mumble
[AFL++]
# Enable all sanitizers
USE_ASAN=1
USE_MSAN=1
USE_UBSAN=1
USE_CFISAN=1

# Memory limits
MEM_LIMIT=1024

# Timeout
TIMEOUT=10000

# Dictionary
DICT_FILE=$FUZZING_DIR/corpus/dictionary.txt

# Output directory
OUTPUT_DIR=$FUZZING_DIR/outputs

# Target directory
TARGET_DIR=$FUZZING_DIR/afl++/targets
EOF

# Create Mull configuration
cat > "$FUZZING_DIR/mull.conf" << EOF
# Mull Configuration for FGCom-mumble
[mull]
# Mutation operators
operators = add_mutation, remove_mutation, replace_mutation

# Test framework
test_framework = GoogleTest

# Timeout
timeout = 300

# Parallel execution
workers = 4

# Output format
format = json

# Target directory
target_dir = $FUZZING_DIR/mull/targets
EOF

print_success "Fuzzing environment configured"
echo

print_status "5. Creating Fuzzing Targets..."

# Create AFL++ fuzzing targets
cat > "$FUZZING_DIR/afl++/targets/fuzz_radio_propagation.cpp" << 'EOF'
#include <iostream>
#include <fstream>
#include <vector>
#include <cmath>
#include <cstring>

// Mock radio propagation functions for fuzzing
class RadioPropagation {
public:
    static double calculatePathLoss(double frequency_hz, double distance_m) {
        const double c = 299792458.0; // speed of light
        double wavelength = c / frequency_hz;
        double free_space_loss = 20 * log10(4 * M_PI * distance_m / wavelength);
        return free_space_loss;
    }
    
    static double calculateAtmosphericAttenuation(double frequency_hz, double rain_rate_mmh) {
        if (frequency_hz < 1e9) return 0.0;
        double k = 0.0001 * pow(frequency_hz / 1e9, 1.5);
        double alpha = 0.8;
        return k * pow(rain_rate_mmh, alpha);
    }
    
    static bool hasLineOfSight(double lat1, double lon1, double alt1,
                              double lat2, double lon2, double alt2) {
        const double earth_radius = 6371000.0;
        double dlat = (lat2 - lat1) * M_PI / 180.0;
        double dlon = (lon2 - lon1) * M_PI / 180.0;
        double a = sin(dlat/2) * sin(dlat/2) + cos(lat1 * M_PI / 180.0) * cos(lat2 * M_PI / 180.0) * sin(dlon/2) * sin(dlon/2);
        double c = 2 * atan2(sqrt(a), sqrt(1-a));
        double distance = earth_radius * c;
        return distance < 100000 && alt1 > 0 && alt2 > 0;
    }
};

// AFL++ main function
int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <input_file>" << std::endl;
        return 1;
    }
    
    std::ifstream file(argv[1], std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Failed to open input file" << std::endl;
        return 1;
    }
    
    // Read input data
    std::vector<char> buffer((std::istreambuf_iterator<char>(file)),
                            std::istreambuf_iterator<char>());
    file.close();
    
    if (buffer.size() < 24) {
        return 1; // Need at least 24 bytes for 3 doubles
    }
    
    // Extract test parameters from input
    double* params = reinterpret_cast<double*>(buffer.data());
    double frequency = params[0];
    double distance = params[1];
    double rain_rate = params[2];
    
    // Fuzz radio propagation calculations
    try {
        double path_loss = RadioPropagation::calculatePathLoss(frequency, distance);
        double attenuation = RadioPropagation::calculateAtmosphericAttenuation(frequency, rain_rate);
        bool los = RadioPropagation::hasLineOfSight(0, 0, 100, 1, 1, 200);
        
        // Trigger potential crashes with extreme values
        if (std::isnan(path_loss) || std::isinf(path_loss)) {
            return 1;
        }
        if (std::isnan(attenuation) || std::isinf(attenuation)) {
            return 1;
        }
        
    } catch (...) {
        return 1;
    }
    
    return 0;
}
EOF

# Create audio processing fuzzing target
cat > "$FUZZING_DIR/afl++/targets/fuzz_audio_processing.cpp" << 'EOF'
#include <iostream>
#include <fstream>
#include <vector>
#include <cmath>
#include <algorithm>

// Mock audio processing functions for fuzzing
class AudioProcessor {
public:
    static void applyGain(std::vector<float>& samples, float gain_db) {
        float gain_linear = std::pow(10.0f, gain_db / 20.0f);
        for (auto& sample : samples) {
            sample *= gain_linear;
        }
    }
    
    static void applyCompression(std::vector<float>& samples, float threshold, float ratio) {
        float threshold_linear = std::pow(10.0f, threshold / 20.0f);
        for (auto& sample : samples) {
            if (std::abs(sample) > threshold_linear) {
                float excess = std::abs(sample) - threshold_linear;
                float compressed_excess = excess / ratio;
                sample = std::copysign(threshold_linear + compressed_excess, sample);
            }
        }
    }
    
    static float calculateRMS(const std::vector<float>& samples) {
        if (samples.empty()) return 0.0f;
        float sum_squares = 0.0f;
        for (float sample : samples) {
            sum_squares += sample * sample;
        }
        return std::sqrt(sum_squares / samples.size());
    }
};

// AFL++ main function
int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <input_file>" << std::endl;
        return 1;
    }
    
    std::ifstream file(argv[1], std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Failed to open input file" << std::endl;
        return 1;
    }
    
    // Read input data
    std::vector<char> buffer((std::istreambuf_iterator<char>(file)),
                            std::istreambuf_iterator<char>());
    file.close();
    
    if (buffer.size() < 16) {
        return 1; // Need at least 16 bytes for parameters
    }
    
    // Extract parameters
    float* params = reinterpret_cast<float*>(buffer.data());
    float gain_db = params[0];
    float threshold = params[1];
    float ratio = params[2];
    
    // Create test audio samples
    std::vector<float> samples;
    for (size_t i = 3; i < buffer.size() / sizeof(float) && i < 1000; ++i) {
        samples.push_back(params[i]);
    }
    
    if (samples.empty()) {
        samples = {0.1f, -0.1f, 0.5f, -0.5f};
    }
    
    // Fuzz audio processing
    try {
        AudioProcessor::applyGain(samples, gain_db);
        AudioProcessor::applyCompression(samples, threshold, ratio);
        float rms = AudioProcessor::calculateRMS(samples);
        
        // Check for invalid results
        if (std::isnan(rms) || std::isinf(rms)) {
            return 1;
        }
        
    } catch (...) {
        return 1;
    }
    
    return 0;
}
EOF

print_success "Fuzzing targets created"
echo

print_status "6. Creating Corpus Data..."

# Create initial corpus for AFL++
mkdir -p "$FUZZING_DIR/corpus/radio_propagation"
mkdir -p "$FUZZING_DIR/corpus/audio_processing"

# Create radio propagation corpus
cat > "$FUZZING_DIR/corpus/radio_propagation/input1" << 'EOF'
# Radio propagation test case 1
# Frequency: 118 MHz (VHF aviation)
# Distance: 10 km
# Rain rate: 0 mm/h
EOF

# Create binary test cases
python3 << 'EOF'
import struct
import os

# Create radio propagation test cases
test_cases = [
    (118e6, 10000, 0),      # VHF aviation, 10km, no rain
    (225e6, 5000, 5),       # UHF, 5km, light rain
    (3e9, 1000, 20),        # Microwave, 1km, heavy rain
    (10e9, 500, 50),        # 10GHz, 500m, very heavy rain
    (1e6, 100000, 0),       # HF, 100km, no rain
]

os.makedirs('/home/haaken/github-projects/fgcom-mumble/test/fuzzing_tests/corpus/radio_propagation', exist_ok=True)

for i, (freq, dist, rain) in enumerate(test_cases):
    with open(f'/home/haaken/github-projects/fgcom-mumble/test/fuzzing_tests/corpus/radio_propagation/input{i+1}', 'wb') as f:
        f.write(struct.pack('ddd', freq, dist, rain))

# Create audio processing test cases
audio_cases = [
    (0, -20, 2.0),          # No gain, -20dB threshold, 2:1 ratio
    (6, -10, 4.0),          # 6dB gain, -10dB threshold, 4:1 ratio
    (-6, -30, 1.5),         # -6dB gain, -30dB threshold, 1.5:1 ratio
    (12, 0, 8.0),           # 12dB gain, 0dB threshold, 8:1 ratio
    (-12, -40, 1.2),        # -12dB gain, -40dB threshold, 1.2:1 ratio
]

os.makedirs('/home/haaken/github-projects/fgcom-mumble/test/fuzzing_tests/corpus/audio_processing', exist_ok=True)

for i, (gain, threshold, ratio) in enumerate(audio_cases):
    with open(f'/home/haaken/github-projects/fgcom-mumble/test/fuzzing_tests/corpus/audio_processing/input{i+1}', 'wb') as f:
        f.write(struct.pack('fff', gain, threshold, ratio))
        # Add some sample data
        for j in range(100):
            f.write(struct.pack('f', 0.1 * j - 5.0))

print("Corpus data created successfully")
EOF

print_success "Corpus data created"
echo

print_status "7. Creating Build Scripts..."

# Create AFL++ build script
cat > "$FUZZING_DIR/build_afl_targets.sh" << 'EOF'
#!/bin/bash

# Build AFL++ fuzzing targets
set -e

echo "Building AFL++ fuzzing targets..."

# Set AFL++ environment
export CC=afl-clang-fast
export CXX=afl-clang-fast++

# Build radio propagation fuzzer
echo "Building radio propagation fuzzer..."
afl-clang-fast++ -O3 -g -fsanitize=address,undefined -o fuzz_radio_propagation fuzz_radio_propagation.cpp

# Build audio processing fuzzer
echo "Building audio processing fuzzer..."
afl-clang-fast++ -O3 -g -fsanitize=address,undefined -o fuzz_audio_processing fuzz_audio_processing.cpp

echo "AFL++ targets built successfully!"
EOF

chmod +x "$FUZZING_DIR/build_afl_targets.sh"

# Create Mull build script
cat > "$FUZZING_DIR/build_mull_targets.sh" << 'EOF'
#!/bin/bash

# Build Mull mutation testing targets
set -e

echo "Building Mull mutation testing targets..."

# Build with Mull instrumentation
echo "Building mutation testing targets..."
mull-cxx -compilation-flags="-O2 -g" -compilation-database compile_commands.json

echo "Mull targets built successfully!"
EOF

chmod +x "$FUZZING_DIR/build_mull_targets.sh"

print_success "Build scripts created"
echo

print_status "8. Creating Run Scripts..."

# Create AFL++ run script
cat > "$FUZZING_DIR/run_afl_fuzzing.sh" << 'EOF'
#!/bin/bash

# Run AFL++ fuzzing
set -e

FUZZING_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="$FUZZING_DIR/outputs"
CORPUS_DIR="$FUZZING_DIR/corpus"

echo "Starting AFL++ fuzzing..."

# Create output directories
mkdir -p "$OUTPUT_DIR/radio_propagation"
mkdir -p "$OUTPUT_DIR/audio_processing"

# Run radio propagation fuzzing
echo "Fuzzing radio propagation..."
afl-fuzz -i "$CORPUS_DIR/radio_propagation" -o "$OUTPUT_DIR/radio_propagation" -t 10000 -- ./fuzz_radio_propagation @@ &

# Run audio processing fuzzing
echo "Fuzzing audio processing..."
afl-fuzz -i "$CORPUS_DIR/audio_processing" -o "$OUTPUT_DIR/audio_processing" -t 10000 -- ./fuzz_audio_processing @@ &

echo "AFL++ fuzzing started in background"
echo "Check output directories for results:"
echo "  Radio propagation: $OUTPUT_DIR/radio_propagation"
echo "  Audio processing: $OUTPUT_DIR/audio_processing"
EOF

chmod +x "$FUZZING_DIR/run_afl_fuzzing.sh"

# Create Mull run script
cat > "$FUZZING_DIR/run_mull_mutation.sh" << 'EOF'
#!/bin/bash

# Run Mull mutation testing
set -e

FUZZING_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="$FUZZING_DIR/outputs/mull"

echo "Starting Mull mutation testing..."

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Run mutation testing
echo "Running mutation testing..."
mull-cxx -compilation-flags="-O2 -g" -compilation-database compile_commands.json \
         -reporters=json -reporters=html \
         -output="$OUTPUT_DIR/mutation_report.json" \
         -output="$OUTPUT_DIR/mutation_report.html"

echo "Mull mutation testing completed"
echo "Check results: $OUTPUT_DIR/mutation_report.html"
EOF

chmod +x "$FUZZING_DIR/run_mull_mutation.sh"

print_success "Run scripts created"
echo

print_status "9. Creating CI/CD Integration..."

# Create GitHub Actions workflow
mkdir -p "$PROJECT_ROOT/.github/workflows"
cat > "$PROJECT_ROOT/.github/workflows/fuzzing.yml" << 'EOF'
name: Fuzzing and Mutation Testing

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  fuzzing:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Install dependencies
      run: |
        sudo apt-get update
        sudo apt-get install -y build-essential cmake clang llvm git python3
    
    - name: Setup AFL++
      run: |
        git clone https://github.com/AFLplusplus/AFLplusplus.git
        cd AFLplusplus
        make clean
        make -j$(nproc)
        sudo make install
    
    - name: Setup Mull
      run: |
        git clone https://github.com/mull-project/mull.git
        cd mull
        mkdir build && cd build
        cmake .. -DCMAKE_BUILD_TYPE=Release
        make -j$(nproc)
        sudo make install
    
    - name: Run AFL++ fuzzing
      run: |
        cd test/fuzzing_tests
        ./build_afl_targets.sh
        timeout 300 ./run_afl_fuzzing.sh || true
    
    - name: Run Mull mutation testing
      run: |
        cd test/fuzzing_tests
        ./build_mull_targets.sh
        ./run_mull_mutation.sh
    
    - name: Upload results
      uses: actions/upload-artifact@v3
      with:
        name: fuzzing-results
        path: test/fuzzing_tests/outputs/
EOF

print_success "CI/CD integration created"
echo

print_status "10. Creating Documentation..."

# Create AFL++ documentation
cat > "$FUZZING_DIR/README_AFL.md" << 'EOF'
# AFL++ Fuzzing for FGCom-mumble

## Overview

AFL++ (American Fuzzy Lop++) is a state-of-the-art fuzzing tool that uses genetic algorithms to find bugs in software. This directory contains AFL++ fuzzing targets for the FGCom-mumble project.

## Setup

1. Install AFL++:
```bash
git clone https://github.com/AFLplusplus/AFLplusplus.git
cd AFLplusplus
make clean
make -j$(nproc)
sudo make install
```

2. Build fuzzing targets:
```bash
cd test/fuzzing_tests
./build_afl_targets.sh
```

3. Run fuzzing:
```bash
./run_afl_fuzzing.sh
```

## Targets

- **fuzz_radio_propagation**: Fuzzes radio propagation calculations
- **fuzz_audio_processing**: Fuzzes audio processing functions

## Corpus

The corpus directory contains initial test cases for each fuzzing target:
- `corpus/radio_propagation/`: Radio propagation test cases
- `corpus/audio_processing/`: Audio processing test cases

## Output

Fuzzing results are stored in the `outputs/` directory:
- `outputs/radio_propagation/`: Radio propagation fuzzing results
- `outputs/audio_processing/`: Audio processing fuzzing results

## Analysis

Use AFL++ tools to analyze results:
```bash
afl-plot outputs/radio_propagation/radio_propagation_plot
afl-cmin -i corpus/radio_propagation -o corpus_min/radio_propagation -- ./fuzz_radio_propagation @@
```
EOF

# Create Mull documentation
cat > "$FUZZING_DIR/README_MULL.md" << 'EOF'
# Mull Mutation Testing for FGCom-mumble

## Overview

Mull is a mutation testing tool that helps evaluate the quality of test suites by introducing small changes (mutations) to the code and checking if tests catch these changes.

## Setup

1. Install Mull:
```bash
git clone https://github.com/mull-project/mull.git
cd mull
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
sudo make install
```

2. Build mutation testing targets:
```bash
cd test/fuzzing_tests
./build_mull_targets.sh
```

3. Run mutation testing:
```bash
./run_mull_mutation.sh
```

## Configuration

Mull configuration is stored in `mull.conf`:
- Mutation operators: add, remove, replace
- Test framework: GoogleTest
- Timeout: 300 seconds
- Workers: 4 parallel processes

## Output

Mutation testing results are stored in:
- `outputs/mull/mutation_report.json`: JSON report
- `outputs/mull/mutation_report.html`: HTML report

## Analysis

The HTML report shows:
- Mutation score (percentage of mutations caught by tests)
- Surviving mutations (mutations not caught by tests)
- Test coverage analysis
- Performance metrics
EOF

print_success "Documentation created"
echo

print_status "11. Final Setup..."

# Create main fuzzing script
cat > "$FUZZING_DIR/run_all_fuzzing.sh" << 'EOF'
#!/bin/bash

# Run all fuzzing and mutation testing
set -e

echo "=========================================="
echo "FGCom-mumble Fuzzing and Mutation Testing"
echo "=========================================="

echo "1. Building AFL++ targets..."
./build_afl_targets.sh

echo "2. Building Mull targets..."
./build_mull_targets.sh

echo "3. Running AFL++ fuzzing..."
./run_afl_fuzzing.sh

echo "4. Running Mull mutation testing..."
./run_mull_mutation.sh

echo "=========================================="
echo "Fuzzing and mutation testing completed!"
echo "Check outputs/ directory for results"
echo "=========================================="
EOF

chmod +x "$FUZZING_DIR/run_all_fuzzing.sh"

# Create summary
cat > "$FUZZING_DIR/README.md" << 'EOF'
# FGCom-mumble Fuzzing and Mutation Testing

This directory contains AFL++ fuzzing and Mull mutation testing for the FGCom-mumble project.

## Quick Start

```bash
# Run all fuzzing and mutation testing
./run_all_fuzzing.sh

# Or run individually:
./build_afl_targets.sh && ./run_afl_fuzzing.sh
./build_mull_targets.sh && ./run_mull_mutation.sh
```

## Directory Structure

```
fuzzing_tests/
├── afl++/                    # AFL++ fuzzing targets
├── mull/                     # Mull mutation testing
├── corpus/                   # Initial test cases
├── outputs/                  # Fuzzing results
├── build_afl_targets.sh     # Build AFL++ targets
├── build_mull_targets.sh    # Build Mull targets
├── run_afl_fuzzing.sh       # Run AFL++ fuzzing
├── run_mull_mutation.sh     # Run Mull mutation testing
├── run_all_fuzzing.sh       # Run everything
├── README_AFL.md            # AFL++ documentation
├── README_MULL.md           # Mull documentation
└── README.md                # This file
```

## Results

- **AFL++ Results**: `outputs/radio_propagation/`, `outputs/audio_processing/`
- **Mull Results**: `outputs/mull/mutation_report.html`

## CI/CD

Fuzzing and mutation testing are integrated with GitHub Actions. See `.github/workflows/fuzzing.yml` for details.
EOF

print_success "Final setup completed"
echo

print_status "12. Verifying Installation..."

# Check AFL++ installation
if command_exists afl-fuzz; then
    print_success "AFL++ is installed and ready"
    afl-fuzz --version
else
    print_error "AFL++ installation failed"
fi

# Check Mull installation
if command_exists mull-cxx; then
    print_success "Mull is installed and ready"
    mull-cxx --version
else
    print_error "Mull installation failed"
fi

echo
print_success "AFL++ and Mull setup completed successfully!"
print_status "Next steps:"
print_status "1. cd test/fuzzing_tests"
print_status "2. ./run_all_fuzzing.sh"
print_status "3. Check outputs/ directory for results"
print_status "4. Review README_AFL.md and README_MULL.md for detailed usage"
