#!/bin/bash

# Script to add AFL++ fuzzing and Mull mutation testing to all test modules
# This script automatically updates CMakeLists.txt files and creates fuzzing targets

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

print_status "Adding AFL++ and Mull integration to all test modules in $PROJECT_ROOT"

# List of test modules to update
TEST_MODULES=(
    "agc_squelch_tests"
    "antenna_pattern_module_tests"
    "atis_module_tests"
    "audio_processing_tests"
    "client_plugin_module_tests"
    "database_configuration_module_tests"
    "error_handling_tests"
    "frequency_management_tests"
    "geographic_module_tests"
    "integration_tests"
    "network_module_tests"
    "openstreetmap_infrastructure_tests"
    "performance_tests"
    "professional_audio_tests"
    "radio_propagation_tests"
    "security_module_tests"
    "status_page_module_tests"
    "webrtc_api_tests"
    "work_unit_distribution_module_tests"
)

# Function to update CMakeLists.txt for fuzzing
update_cmake_for_fuzzing() {
    local module_dir="$TEST_DIR/$1"
    local cmake_file="$module_dir/CMakeLists.txt"
    
    if [ ! -f "$cmake_file" ]; then
        print_warning "CMakeLists.txt not found for $1, skipping"
        return
    fi
    
    print_status "Adding fuzzing support to CMakeLists.txt for $1"
    
    # Create backup
    cp "$cmake_file" "$cmake_file.backup"
    
    # Check if fuzzing is already added
    if grep -q "FUZZING_SUPPORT" "$cmake_file"; then
        print_warning "Fuzzing already added to $1, skipping"
        return
    fi
    
    # Add fuzzing support after find_package calls
    sed -i '/find_package.*REQUIRED/a\
\
# Fuzzing support\
option(ENABLE_FUZZING "Enable AFL++ fuzzing and Mull mutation testing" OFF)\
option(ENABLE_AFL "Enable AFL++ fuzzing" OFF)\
option(ENABLE_MULL "Enable Mull mutation testing" OFF)\
\
# AFL++ configuration\
if(ENABLE_AFL OR ENABLE_FUZZING)\
    find_program(AFL_CC afl-clang-fast)\
    find_program(AFL_CXX afl-clang-fast++)\
    if(AFL_CC AND AFL_CXX)\
        set(CMAKE_C_COMPILER ${AFL_CC})\
        set(CMAKE_CXX_COMPILER ${AFL_CXX})\
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3 -g -fsanitize=address,undefined")\
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -g -fsanitize=address,undefined")\
        message(STATUS "AFL++ fuzzing enabled")\
    else()\
        message(WARNING "AFL++ not found, fuzzing disabled")\
    endif()\
endif()\
\
# Mull configuration\
if(ENABLE_MULL OR ENABLE_FUZZING)\
    find_program(MULL_CXX mull-cxx)\
    if(MULL_CXX)\
        message(STATUS "Mull mutation testing enabled")\
    else()\
        message(WARNING "Mull not found, mutation testing disabled")\
    endif()\
endif()\
' "$cmake_file"
    
    # Add fuzzing targets
    sed -i '/add_executable.*{/a\
\
# Fuzzing targets\
if(ENABLE_AFL OR ENABLE_FUZZING)\
    add_executable(fuzz_${1} fuzz_${1}.cpp)\
    target_compile_options(fuzz_${1} PRIVATE -O3 -g -fsanitize=address,undefined)\
    target_link_libraries(fuzz_${1} ${GTEST_GMOCK_LIBRARIES} Threads::Threads m pthread)\
endif()\
\
# Mutation testing targets\
if(ENABLE_MULL OR ENABLE_FUZZING)\
    add_executable(mutation_${1} mutation_${1}.cpp)\
    target_compile_options(mutation_${1} PRIVATE -O2 -g)\
    target_link_libraries(mutation_${1} ${GTEST_GMOCK_LIBRARIES} Threads::Threads m pthread)\
endif()\
' "$cmake_file"
    
    print_success "Updated CMakeLists.txt for fuzzing support in $1"
}

# Function to create AFL++ fuzzing target
create_afl_target() {
    local module_dir="$TEST_DIR/$1"
    local fuzz_file="$module_dir/fuzz_${1}.cpp"
    
    if [ -f "$fuzz_file" ]; then
        print_warning "AFL++ fuzzing target already exists for $1, skipping"
        return
    fi
    
    print_status "Creating AFL++ fuzzing target for $1"
    
    # Create AFL++ fuzzing target based on module type
    case "$1" in
        "agc_squelch_tests")
            create_agc_squelch_fuzzer "$fuzz_file"
            ;;
        "audio_processing_tests")
            create_audio_processing_fuzzer "$fuzz_file"
            ;;
        "radio_propagation_tests")
            create_radio_propagation_fuzzer "$fuzz_file"
            ;;
        "frequency_management_tests")
            create_frequency_management_fuzzer "$fuzz_file"
            ;;
        "antenna_pattern_module_tests")
            create_antenna_pattern_fuzzer "$fuzz_file"
            ;;
        *)
            create_generic_fuzzer "$fuzz_file" "$1"
            ;;
    esac
    
    print_success "Created AFL++ fuzzing target for $1"
}

# Function to create Mull mutation testing target
create_mull_target() {
    local module_dir="$TEST_DIR/$1"
    local mutation_file="$module_dir/mutation_${1}.cpp"
    
    if [ -f "$mutation_file" ]; then
        print_warning "Mull mutation testing target already exists for $1, skipping"
        return
    fi
    
    print_status "Creating Mull mutation testing target for $1"
    
    # Create Mull mutation testing target
    cat > "$mutation_file" << EOF
#include <gtest/gtest.h>
#include <rapidcheck.h>
#include <rapidcheck/gtest.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <cmath>
#include <algorithm>

// Mock classes for $1 mutation testing
class ${1^}Processor {
public:
    struct TestData {
        double value;
        std::string name;
        bool enabled;
    };
    
    // Functions to be mutated
    static bool isValidData(const TestData& data) {
        return data.value >= 0.0 && !data.name.empty() && data.enabled;
    }
    
    static double calculateResult(const TestData& data) {
        return data.value * 2.0;
    }
    
    static std::vector<double> processData(const std::vector<double>& input) {
        std::vector<double> result;
        for (double val : input) {
            result.push_back(val * 1.5);
        }
        return result;
    }
    
    static bool checkBounds(double value, double min_val, double max_val) {
        return value >= min_val && value <= max_val;
    }
};

// Unit tests for mutation testing
TEST(${1^}MutationTests, DataValidation) {
    ${1^}Processor::TestData data{10.0, "test", true};
    EXPECT_TRUE(${1^}Processor::isValidData(data));
}

TEST(${1^}MutationTests, CalculationResult) {
    ${1^}Processor::TestData data{5.0, "test", true};
    double result = ${1^}Processor::calculateResult(data);
    EXPECT_EQ(result, 10.0);
}

TEST(${1^}MutationTests, DataProcessing) {
    std::vector<double> input = {1.0, 2.0, 3.0};
    std::vector<double> result = ${1^}Processor::processData(input);
    EXPECT_EQ(result.size(), 3);
    EXPECT_EQ(result[0], 1.5);
}

TEST(${1^}MutationTests, BoundsChecking) {
    EXPECT_TRUE(${1^}Processor::checkBounds(5.0, 0.0, 10.0));
    EXPECT_FALSE(${1^}Processor::checkBounds(15.0, 0.0, 10.0));
}

// Property-based tests for mutation testing
RC_GTEST_PROP(${1^}MutationTests,
              DataValidationProperty,
              (${1^}Processor::TestData data)) {
    RC_PRE(data.value >= 0.0);
    RC_PRE(!data.name.empty());
    
    bool is_valid = ${1^}Processor::isValidData(data);
    RC_ASSERT(is_valid);
}

RC_GTEST_PROP(${1^}MutationTests,
              CalculationConsistency,
              (${1^}Processor::TestData data)) {
    RC_PRE(data.value >= 0.0);
    
    double result = ${1^}Processor::calculateResult(data);
    RC_ASSERT(result >= 0.0);
    RC_ASSERT(result == data.value * 2.0);
}

// Custom generators for mutation testing
namespace rc {
    template<>
    struct Arbitrary<${1^}Processor::TestData> {
        static Gen<${1^}Processor::TestData> arbitrary() {
            return gen::construct<${1^}Processor::TestData>(
                gen::inRange(0.0, 1000.0),     // value
                gen::arbitrary<std::string>(),  // name
                gen::arbitrary<bool>()         // enabled
            );
        }
    };
}
EOF
    
    print_success "Created Mull mutation testing target for $1"
}

# Function to create AGC/Squelch fuzzer
create_agc_squelch_fuzzer() {
    local fuzz_file="$1"
    
    cat > "$fuzz_file" << 'EOF'
#include <iostream>
#include <fstream>
#include <vector>
#include <cmath>
#include <cstring>

// Mock AGC/Squelch functions for fuzzing
class AGCProcessor {
public:
    static double applyGain(double input_db, double gain_db) {
        return input_db + gain_db;
    }
    
    static double applyCompression(double input_db, double threshold_db, double ratio) {
        if (input_db > threshold_db) {
            double excess = input_db - threshold_db;
            return threshold_db + excess / ratio;
        }
        return input_db;
    }
    
    static bool applySquelch(double input_db, double threshold_db) {
        return input_db >= threshold_db;
    }
    
    static double calculateRMS(const std::vector<double>& samples) {
        if (samples.empty()) return 0.0;
        double sum_squares = 0.0;
        for (double sample : samples) {
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
    double* params = reinterpret_cast<double*>(buffer.data());
    double input_db = params[0];
    double gain_db = params[1];
    double threshold_db = params[2];
    double ratio = params[3];
    
    // Create test samples
    std::vector<double> samples;
    for (size_t i = 4; i < buffer.size() / sizeof(double) && i < 1000; ++i) {
        samples.push_back(params[i]);
    }
    
    if (samples.empty()) {
        samples = {0.1, -0.1, 0.5, -0.5};
    }
    
    // Fuzz AGC/Squelch processing
    try {
        double gain_output = AGCProcessor::applyGain(input_db, gain_db);
        double compression_output = AGCProcessor::applyCompression(input_db, threshold_db, ratio);
        bool squelch_output = AGCProcessor::applySquelch(input_db, threshold_db);
        double rms = AGCProcessor::calculateRMS(samples);
        
        // Check for invalid results
        if (std::isnan(gain_output) || std::isinf(gain_output)) {
            return 1;
        }
        if (std::isnan(compression_output) || std::isinf(compression_output)) {
            return 1;
        }
        if (std::isnan(rms) || std::isinf(rms)) {
            return 1;
        }
        
    } catch (...) {
        return 1;
    }
    
    return 0;
}
EOF
}

# Function to create audio processing fuzzer
create_audio_processing_fuzzer() {
    local fuzz_file="$1"
    
    cat > "$fuzz_file" << 'EOF'
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
    
    static void applyLowPassFilter(std::vector<float>& samples, float cutoff_freq, float sample_rate) {
        float rc = 1.0f / (2.0f * M_PI * cutoff_freq);
        float dt = 1.0f / sample_rate;
        float alpha = dt / (rc + dt);
        
        float prev = 0.0f;
        for (auto& sample : samples) {
            sample = alpha * sample + (1.0f - alpha) * prev;
            prev = sample;
        }
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
    float cutoff_freq = params[3];
    float sample_rate = params[4];
    
    // Create test audio samples
    std::vector<float> samples;
    for (size_t i = 5; i < buffer.size() / sizeof(float) && i < 1000; ++i) {
        samples.push_back(params[i]);
    }
    
    if (samples.empty()) {
        samples = {0.1f, -0.1f, 0.5f, -0.5f, 0.8f, -0.8f};
    }
    
    // Fuzz audio processing
    try {
        AudioProcessor::applyGain(samples, gain_db);
        AudioProcessor::applyCompression(samples, threshold, ratio);
        AudioProcessor::applyLowPassFilter(samples, cutoff_freq, sample_rate);
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
}

# Function to create radio propagation fuzzer
create_radio_propagation_fuzzer() {
    local fuzz_file="$1"
    
    cat > "$fuzz_file" << 'EOF'
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
    
    static double calculateFresnelZone(double frequency_hz, double distance_m, double height_m) {
        const double c = 299792458.0;
        double wavelength = c / frequency_hz;
        return sqrt(wavelength * distance_m * height_m / (distance_m + height_m));
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
    
    if (buffer.size() < 32) {
        return 1; // Need at least 32 bytes for parameters
    }
    
    // Extract parameters
    double* params = reinterpret_cast<double*>(buffer.data());
    double frequency = params[0];
    double distance = params[1];
    double rain_rate = params[2];
    double lat1 = params[3];
    double lon1 = params[4];
    double alt1 = params[5];
    double lat2 = params[6];
    double lon2 = params[7];
    double alt2 = params[8];
    
    // Fuzz radio propagation calculations
    try {
        double path_loss = RadioPropagation::calculatePathLoss(frequency, distance);
        double attenuation = RadioPropagation::calculateAtmosphericAttenuation(frequency, rain_rate);
        bool los = RadioPropagation::hasLineOfSight(lat1, lon1, alt1, lat2, lon2, alt2);
        double fresnel = RadioPropagation::calculateFresnelZone(frequency, distance, alt1);
        
        // Check for invalid results
        if (std::isnan(path_loss) || std::isinf(path_loss)) {
            return 1;
        }
        if (std::isnan(attenuation) || std::isinf(attenuation)) {
            return 1;
        }
        if (std::isnan(fresnel) || std::isinf(fresnel)) {
            return 1;
        }
        
    } catch (...) {
        return 1;
    }
    
    return 0;
}
EOF
}

# Function to create frequency management fuzzer
create_frequency_management_fuzzer() {
    local fuzz_file="$1"
    
    cat > "$fuzz_file" << 'EOF'
#include <iostream>
#include <fstream>
#include <vector>
#include <cmath>
#include <algorithm>

// Mock frequency management functions for fuzzing
class FrequencyManager {
public:
    static bool isFrequencyInBand(double frequency_hz, double start_freq, double end_freq) {
        return frequency_hz >= start_freq && frequency_hz <= end_freq;
    }
    
    static bool isChannelSpacingCompliant(double frequency_hz, double start_freq, double spacing) {
        if (spacing <= 0.0) return true;
        double offset = fmod(frequency_hz - start_freq, spacing);
        return abs(offset) < 1e-6 || abs(offset - spacing) < 1e-6;
    }
    
    static double calculateFrequencyOffset(double base_freq, double offset_hz) {
        return base_freq + offset_hz;
    }
    
    static bool hasBandOverlap(double start1, double end1, double start2, double end2) {
        return !(end1 < start2 || end2 < start1);
    }
    
    static double calculateFrequencySeparation(double freq1, double freq2) {
        return abs(freq1 - freq2);
    }
    
    static bool isHarmonic(double base_freq, double test_freq, int harmonic_order) {
        if (harmonic_order <= 0) return false;
        double expected_freq = base_freq * harmonic_order;
        return abs(test_freq - expected_freq) < 1e-6;
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
    
    if (buffer.size() < 32) {
        return 1; // Need at least 32 bytes for parameters
    }
    
    // Extract parameters
    double* params = reinterpret_cast<double*>(buffer.data());
    double frequency = params[0];
    double start_freq = params[1];
    double end_freq = params[2];
    double spacing = params[3];
    double offset = params[4];
    double freq1 = params[5];
    double freq2 = params[6];
    double base_freq = params[7];
    double test_freq = params[8];
    int harmonic_order = static_cast<int>(params[9]);
    
    // Fuzz frequency management calculations
    try {
        bool in_band = FrequencyManager::isFrequencyInBand(frequency, start_freq, end_freq);
        bool spacing_ok = FrequencyManager::isChannelSpacingCompliant(frequency, start_freq, spacing);
        double offset_freq = FrequencyManager::calculateFrequencyOffset(frequency, offset);
        bool overlap = FrequencyManager::hasBandOverlap(start_freq, end_freq, freq1, freq2);
        double separation = FrequencyManager::calculateFrequencySeparation(freq1, freq2);
        bool harmonic = FrequencyManager::isHarmonic(base_freq, test_freq, harmonic_order);
        
        // Check for invalid results
        if (std::isnan(offset_freq) || std::isinf(offset_freq)) {
            return 1;
        }
        if (std::isnan(separation) || std::isinf(separation)) {
            return 1;
        }
        
    } catch (...) {
        return 1;
    }
    
    return 0;
}
EOF
}

# Function to create antenna pattern fuzzer
create_antenna_pattern_fuzzer() {
    local fuzz_file="$1"
    
    cat > "$fuzz_file" << 'EOF'
#include <iostream>
#include <fstream>
#include <vector>
#include <cmath>
#include <algorithm>

// Mock antenna pattern functions for fuzzing
class AntennaPattern {
public:
    static double getGainAt(double azimuth, double elevation, const std::vector<double>& pattern_data) {
        if (pattern_data.empty()) return 0.0;
        
        // Simple interpolation
        double min_distance = std::numeric_limits<double>::max();
        double closest_gain = 0.0;
        
        for (size_t i = 0; i < pattern_data.size(); i += 3) {
            if (i + 2 < pattern_data.size()) {
                double az = pattern_data[i];
                double el = pattern_data[i + 1];
                double gain = pattern_data[i + 2];
                
                double az_diff = abs(azimuth - az);
                double el_diff = abs(elevation - el);
                double distance = sqrt(az_diff * az_diff + el_diff * el_diff);
                
                if (distance < min_distance) {
                    min_distance = distance;
                    closest_gain = gain;
                }
            }
        }
        
        return closest_gain;
    }
    
    static double getMaximumGain(const std::vector<double>& pattern_data) {
        if (pattern_data.empty()) return 0.0;
        
        double max_gain = pattern_data[2]; // First gain value
        for (size_t i = 2; i < pattern_data.size(); i += 3) {
            if (i < pattern_data.size()) {
                max_gain = std::max(max_gain, pattern_data[i]);
            }
        }
        return max_gain;
    }
    
    static double get3dBBeamwidth(const std::vector<double>& pattern_data, double max_gain) {
        if (pattern_data.empty()) return 360.0;
        
        double threshold = max_gain - 3.0;
        std::vector<double> azimuths;
        
        for (size_t i = 0; i < pattern_data.size(); i += 3) {
            if (i + 2 < pattern_data.size() && pattern_data[i + 2] >= threshold) {
                azimuths.push_back(pattern_data[i]);
            }
        }
        
        if (azimuths.size() < 2) return 360.0;
        
        std::sort(azimuths.begin(), azimuths.end());
        return azimuths.back() - azimuths.front();
    }
    
    static double calculateSymmetry(const std::vector<double>& pattern_data) {
        if (pattern_data.empty()) return 0.0;
        
        double total_variance = 0.0;
        int count = 0;
        
        for (size_t i = 0; i < pattern_data.size(); i += 3) {
            if (i + 2 < pattern_data.size()) {
                double azimuth = pattern_data[i];
                double gain = pattern_data[i + 2];
                double opposite_azimuth = fmod(azimuth + 180.0, 360.0);
                
                // Find gain at opposite azimuth
                double opposite_gain = 0.0;
                for (size_t j = 0; j < pattern_data.size(); j += 3) {
                    if (j + 2 < pattern_data.size() && abs(pattern_data[j] - opposite_azimuth) < 1.0) {
                        opposite_gain = pattern_data[j + 2];
                        break;
                    }
                }
                
                double difference = abs(gain - opposite_gain);
                total_variance += difference * difference;
                count++;
            }
        }
        
        return count > 0 ? sqrt(total_variance / count) : 0.0;
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
        return 1; // Need at least 24 bytes for parameters
    }
    
    // Extract parameters
    double* params = reinterpret_cast<double*>(buffer.data());
    double azimuth = params[0];
    double elevation = params[1];
    
    // Create pattern data from remaining parameters
    std::vector<double> pattern_data;
    for (size_t i = 2; i < buffer.size() / sizeof(double) && i < 1000; ++i) {
        pattern_data.push_back(params[i]);
    }
    
    if (pattern_data.empty()) {
        // Create default pattern data
        pattern_data = {0, 0, 10, 90, 0, 8, 180, 0, 6, 270, 0, 4};
    }
    
    // Fuzz antenna pattern calculations
    try {
        double gain = AntennaPattern::getGainAt(azimuth, elevation, pattern_data);
        double max_gain = AntennaPattern::getMaximumGain(pattern_data);
        double beamwidth = AntennaPattern::get3dBBeamwidth(pattern_data, max_gain);
        double symmetry = AntennaPattern::calculateSymmetry(pattern_data);
        
        // Check for invalid results
        if (std::isnan(gain) || std::isinf(gain)) {
            return 1;
        }
        if (std::isnan(max_gain) || std::isinf(max_gain)) {
            return 1;
        }
        if (std::isnan(beamwidth) || std::isinf(beamwidth)) {
            return 1;
        }
        if (std::isnan(symmetry) || std::isinf(symmetry)) {
            return 1;
        }
        
    } catch (...) {
        return 1;
    }
    
    return 0;
}
EOF
}

# Function to create generic fuzzer
create_generic_fuzzer() {
    local fuzz_file="$1"
    local module_name="$2"
    
    cat > "$fuzz_file" << EOF
#include <iostream>
#include <fstream>
#include <vector>
#include <cmath>
#include <algorithm>

// Mock $module_name functions for fuzzing
class ${module_name^}Processor {
public:
    static double processData(double input, double param1, double param2) {
        return input * param1 + param2;
    }
    
    static bool validateInput(double value, double min_val, double max_val) {
        return value >= min_val && value <= max_val;
    }
    
    static std::vector<double> transformData(const std::vector<double>& input, double factor) {
        std::vector<double> result;
        for (double val : input) {
            result.push_back(val * factor);
        }
        return result;
    }
    
    static double calculateMetric(const std::vector<double>& data) {
        if (data.empty()) return 0.0;
        double sum = 0.0;
        for (double val : data) {
            sum += val;
        }
        return sum / data.size();
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
    double* params = reinterpret_cast<double*>(buffer.data());
    double input = params[0];
    double param1 = params[1];
    double param2 = params[2];
    double min_val = params[3];
    double max_val = params[4];
    
    // Create test data
    std::vector<double> test_data;
    for (size_t i = 5; i < buffer.size() / sizeof(double) && i < 1000; ++i) {
        test_data.push_back(params[i]);
    }
    
    if (test_data.empty()) {
        test_data = {1.0, 2.0, 3.0, 4.0, 5.0};
    }
    
    // Fuzz $module_name processing
    try {
        double result = ${module_name^}Processor::processData(input, param1, param2);
        bool valid = ${module_name^}Processor::validateInput(input, min_val, max_val);
        std::vector<double> transformed = ${module_name^}Processor::transformData(test_data, param1);
        double metric = ${module_name^}Processor::calculateMetric(test_data);
        
        // Check for invalid results
        if (std::isnan(result) || std::isinf(result)) {
            return 1;
        }
        if (std::isnan(metric) || std::isinf(metric)) {
            return 1;
        }
        
    } catch (...) {
        return 1;
    }
    
    return 0;
}
EOF
}

# Main execution
print_status "Starting AFL++ and Mull integration for all test modules..."

for module in "${TEST_MODULES[@]}"; do
    print_status "Processing module: $module"
    
    # Update CMakeLists.txt for fuzzing
    update_cmake_for_fuzzing "$module"
    
    # Create AFL++ fuzzing target
    create_afl_target "$module"
    
    # Create Mull mutation testing target
    create_mull_target "$module"
    
    print_success "Completed processing for $module"
    echo "---"
done

print_success "AFL++ and Mull integration completed for all test modules!"
print_status "Summary:"
print_status "- Updated CMakeLists.txt files to include fuzzing support"
print_status "- Created AFL++ fuzzing targets for each module"
print_status "- Created Mull mutation testing targets for each module"
print_status "- Added fuzzing configuration options"

print_warning "Note: The generated fuzzing targets are templates."
print_warning "You should customize them with specific functions for each module."

print_status "To build and run fuzzing:"
print_status "cd test/[module_name] && mkdir build && cd build"
print_status "cmake .. -DENABLE_FUZZING=ON"
print_status "make"
print_status "Then run: ./fuzz_[module_name] <input_file>"
print_status "Or run: ./mutation_[module_name]"
