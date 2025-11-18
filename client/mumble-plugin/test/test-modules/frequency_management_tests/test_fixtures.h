#ifndef TEST_FIXTURES_H
#define TEST_FIXTURES_H

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <thread>
#include <vector>
#include <chrono>
#include <memory>
#include <random>
#include <cmath>
#include <fstream>
#include <sstream>
#include <map>
#include <set>

// Include the frequency management modules
#include "../../client/mumble-plugin/lib/amateur_radio.h"
#include "../../client/mumble-plugin/lib/radio_model.h"

// Test fixtures and utilities
class Frequency_Management_Test : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize test parameters
        test_frequency_160m = 1830.0;    // 160m band
        test_frequency_80m = 3750.0;     // 80m band
        test_frequency_40m = 7150.0;     // 40m band
        test_frequency_20m = 14200.0;   // 20m band
        test_frequency_2m = 145.0;      // 2m band
        test_frequency_70cm = 435.0;    // 70cm band
        
        // Aviation frequencies
        test_frequency_emergency = 121.5;   // Emergency frequency
        test_frequency_guard = 243.0;       // Guard frequency
        test_frequency_civil_vhf = 118.0;   // Civil VHF
        
        // Maritime frequencies
        test_frequency_distress = 2182.0;    // Maritime distress
        test_frequency_working = 2187.5;    // Maritime working
        
        // ITU regions
        itu_region_1 = 1; // Europe/Africa
        itu_region_2 = 2; // Americas
        itu_region_3 = 3; // Asia-Pacific
        
        // License classes
        license_foundation = "Foundation";
        license_intermediate = "Intermediate";
        license_full = "Full";
        license_extra = "Extra";
        
        // Operating modes
        mode_cw = "CW";
        mode_ssb = "SSB";
        mode_fm = "FM";
        mode_am = "AM";
        mode_digital = "Digital";
    }
    
    void TearDown() override {
        // Clean up after each test
    }
    
    // Test frequencies
    double test_frequency_160m, test_frequency_80m, test_frequency_40m;
    double test_frequency_20m, test_frequency_2m, test_frequency_70cm;
    double test_frequency_emergency, test_frequency_guard, test_frequency_civil_vhf;
    double test_frequency_distress, test_frequency_working;
    
    // ITU regions
    int itu_region_1, itu_region_2, itu_region_3;
    
    // License classes
    std::string license_foundation, license_intermediate, license_full, license_extra;
    
    // Operating modes
    std::string mode_cw, mode_ssb, mode_fm, mode_am, mode_digital;
    
    // Helper functions for test data generation
    struct BandSegment {
        std::string band;
        std::string mode;
        double start_freq;
        double end_freq;
        int itu_region;
        std::string country;
        std::string license_class;
        double power_limit;
        std::string notes;
    };
    
    std::vector<BandSegment> generateAmateurBandSegments() {
        std::vector<BandSegment> segments;
        
        // 160m band segments
        segments.push_back({"160m", "CW", 1810.0, 1820.0, 1, "UK", "Foundation", 10.0, "CW only"});
        segments.push_back({"160m", "SSB", 1838.0, 1890.0, 1, "UK", "Intermediate", 100.0, "SSB only"});
        segments.push_back({"160m", "CW", 1800.0, 1900.0, 2, "USA", "Full", 1500.0, "Full power"});
        
        // 80m band segments
        segments.push_back({"80m", "CW", 3500.0, 3600.0, 1, "UK", "Foundation", 10.0, "CW only"});
        segments.push_back({"80m", "SSB", 3600.0, 3650.0, 1, "UK", "Intermediate", 100.0, "SSB only"});
        segments.push_back({"80m", "CW", 3500.0, 3600.0, 2, "USA", "Full", 1500.0, "Full power"});
        
        // 40m band segments
        segments.push_back({"40m", "CW", 7000.0, 7100.0, 1, "UK", "Foundation", 10.0, "CW only"});
        segments.push_back({"40m", "SSB", 7100.0, 7150.0, 1, "UK", "Intermediate", 100.0, "SSB only"});
        segments.push_back({"40m", "CW", 7000.0, 7100.0, 2, "USA", "Full", 1500.0, "Full power"});
        
        // 20m band segments
        segments.push_back({"20m", "CW", 14000.0, 14100.0, 1, "UK", "Foundation", 10.0, "CW only"});
        segments.push_back({"20m", "SSB", 14100.0, 14150.0, 1, "UK", "Intermediate", 100.0, "SSB only"});
        segments.push_back({"20m", "CW", 14000.0, 14100.0, 2, "USA", "Full", 1500.0, "Full power"});
        
        // 2m band segments
        segments.push_back({"2m", "FM", 144.0, 146.0, 1, "UK", "Foundation", 10.0, "FM only"});
        segments.push_back({"2m", "USB", 144.0, 148.0, 1, "UK", "Intermediate", 100.0, "USB SSB"});
        segments.push_back({"2m", "NFM", 144.0, 148.0, 1, "UK", "Intermediate", 100.0, "Narrow FM"});
        segments.push_back({"2m", "FM", 144.0, 146.0, 2, "USA", "Full", 1500.0, "Full power"});
        
        // 70cm band segments
        segments.push_back({"70cm", "FM", 430.0, 440.0, 1, "UK", "Foundation", 10.0, "FM only"});
        segments.push_back({"70cm", "USB", 430.0, 440.0, 1, "UK", "Intermediate", 100.0, "USB SSB"});
        segments.push_back({"70cm", "NFM", 430.0, 440.0, 1, "UK", "Intermediate", 100.0, "Narrow FM"});
        segments.push_back({"70cm", "FM", 430.0, 440.0, 2, "USA", "Full", 1500.0, "Full power"});
        
        // ITU Region 3 (Asia-Pacific) segments
        segments.push_back({"160m", "CW", 1810.0, 1838.0, 3, "Japan", "Foundation", 10.0, "CW only"});
        segments.push_back({"80m", "CW", 3500.0, 3570.0, 3, "Australia", "Foundation", 10.0, "CW only"});
        segments.push_back({"40m", "CW", 7000.0, 7100.0, 3, "China", "Foundation", 10.0, "CW only"});
        segments.push_back({"20m", "CW", 14000.0, 14100.0, 3, "India", "Foundation", 10.0, "CW only"});
        segments.push_back({"2m", "FM", 144.0, 146.0, 3, "South Korea", "Foundation", 10.0, "FM only"});
        segments.push_back({"70cm", "FM", 430.0, 440.0, 3, "Thailand", "Foundation", 10.0, "FM only"});
        
        // Additional countries for testing
        segments.push_back({"160m", "CW", 1810.0, 1838.0, 1, "Germany", "Foundation", 10.0, "CW only"});
        segments.push_back({"80m", "CW", 3500.0, 3570.0, 2, "Canada", "Foundation", 10.0, "CW only"});
        
        // Extra license class segments
        segments.push_back({"160m", "CW", 1800.0, 1900.0, 1, "UK", "Extra", 100.0, "Full power"});
        segments.push_back({"80m", "CW", 3500.0, 3600.0, 1, "UK", "Extra", 100.0, "Full power"});
        segments.push_back({"40m", "CW", 7000.0, 7100.0, 1, "UK", "Extra", 100.0, "Full power"});
        segments.push_back({"20m", "CW", 14000.0, 14100.0, 1, "UK", "Extra", 100.0, "Full power"});
        
        return segments;
    }
    
    std::vector<BandSegment> generateAviationFrequencies() {
        std::vector<BandSegment> frequencies;
        
        // Civil VHF frequencies
        frequencies.push_back({"VHF", "AM", 118.0, 137.0, 1, "ICAO", "Pilot", 25.0, "Civil aviation"});
        frequencies.push_back({"VHF", "AM", 118.0, 137.0, 2, "ICAO", "Pilot", 25.0, "Civil aviation"});
        frequencies.push_back({"VHF", "AM", 118.0, 137.0, 3, "ICAO", "Pilot", 25.0, "Civil aviation"});
        
        // Emergency frequencies - using frequency ranges
        frequencies.push_back({"Emergency", "AM", 121.0, 122.0, 1, "ICAO", "Emergency", 25.0, "Emergency guard"});
        frequencies.push_back({"Emergency", "AM", 121.0, 122.0, 2, "ICAO", "Emergency", 25.0, "Emergency guard"});
        frequencies.push_back({"Emergency", "AM", 121.0, 122.0, 3, "ICAO", "Emergency", 25.0, "Emergency guard"});
        
        // Guard frequencies - using frequency ranges
        frequencies.push_back({"Guard", "AM", 242.0, 244.0, 1, "NATO", "Military", 25.0, "Military guard"});
        frequencies.push_back({"Guard", "AM", 242.0, 244.0, 2, "NATO", "Military", 25.0, "Military guard"});
        frequencies.push_back({"Guard", "AM", 242.0, 244.0, 3, "NATO", "Military", 25.0, "Military guard"});
        
        return frequencies;
    }
    
    std::vector<BandSegment> generateMaritimeFrequencies() {
        std::vector<BandSegment> frequencies;
        
        // Maritime HF frequencies - using frequency ranges but keeping expected start frequencies
        frequencies.push_back({"Maritime HF", "SSB", 2182.0, 2185.0, 1, "ITU", "Maritime", 100.0, "Distress frequency"});
        frequencies.push_back({"Maritime HF", "SSB", 2187.5, 2190.0, 1, "ITU", "Maritime", 100.0, "Working frequency"});
        frequencies.push_back({"Maritime HF", "SSB", 4125.0, 4130.0, 1, "ITU", "Maritime", 100.0, "Distress frequency"});
        frequencies.push_back({"Maritime HF", "SSB", 6215.0, 6220.0, 1, "ITU", "Maritime", 100.0, "Working frequency"});
        frequencies.push_back({"Maritime HF", "SSB", 8291.0, 8295.0, 1, "ITU", "Maritime", 100.0, "Distress frequency"});
        frequencies.push_back({"Maritime HF", "SSB", 12290.0, 12295.0, 1, "ITU", "Maritime", 100.0, "Working frequency"});
        
        return frequencies;
    }
    
    // Helper to measure execution time
    template<typename Func>
    auto measureTime(Func&& func) -> decltype(func()) {
        auto start = std::chrono::high_resolution_clock::now();
        auto result = func();
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        std::cout << "Execution time: " << duration.count() << " microseconds" << std::endl;
        return result;
    }
};

// Test suite for band segment validation
class BandSegmentValidationTest : public Frequency_Management_Test {
protected:
    void SetUp() override {
        Frequency_Management_Test::SetUp();
    }
};

// Test suite for aviation frequencies
class AviationFrequencyTest : public Frequency_Management_Test {
protected:
    void SetUp() override {
        Frequency_Management_Test::SetUp();
    }
};

// Test suite for maritime frequencies
class MaritimeFrequencyTest : public Frequency_Management_Test {
protected:
    void SetUp() override {
        Frequency_Management_Test::SetUp();
    }
};

// Test suite for frequency offsets
class FrequencyOffsetTest : public Frequency_Management_Test {
protected:
    void SetUp() override {
        Frequency_Management_Test::SetUp();
    }
};

#endif // TEST_FIXTURES_H
