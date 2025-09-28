#include <iostream>
#include <cassert>
#include <vector>
#include <string>
#include "lib/soviet_vhf_equipment.h"

using namespace SovietVHF;

// Test framework
class TestFramework {
public:
    static int tests_run;
    static int tests_passed;
    static int tests_failed;
    
    static void runTest(const std::string& testName, bool result) {
        tests_run++;
        if (result) {
            tests_passed++;
            std::cout << "✓ " << testName << " PASSED" << std::endl;
        } else {
            tests_failed++;
            std::cout << "✗ " << testName << " FAILED" << std::endl;
        }
    }
    
    static void printResults() {
        std::cout << "\n=== SOVIET VHF EQUIPMENT TEST RESULTS ===" << std::endl;
        std::cout << "Tests run: " << tests_run << std::endl;
        std::cout << "Tests passed: " << tests_passed << std::endl;
        std::cout << "Tests failed: " << tests_failed << std::endl;
        std::cout << "Success rate: " << (tests_passed * 100.0 / tests_run) << "%" << std::endl;
    }
};

int TestFramework::tests_run = 0;
int TestFramework::tests_passed = 0;
int TestFramework::tests_failed = 0;

// Test R-105M Radio
void testR105M_Radio() {
    std::cout << "\n=== Testing R-105M Radio ===" << std::endl;
    
    R105M_Radio radio(true); // Portable mode
    
    // Test channel operations
    TestFramework::runTest("R-105M: Set valid channel", radio.setChannel(1));
    TestFramework::runTest("R-105M: Get current channel", radio.getCurrentChannel() == 1);
    TestFramework::runTest("R-105M: Set invalid channel (too low)", !radio.setChannel(0));
    TestFramework::runTest("R-105M: Set invalid channel (too high)", !radio.setChannel(405));
    TestFramework::runTest("R-105M: Set maximum channel", radio.setChannel(404));
    
    // Test frequency calculations
    radio.setChannel(1);
    TestFramework::runTest("R-105M: Channel 1 frequency", 
        std::abs(radio.getCurrentFrequency() - 36.0) < 0.001);
    
    radio.setChannel(2);
    TestFramework::runTest("R-105M: Channel 2 frequency", 
        std::abs(radio.getCurrentFrequency() - 36.025) < 0.001);
    
    radio.setChannel(404);
    TestFramework::runTest("R-105M: Channel 404 frequency", 
        std::abs(radio.getCurrentFrequency() - 46.075) < 0.001);
    
    // Test power operations
    TestFramework::runTest("R-105M: Portable power", 
        std::abs(radio.getCurrentPower() - 1.5) < 0.001);
    TestFramework::runTest("R-105M: Portable mode", radio.isPortableMode());
    
    radio.setPortableMode(false);
    TestFramework::runTest("R-105M: Vehicle power", 
        std::abs(radio.getCurrentPower() - 20.0) < 0.001);
    TestFramework::runTest("R-105M: Vehicle mode", !radio.isPortableMode());
    
    // Test operational status
    TestFramework::runTest("R-105M: Initial operational", radio.isRadioOperational());
    radio.setOperational(false);
    TestFramework::runTest("R-105M: Set non-operational", !radio.isRadioOperational());
    
    // Test specifications
    TestFramework::runTest("R-105M: Model name", R105M_Radio::getModelName() == "R-105M");
    TestFramework::runTest("R-105M: Total channels", R105M_Radio::getTotalChannels() == 404);
    TestFramework::runTest("R-105M: Frequency range", 
        std::abs(R105M_Radio::getFrequencyRange() - 10.1) < 0.001);
}

// Test R-105D Radio
void testR105D_Radio() {
    std::cout << "\n=== Testing R-105D Radio ===" << std::endl;
    
    R105D_Radio radio(true); // Portable mode
    
    // Test channel operations
    TestFramework::runTest("R-105D: Set valid channel", radio.setChannel(1));
    TestFramework::runTest("R-105D: Get current channel", radio.getCurrentChannel() == 1);
    TestFramework::runTest("R-105D: Set invalid channel (too low)", !radio.setChannel(0));
    TestFramework::runTest("R-105D: Set invalid channel (too high)", !radio.setChannel(637));
    TestFramework::runTest("R-105D: Set maximum channel", radio.setChannel(636));
    
    // Test frequency calculations
    radio.setChannel(1);
    TestFramework::runTest("R-105D: Channel 1 frequency", 
        std::abs(radio.getCurrentFrequency() - 20.0) < 0.001);
    
    radio.setChannel(2);
    TestFramework::runTest("R-105D: Channel 2 frequency", 
        std::abs(radio.getCurrentFrequency() - 20.025) < 0.001);
    
    radio.setChannel(636);
    TestFramework::runTest("R-105D: Channel 636 frequency", 
        std::abs(radio.getCurrentFrequency() - 35.875) < 0.001);
    
    // Test specifications
    TestFramework::runTest("R-105D: Model name", R105D_Radio::getModelName() == "R-105D");
    TestFramework::runTest("R-105D: Total channels", R105D_Radio::getTotalChannels() == 636);
    TestFramework::runTest("R-105D: Frequency range", 
        std::abs(R105D_Radio::getFrequencyRange() - 15.9) < 0.001);
}

// Test R-107 Radio
void testR107_Radio() {
    std::cout << "\n=== Testing R-107 Radio ===" << std::endl;
    
    R107_Radio radio;
    
    // Test channel operations
    TestFramework::runTest("R-107: Set valid channel", radio.setChannel(1));
    TestFramework::runTest("R-107: Get current channel", radio.getCurrentChannel() == 1);
    TestFramework::runTest("R-107: Set invalid channel (too low)", !radio.setChannel(0));
    TestFramework::runTest("R-107: Set invalid channel (too high)", !radio.setChannel(1281));
    TestFramework::runTest("R-107: Set maximum channel", radio.setChannel(1280));
    
    // Test frequency calculations
    radio.setChannel(1);
    TestFramework::runTest("R-107: Channel 1 frequency", 
        std::abs(radio.getCurrentFrequency() - 20.0) < 0.001);
    
    radio.setChannel(2);
    TestFramework::runTest("R-107: Channel 2 frequency", 
        std::abs(radio.getCurrentFrequency() - 20.025) < 0.001);
    
    radio.setChannel(1280);
    TestFramework::runTest("R-107: Channel 1280 frequency", 
        std::abs(radio.getCurrentFrequency() - 51.975) < 0.001);
    
    // Test mode operations
    TestFramework::runTest("R-107: Initial FM mode", radio.isFMMode());
    TestFramework::runTest("R-107: Initial CW mode", !radio.isCWMode());
    
    radio.setCWMode(true);
    TestFramework::runTest("R-107: Set CW mode", radio.isCWMode());
    TestFramework::runTest("R-107: FM mode disabled when CW enabled", !radio.isFMMode());
    
    radio.setFMMode(true);
    TestFramework::runTest("R-107: Set FM mode", radio.isFMMode());
    TestFramework::runTest("R-107: CW mode disabled when FM enabled", !radio.isCWMode());
    
    // Test power operations
    radio.setPower(10.0);
    TestFramework::runTest("R-107: Set power", std::abs(radio.getCurrentPower() - 10.0) < 0.001);
    
    radio.setPower(30.0); // Above maximum
    TestFramework::runTest("R-107: Power clamped to maximum", 
        std::abs(radio.getCurrentPower() - 25.0) < 0.001);
    
    radio.setPower(-5.0); // Below minimum
    TestFramework::runTest("R-107: Power clamped to minimum", 
        std::abs(radio.getCurrentPower() - 0.1) < 0.001);
    
    // Test specifications
    TestFramework::runTest("R-107: Model name", R107_Radio::getModelName() == "R-107");
    TestFramework::runTest("R-107: Total channels", R107_Radio::getTotalChannels() == 1280);
    TestFramework::runTest("R-107: Frequency range", 
        std::abs(R107_Radio::getFrequencyRange() - 32.0) < 0.001);
    TestFramework::runTest("R-107: Broadband capability", R107_Radio::isBroadband());
}

// Test R-123 Magnolia Radio
void testR123_Magnolia_Radio() {
    std::cout << "\n=== Testing R-123 Magnolia Radio ===" << std::endl;
    
    R123_Magnolia_Radio radio;
    
    // Test channel operations
    TestFramework::runTest("R-123: Set valid channel", radio.setChannel(1));
    TestFramework::runTest("R-123: Get current channel", radio.getCurrentChannel() == 1);
    TestFramework::runTest("R-123: Set invalid channel (too low)", !radio.setChannel(0));
    TestFramework::runTest("R-123: Set invalid channel (too high)", !radio.setChannel(1261));
    TestFramework::runTest("R-123: Set maximum channel", radio.setChannel(1260));
    
    // Test frequency calculations
    radio.setChannel(1);
    TestFramework::runTest("R-123: Channel 1 frequency", 
        std::abs(radio.getCurrentFrequency() - 20.0) < 0.001);
    
    radio.setChannel(2);
    TestFramework::runTest("R-123: Channel 2 frequency", 
        std::abs(radio.getCurrentFrequency() - 20.025) < 0.001);
    
    radio.setChannel(1260);
    TestFramework::runTest("R-123: Channel 1260 frequency", 
        std::abs(radio.getCurrentFrequency() - 51.475) < 0.001);
    
    // Test preset channel operations
    TestFramework::runTest("R-123: Get preset channel 0", radio.getPresetChannel(0) == 1);
    TestFramework::runTest("R-123: Get preset channel 1", radio.getPresetChannel(1) == 100);
    TestFramework::runTest("R-123: Get preset channel 2", radio.getPresetChannel(2) == 200);
    TestFramework::runTest("R-123: Get preset channel 3", radio.getPresetChannel(3) == 300);
    
    TestFramework::runTest("R-123: Set preset channel", radio.setPresetChannel(0, 50));
    TestFramework::runTest("R-123: Preset channel updated", radio.getPresetChannel(0) == 50);
    
    TestFramework::runTest("R-123: Set invalid preset", !radio.setPresetChannel(-1, 50));
    TestFramework::runTest("R-123: Set invalid preset", !radio.setPresetChannel(4, 50));
    TestFramework::runTest("R-123: Set invalid channel for preset", !radio.setPresetChannel(0, 0));
    
    TestFramework::runTest("R-123: Select preset channel", radio.selectPresetChannel(1));
    TestFramework::runTest("R-123: Current channel after preset selection", radio.getCurrentChannel() == 100);
    
    TestFramework::runTest("R-123: Select invalid preset", !radio.selectPresetChannel(-1));
    TestFramework::runTest("R-123: Select invalid preset", !radio.selectPresetChannel(4));
    
    // Test manual tuning
    TestFramework::runTest("R-123: Initial manual tuning", !radio.isManualTuning());
    radio.setManualTuning(true);
    TestFramework::runTest("R-123: Set manual tuning", radio.isManualTuning());
    
    // Test power operations
    radio.setPower(10.0);
    TestFramework::runTest("R-123: Set power", std::abs(radio.getCurrentPower() - 10.0) < 0.001);
    
    radio.setPower(25.0); // Above maximum
    TestFramework::runTest("R-123: Power clamped to maximum", 
        std::abs(radio.getCurrentPower() - 15.0) < 0.001);
    
    // Test specifications
    TestFramework::runTest("R-123: Model name", R123_Magnolia_Radio::getModelName() == "R-123 Magnolia");
    TestFramework::runTest("R-123: Total channels", R123_Magnolia_Radio::getTotalChannels() == 1260);
    TestFramework::runTest("R-123: Preset channels", R123_Magnolia_Radio::getPresetChannels() == 4);
    TestFramework::runTest("R-123: Frequency range", 
        std::abs(R123_Magnolia_Radio::getFrequencyRange() - 31.5) < 0.001);
    TestFramework::runTest("R-123: Superheterodyne", R123_Magnolia_Radio::isSuperheterodyne());
}

// Test Channel Calculator
void testChannelCalculator() {
    std::cout << "\n=== Testing Channel Calculator ===" << std::endl;
    
    // Test frequency calculation
    double freq1 = SovietVHFChannelCalculator::calculateFrequency(1, 20.0, 25.0);
    TestFramework::runTest("Calculator: Channel 1 frequency", std::abs(freq1 - 20.0) < 0.001);
    
    double freq2 = SovietVHFChannelCalculator::calculateFrequency(2, 20.0, 25.0);
    TestFramework::runTest("Calculator: Channel 2 frequency", std::abs(freq2 - 20.025) < 0.001);
    
    double freq100 = SovietVHFChannelCalculator::calculateFrequency(100, 20.0, 25.0);
    TestFramework::runTest("Calculator: Channel 100 frequency", std::abs(freq100 - 22.475) < 0.001);
    
    // Test channel calculation
    int channel1 = SovietVHFChannelCalculator::calculateChannel(20.0, 20.0, 25.0);
    TestFramework::runTest("Calculator: Frequency 20.0 MHz channel", channel1 == 1);
    
    int channel2 = SovietVHFChannelCalculator::calculateChannel(20.025, 20.0, 25.0);
    TestFramework::runTest("Calculator: Frequency 20.025 MHz channel", channel2 == 2);
    
    int channel100 = SovietVHFChannelCalculator::calculateChannel(22.475, 20.0, 25.0);
    TestFramework::runTest("Calculator: Frequency 22.475 MHz channel", channel100 == 100);
    
    // Test frequency validation
    TestFramework::runTest("Calculator: Valid frequency", 
        SovietVHFChannelCalculator::isValidFrequency(25.0, 20.0, 30.0));
    TestFramework::runTest("Calculator: Invalid frequency (too low)", 
        !SovietVHFChannelCalculator::isValidFrequency(15.0, 20.0, 30.0));
    TestFramework::runTest("Calculator: Invalid frequency (too high)", 
        !SovietVHFChannelCalculator::isValidFrequency(35.0, 20.0, 30.0));
    
    // Test channel list generation
    std::vector<double> channels = SovietVHFChannelCalculator::getAllChannels(20.0, 20.1, 25.0);
    TestFramework::runTest("Calculator: Channel list size", channels.size() == 5);
    TestFramework::runTest("Calculator: First channel", std::abs(channels[0] - 20.0) < 0.001);
    TestFramework::runTest("Calculator: Last channel", std::abs(channels[4] - 20.1) < 0.001);
}

// Test channel count calculations
void testChannelCounts() {
    std::cout << "\n=== Testing Channel Count Calculations ===" << std::endl;
    
    // R-105M: 36.0-46.1 MHz, 25 kHz spacing
    double r105m_range = 46.1 - 36.0;
    int r105m_channels = static_cast<int>(r105m_range * 1000.0 / 25.0) + 1;
    TestFramework::runTest("R-105M: Channel count calculation", r105m_channels == 404);
    
    // R-105D: 20.0-35.9 MHz, 25 kHz spacing
    double r105d_range = 35.9 - 20.0;
    int r105d_channels = static_cast<int>(r105d_range * 1000.0 / 25.0) + 1;
    TestFramework::runTest("R-105D: Channel count calculation", r105d_channels == 636);
    
    // R-107: 20.0-52.0 MHz, 25 kHz spacing
    double r107_range = 52.0 - 20.0;
    int r107_channels = static_cast<int>(r107_range * 1000.0 / 25.0) + 1;
    TestFramework::runTest("R-107: Channel count calculation", r107_channels == 1280);
    
    // R-123: 20.0-51.5 MHz, 25 kHz spacing
    double r123_range = 51.5 - 20.0;
    int r123_channels = static_cast<int>(r123_range * 1000.0 / 25.0) + 1;
    TestFramework::runTest("R-123: Channel count calculation", r123_channels == 1260);
}

int main() {
    std::cout << "=== SOVIET VHF EQUIPMENT COMPREHENSIVE TEST SUITE ===" << std::endl;
    std::cout << "Testing Soviet/Warsaw Pact VHF radio equipment implementation" << std::endl;
    
    // Run all test suites
    testR105M_Radio();
    testR105D_Radio();
    testR107_Radio();
    testR123_Magnolia_Radio();
    testChannelCalculator();
    testChannelCounts();
    
    // Print final results
    TestFramework::printResults();
    
    if (TestFramework::tests_failed == 0) {
        std::cout << "\nALL TESTS PASSED! Soviet VHF equipment implementation is working correctly." << std::endl;
        return 0;
    } else {
        std::cout << "\nSome tests failed. Please review the implementation." << std::endl;
        return 1;
    }
}
