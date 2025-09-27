#include <iostream>
#include <string>
#include <vector>
#include <cassert>
#include "../lib/preset_channel_api.h"
#include "../lib/nato_vhf_equipment.h"

using namespace PresetChannelAPI;
using namespace NATO_VHF;

int main() {
    std::cout << "Testing Preset Channel API..." << std::endl;
    
    // Initialize the API
    PresetChannelManager::initialize();
    
    int testsPassed = 0;
    int testsTotal = 0;
    
    // Test 1: Create preset channel
    testsTotal++;
    bool result1 = PresetChannelManager::setPresetChannel("AN/PRC-152", 1, 100, "Tactical 1", "Primary tactical frequency");
    if (result1) {
        std::cout << "✓ Test 1 PASSED: Create preset channel" << std::endl;
        testsPassed++;
    } else {
        std::cout << "✗ Test 1 FAILED: Create preset channel" << std::endl;
    }
    
    // Test 2: Get preset channel
    testsTotal++;
    auto preset = PresetChannelManager::getPresetChannel("AN/PRC-152", 1);
    if (preset.presetNumber == 1 && preset.channelNumber == 100) {
        std::cout << "✓ Test 2 PASSED: Get preset channel" << std::endl;
        testsPassed++;
    } else {
        std::cout << "✗ Test 2 FAILED: Get preset channel" << std::endl;
    }
    
    // Test 3: Get all presets
    testsTotal++;
    auto allPresets = PresetChannelManager::getAllPresetChannels("AN/PRC-152");
    if (allPresets.size() == 1) {
        std::cout << "✓ Test 3 PASSED: Get all presets" << std::endl;
        testsPassed++;
    } else {
        std::cout << "✗ Test 3 FAILED: Get all presets" << std::endl;
    }
    
    // Test 4: Search presets
    testsTotal++;
    auto searchResults = PresetChannelManager::searchPresets("AN/PRC-152", "tactical");
    if (searchResults.size() == 1) {
        std::cout << "✓ Test 4 PASSED: Search presets" << std::endl;
        testsPassed++;
    } else {
        std::cout << "✗ Test 4 FAILED: Search presets" << std::endl;
    }
    
    // Test 5: Delete preset channel
    testsTotal++;
    bool result5 = PresetChannelManager::deletePresetChannel("AN/PRC-152", 1);
    if (result5) {
        std::cout << "✓ Test 5 PASSED: Delete preset channel" << std::endl;
        testsPassed++;
    } else {
        std::cout << "✗ Test 5 FAILED: Delete preset channel" << std::endl;
    }
    
    // Test 6: Verify deletion
    testsTotal++;
    auto deletedPreset = PresetChannelManager::getPresetChannel("AN/PRC-152", 1);
    if (deletedPreset.presetNumber == 0) {
        std::cout << "✓ Test 6 PASSED: Verify deletion" << std::endl;
        testsPassed++;
    } else {
        std::cout << "✗ Test 6 FAILED: Verify deletion" << std::endl;
    }
    
    // Test 7: Get preset count
    testsTotal++;
    int count = PresetChannelManager::getPresetCount("AN/PRC-152");
    if (count == 0) {
        std::cout << "✓ Test 7 PASSED: Get preset count" << std::endl;
        testsPassed++;
    } else {
        std::cout << "✗ Test 7 FAILED: Get preset count" << std::endl;
    }
    
    // Test 8: Export to JSON
    testsTotal++;
    std::string json = PresetChannelManager::exportPresetsToJSON("AN/PRC-152");
    if (json == "[]") {
        std::cout << "✓ Test 8 PASSED: Export to JSON" << std::endl;
        testsPassed++;
    } else {
        std::cout << "✗ Test 8 FAILED: Export to JSON" << std::endl;
    }
    
    // Test 9: Export to CSV
    testsTotal++;
    std::string csv = PresetChannelManager::exportPresetsToCSV("AN/PRC-152");
    if (csv == "PresetNumber,ChannelNumber,Frequency,Label,Description,IsActive\n") {
        std::cout << "✓ Test 9 PASSED: Export to CSV" << std::endl;
        testsPassed++;
    } else {
        std::cout << "✗ Test 9 FAILED: Export to CSV" << std::endl;
    }
    
    // Test 10: Backup presets
    testsTotal++;
    std::string backup = PresetChannelManager::backupPresets("AN/PRC-152");
    if (backup == "[]") {
        std::cout << "✓ Test 10 PASSED: Backup presets" << std::endl;
        testsPassed++;
    } else {
        std::cout << "✗ Test 10 FAILED: Backup presets" << std::endl;
    }
    
    // Print summary
    std::cout << "\n=== TEST SUMMARY ===" << std::endl;
    std::cout << "Total Tests: " << testsTotal << std::endl;
    std::cout << "Passed: " << testsPassed << std::endl;
    std::cout << "Failed: " << (testsTotal - testsPassed) << std::endl;
    std::cout << "Result: " << (testsPassed == testsTotal ? "ALL TESTS PASSED" : "SOME TESTS FAILED") << std::endl;
    
    return (testsPassed == testsTotal) ? 0 : 1;
}
