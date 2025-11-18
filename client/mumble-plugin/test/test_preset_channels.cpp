#include "TestFramework.h"
#include "../lib/preset_channel_api.h"
#include "../lib/nato_vhf_equipment.h"
#include <iostream>

// Test suite for Preset Channel API
TEST_SUITE(PresetChannelTest) {

    // Setup: Initialize the preset channel system before each test
    BEFORE_EACH() {
        PresetChannelAPI::PresetChannelManager::initialize();
    }

    // Test case: AN/PRC-152 preset channel creation
    TEST_CASE("AN/PRC-152 Preset Channel Creation") {
        // Test creating preset channels for AN/PRC-152
        bool result1 = PresetChannelAPI::PresetChannelManager::setPresetChannel(
            "AN/PRC-152", 1, 100, "Tactical 1", "Primary tactical frequency");
        ASSERT_TRUE(result1, "Create preset 1");
        
        bool result2 = PresetChannelAPI::PresetChannelManager::setPresetChannel(
            "AN/PRC-152", 2, 200, "Tactical 2", "Secondary tactical frequency");
        ASSERT_TRUE(result2, "Create preset 2");
        
        bool result3 = PresetChannelAPI::PresetChannelManager::setPresetChannel(
            "AN/PRC-152", 3, 300, "Emergency", "Emergency frequency");
        ASSERT_TRUE(result3, "Create preset 3");
        
        // Test getting preset channels
        auto preset1 = PresetChannelAPI::PresetChannelManager::getPresetChannel("AN/PRC-152", 1);
        ASSERT_EQ(preset1.presetNumber, 1, "Preset 1 number");
        ASSERT_EQ(preset1.channelNumber, 100, "Preset 1 channel");
        ASSERT_EQ(preset1.label, "Tactical 1", "Preset 1 label");
        ASSERT_EQ(preset1.description, "Primary tactical frequency", "Preset 1 description");
        ASSERT_TRUE(preset1.isActive, "Preset 1 active");
        
        auto preset2 = PresetChannelAPI::PresetChannelManager::getPresetChannel("AN/PRC-152", 2);
        ASSERT_EQ(preset2.presetNumber, 2, "Preset 2 number");
        ASSERT_EQ(preset2.channelNumber, 200, "Preset 2 channel");
        ASSERT_EQ(preset2.label, "Tactical 2", "Preset 2 label");
        
        auto preset3 = PresetChannelAPI::PresetChannelManager::getPresetChannel("AN/PRC-152", 3);
        ASSERT_EQ(preset3.presetNumber, 3, "Preset 3 number");
        ASSERT_EQ(preset3.channelNumber, 300, "Preset 3 channel");
        ASSERT_EQ(preset3.label, "Emergency", "Preset 3 label");
    }

    // Test case: AN/PRC-152 preset channel operations
    TEST_CASE("AN/PRC-152 Preset Channel Operations") {
        // Create some preset channels
        PresetChannelAPI::PresetChannelManager::setPresetChannel("AN/PRC-152", 1, 100, "Tactical 1");
        PresetChannelAPI::PresetChannelManager::setPresetChannel("AN/PRC-152", 2, 200, "Tactical 2");
        PresetChannelAPI::PresetChannelManager::setPresetChannel("AN/PRC-152", 3, 300, "Emergency");
        
        // Test preset selection
        bool select1 = PresetChannelAPI::PresetChannelManager::selectPresetChannel("AN/PRC-152", 1);
        ASSERT_TRUE(select1, "Select preset 1");
        
        bool select2 = PresetChannelAPI::PresetChannelManager::selectPresetChannel("AN/PRC-152", 2);
        ASSERT_TRUE(select2, "Select preset 2");
        
        // Test preset label updates
        bool label1 = PresetChannelAPI::PresetChannelManager::setPresetLabel("AN/PRC-152", 1, "Updated Tactical 1");
        ASSERT_TRUE(label1, "Update preset 1 label");
        
        bool label2 = PresetChannelAPI::PresetChannelManager::setPresetLabel("AN/PRC-152", 2, "Updated Tactical 2");
        ASSERT_TRUE(label2, "Update preset 2 label");
        
        // Test preset description updates
        bool desc1 = PresetChannelAPI::PresetChannelManager::setPresetDescription("AN/PRC-152", 1, "Updated primary tactical frequency");
        ASSERT_TRUE(desc1, "Update preset 1 description");
        
        // Test preset active status
        bool active1 = PresetChannelAPI::PresetChannelManager::setPresetActive("AN/PRC-152", 1, false);
        ASSERT_TRUE(active1, "Set preset 1 inactive");
        
        bool active2 = PresetChannelAPI::PresetChannelManager::setPresetActive("AN/PRC-152", 2, true);
        ASSERT_TRUE(active2, "Set preset 2 active");
        
        // Verify updates
        auto preset1 = PresetChannelAPI::PresetChannelManager::getPresetChannel("AN/PRC-152", 1);
        ASSERT_EQ(preset1.label, "Updated Tactical 1", "Preset 1 updated label");
        ASSERT_EQ(preset1.description, "Updated primary tactical frequency", "Preset 1 updated description");
        ASSERT_FALSE(preset1.isActive, "Preset 1 inactive");
        
        auto preset2 = PresetChannelAPI::PresetChannelManager::getPresetChannel("AN/PRC-152", 2);
        ASSERT_EQ(preset2.label, "Updated Tactical 2", "Preset 2 updated label");
        ASSERT_TRUE(preset2.isActive, "Preset 2 active");
    }

    // Test case: AN/PRC-152 preset channel search
    TEST_CASE("AN/PRC-152 Preset Channel Search") {
        // Create preset channels with different labels
        PresetChannelAPI::PresetChannelManager::setPresetChannel("AN/PRC-152", 1, 100, "Tactical 1", "Primary tactical frequency");
        PresetChannelAPI::PresetChannelManager::setPresetChannel("AN/PRC-152", 2, 200, "Tactical 2", "Secondary tactical frequency");
        PresetChannelAPI::PresetChannelManager::setPresetChannel("AN/PRC-152", 3, 300, "Emergency", "Emergency frequency");
        PresetChannelAPI::PresetChannelManager::setPresetChannel("AN/PRC-152", 4, 400, "Training", "Training frequency");
        PresetChannelAPI::PresetChannelManager::setPresetChannel("AN/PRC-152", 5, 500, "Test", "Test frequency");
        
        // Test search by label
        auto tacticalResults = PresetChannelAPI::PresetChannelManager::searchPresets("AN/PRC-152", "Tactical");
        ASSERT_EQ(tacticalResults.size(), 2, "Tactical search results");
        
        auto emergencyResults = PresetChannelAPI::PresetChannelManager::searchPresets("AN/PRC-152", "Emergency");
        ASSERT_EQ(emergencyResults.size(), 1, "Emergency search results");
        
        auto trainingResults = PresetChannelAPI::PresetChannelManager::searchPresets("AN/PRC-152", "Training");
        ASSERT_EQ(trainingResults.size(), 1, "Training search results");
        
        // Test search by description
        auto frequencyResults = PresetChannelAPI::PresetChannelManager::searchPresets("AN/PRC-152", "frequency");
        ASSERT_EQ(frequencyResults.size(), 5, "Frequency search results");
        
        // Test search by channel number
        auto channelResults = PresetChannelAPI::PresetChannelManager::getPresetsByChannel("AN/PRC-152", 100);
        ASSERT_EQ(channelResults.size(), 1, "Channel 100 search results");
        
        auto channelResults2 = PresetChannelAPI::PresetChannelManager::getPresetsByChannel("AN/PRC-152", 200);
        ASSERT_EQ(channelResults2.size(), 1, "Channel 200 search results");
    }

    // Test case: AN/PRC-152 preset channel statistics
    TEST_CASE("AN/PRC-152 Preset Channel Statistics") {
        // Create preset channels with different active status
        PresetChannelAPI::PresetChannelManager::setPresetChannel("AN/PRC-152", 1, 100, "Tactical 1");
        PresetChannelAPI::PresetChannelManager::setPresetChannel("AN/PRC-152", 2, 200, "Tactical 2");
        PresetChannelAPI::PresetChannelManager::setPresetChannel("AN/PRC-152", 3, 300, "Emergency");
        PresetChannelAPI::PresetChannelManager::setPresetChannel("AN/PRC-152", 4, 400, "Training");
        PresetChannelAPI::PresetChannelManager::setPresetChannel("AN/PRC-152", 5, 500, "Test");
        
        // Set some presets as inactive
        PresetChannelAPI::PresetChannelManager::setPresetActive("AN/PRC-152", 4, false);
        PresetChannelAPI::PresetChannelManager::setPresetActive("AN/PRC-152", 5, false);
        
        // Test preset counts
        int totalPresets = PresetChannelAPI::PresetChannelManager::getPresetCount("AN/PRC-152");
        ASSERT_EQ(totalPresets, 5, "Total preset count");
        
        int activePresets = PresetChannelAPI::PresetChannelManager::getActivePresetCount("AN/PRC-152");
        ASSERT_EQ(activePresets, 3, "Active preset count");
        
        int inactivePresets = PresetChannelAPI::PresetChannelManager::getInactivePresetCount("AN/PRC-152");
        ASSERT_EQ(inactivePresets, 2, "Inactive preset count");
        
        // Test active and inactive preset retrieval
        auto activePresetsList = PresetChannelAPI::PresetChannelManager::getActivePresets("AN/PRC-152");
        ASSERT_EQ(activePresetsList.size(), 3, "Active presets list size");
        
        auto inactivePresetsList = PresetChannelAPI::PresetChannelManager::getInactivePresets("AN/PRC-152");
        ASSERT_EQ(inactivePresetsList.size(), 2, "Inactive presets list size");
    }

    // Test case: AN/PRC-152 preset channel validation
    TEST_CASE("AN/PRC-152 Preset Channel Validation") {
        // Test valid preset channels
        bool valid1 = PresetChannelAPI::PresetChannelManager::validatePresetChannel("AN/PRC-152", 1, 100);
        ASSERT_TRUE(valid1, "Valid preset 1, channel 100");
        
        bool valid2 = PresetChannelAPI::PresetChannelManager::validatePresetChannel("AN/PRC-152", 50, 2500);
        ASSERT_TRUE(valid2, "Valid preset 50, channel 2500");
        
        bool valid3 = PresetChannelAPI::PresetChannelManager::validatePresetChannel("AN/PRC-152", 99, 4638);
        ASSERT_TRUE(valid3, "Valid preset 99, channel 4638");
        
        // Test invalid preset channels
        bool invalid1 = PresetChannelAPI::PresetChannelManager::validatePresetChannel("AN/PRC-152", 0, 100);
        ASSERT_FALSE(invalid1, "Invalid preset 0");
        
        bool invalid2 = PresetChannelAPI::PresetChannelManager::validatePresetChannel("AN/PRC-152", 100, 100);
        ASSERT_FALSE(invalid2, "Invalid preset 100");
        
        bool invalid3 = PresetChannelAPI::PresetChannelManager::validatePresetChannel("AN/PRC-152", 1, 0);
        ASSERT_FALSE(invalid3, "Invalid channel 0");
        
        bool invalid4 = PresetChannelAPI::PresetChannelManager::validatePresetChannel("AN/PRC-152", 1, 5000);
        ASSERT_FALSE(invalid4, "Invalid channel 5000");
    }

    // Test case: AN/PRC-152 preset channel export/import
    TEST_CASE("AN/PRC-152 Preset Channel Export/Import") {
        // Create preset channels
        PresetChannelAPI::PresetChannelManager::setPresetChannel("AN/PRC-152", 1, 100, "Tactical 1", "Primary tactical frequency");
        PresetChannelAPI::PresetChannelManager::setPresetChannel("AN/PRC-152", 2, 200, "Tactical 2", "Secondary tactical frequency");
        PresetChannelAPI::PresetChannelManager::setPresetChannel("AN/PRC-152", 3, 300, "Emergency", "Emergency frequency");
        
        // Test JSON export
        std::string jsonData = PresetChannelAPI::PresetChannelManager::exportPresetsToJSON("AN/PRC-152");
        ASSERT_FALSE(jsonData.empty(), "JSON export not empty");
        
        // Test CSV export
        std::string csvData = PresetChannelAPI::PresetChannelManager::exportPresetsToCSV("AN/PRC-152");
        ASSERT_FALSE(csvData.empty(), "CSV export not empty");
        
        // Test backup
        std::string backupData = PresetChannelAPI::PresetChannelManager::backupPresets("AN/PRC-152");
        ASSERT_FALSE(backupData.empty(), "Backup data not empty");
        
        // Test clear presets
        bool clearResult = PresetChannelAPI::PresetChannelManager::clearPresets("AN/PRC-152");
        ASSERT_TRUE(clearResult, "Clear presets");
        
        int presetCount = PresetChannelAPI::PresetChannelManager::getPresetCount("AN/PRC-152");
        ASSERT_EQ(presetCount, 0, "Preset count after clear");
        
        // Test restore
        bool restoreResult = PresetChannelAPI::PresetChannelManager::restorePresets("AN/PRC-152", backupData);
        ASSERT_TRUE(restoreResult, "Restore presets");
        
        int restoredCount = PresetChannelAPI::PresetChannelManager::getPresetCount("AN/PRC-152");
        ASSERT_EQ(restoredCount, 3, "Restored preset count");
    }

    // Test case: AN/PRC-152 preset channel builder
    TEST_CASE("AN/PRC-152 Preset Channel Builder") {
        // Test builder pattern
        PresetChannelAPI::PresetChannelBuilder builder;
        auto preset = builder
            .setPresetNumber(1)
            .setChannelNumber(100)
            .setFrequency(30.125)
            .setLabel("Tactical 1")
            .setDescription("Primary tactical frequency")
            .setActive(true)
            .addCustomProperty("encryption", "AES-256")
            .addCustomProperty("power", "high")
            .build();
        
        ASSERT_EQ(preset.presetNumber, 1, "Builder preset number");
        ASSERT_EQ(preset.channelNumber, 100, "Builder channel number");
        ASSERT_EQ(preset.frequency, 30.125, "Builder frequency");
        ASSERT_EQ(preset.label, "Tactical 1", "Builder label");
        ASSERT_EQ(preset.description, "Primary tactical frequency", "Builder description");
        ASSERT_TRUE(preset.isActive, "Builder active status");
        ASSERT_EQ(preset.customProperties.size(), 2, "Builder custom properties count");
        
        // Test validation
        bool isValid = builder.validate();
        ASSERT_TRUE(isValid, "Builder validation");
        
        auto errors = builder.getValidationErrors();
        ASSERT_EQ(errors.size(), 0, "Builder validation errors");
    }

    // Test case: AN/PRC-152 preset channel comparison
    TEST_CASE("AN/PRC-152 Preset Channel Comparison") {
        // Create preset channels for two different radio models
        PresetChannelAPI::PresetChannelManager::setPresetChannel("AN/PRC-152", 1, 100, "Tactical 1");
        PresetChannelAPI::PresetChannelManager::setPresetChannel("AN/PRC-152", 2, 200, "Tactical 2");
        PresetChannelAPI::PresetChannelManager::setPresetChannel("AN/PRC-77", 1, 100, "Tactical 1");
        PresetChannelAPI::PresetChannelManager::setPresetChannel("AN/PRC-77", 2, 200, "Tactical 2");
        PresetChannelAPI::PresetChannelManager::setPresetChannel("AN/PRC-77", 3, 300, "Emergency");
        
        // Test preset comparison
        auto comparison = PresetChannelAPI::PresetChannelManager::comparePresets("AN/PRC-152", "AN/PRC-77");
        ASSERT_FALSE(comparison.empty(), "Preset comparison not empty");
        
        // Test common presets
        auto commonPresets = PresetChannelAPI::PresetChannelManager::getCommonPresets("AN/PRC-152", "AN/PRC-77");
        ASSERT_EQ(commonPresets.size(), 2, "Common presets count");
        
        // Test unique presets
        auto uniquePresets = PresetChannelAPI::PresetChannelManager::getUniquePresets("AN/PRC-152", "AN/PRC-77");
        ASSERT_EQ(uniquePresets.size(), 1, "Unique presets count");
    }

    // Test case: AN/PRC-152 preset channel recommendations
    TEST_CASE("AN/PRC-152 Preset Channel Recommendations") {
        // Create preset channels
        PresetChannelAPI::PresetChannelManager::setPresetChannel("AN/PRC-152", 1, 100, "Tactical 1");
        PresetChannelAPI::PresetChannelManager::setPresetChannel("AN/PRC-152", 2, 200, "Tactical 2");
        PresetChannelAPI::PresetChannelManager::setPresetChannel("AN/PRC-152", 3, 300, "Emergency");
        PresetChannelAPI::PresetChannelManager::setPresetChannel("AN/PRC-152", 4, 400, "Training");
        PresetChannelAPI::PresetChannelManager::setPresetChannel("AN/PRC-152", 5, 500, "Test");
        
        // Test preset recommendations
        auto recommendations = PresetChannelAPI::PresetChannelManager::getPresetRecommendations("AN/PRC-152", "tactical");
        ASSERT_FALSE(recommendations.empty(), "Preset recommendations not empty");
        
        // Test popular presets
        auto popularPresets = PresetChannelAPI::PresetChannelManager::getPopularPresets("AN/PRC-152");
        ASSERT_FALSE(popularPresets.empty(), "Popular presets not empty");
        
        // Test recently used presets
        auto recentPresets = PresetChannelAPI::PresetChannelManager::getRecentlyUsedPresets("AN/PRC-152");
        ASSERT_FALSE(recentPresets.empty(), "Recent presets not empty");
    }

    // Test case: AN/PRC-152 preset channel frequency operations
    TEST_CASE("AN/PRC-152 Preset Channel Frequency Operations") {
        // Create preset channels with specific frequencies
        PresetChannelAPI::PresetChannelManager::setPresetFrequency("AN/PRC-152", 1, 30.125, "Tactical 1", "Primary tactical frequency");
        PresetChannelAPI::PresetChannelManager::setPresetFrequency("AN/PRC-152", 2, 30.25, "Tactical 2", "Secondary tactical frequency");
        PresetChannelAPI::PresetChannelManager::setPresetFrequency("AN/PRC-152", 3, 30.375, "Emergency", "Emergency frequency");
        
        // Test frequency-based search
        auto freqResults = PresetChannelAPI::PresetChannelManager::getPresetsByFrequency("AN/PRC-152", 30.125, 0.001);
        ASSERT_EQ(freqResults.size(), 1, "Frequency 30.125 search results");
        
        auto freqResults2 = PresetChannelAPI::PresetChannelManager::getPresetsByFrequency("AN/PRC-152", 30.25, 0.001);
        ASSERT_EQ(freqResults2.size(), 1, "Frequency 30.25 search results");
        
        // Test frequency range search
        auto freqRangeResults = PresetChannelAPI::PresetChannelManager::getPresetsByFrequency("AN/PRC-152", 30.0, 0.5);
        ASSERT_EQ(freqRangeResults.size(), 3, "Frequency range 30.0-30.5 search results");
        
        // Test frequency validation
        bool validFreq1 = PresetChannelAPI::PresetChannelManager::validatePresetFrequency("AN/PRC-152", 1, 30.125);
        ASSERT_TRUE(validFreq1, "Valid frequency 30.125");
        
        bool validFreq2 = PresetChannelAPI::PresetChannelManager::validatePresetFrequency("AN/PRC-152", 2, 30.25);
        ASSERT_TRUE(validFreq2, "Valid frequency 30.25");
        
        bool invalidFreq = PresetChannelAPI::PresetChannelManager::validatePresetFrequency("AN/PRC-152", 1, 25.0);
        ASSERT_FALSE(invalidFreq, "Invalid frequency 25.0");
    }

    // Test case: AN/PRC-152 preset channel error handling
    TEST_CASE("AN/PRC-152 Preset Channel Error Handling") {
        // Test getting non-existent preset
        auto nonExistent = PresetChannelAPI::PresetChannelManager::getPresetChannel("AN/PRC-152", 999);
        ASSERT_EQ(nonExistent.presetNumber, 0, "Non-existent preset number");
        ASSERT_EQ(nonExistent.channelNumber, 0, "Non-existent preset channel");
        ASSERT_FALSE(nonExistent.isActive, "Non-existent preset active");
        
        // Test setting invalid preset
        bool invalidPreset = PresetChannelAPI::PresetChannelManager::setPresetChannel("AN/PRC-152", 0, 100, "Invalid");
        ASSERT_FALSE(invalidPreset, "Invalid preset 0");
        
        bool invalidPreset2 = PresetChannelAPI::PresetChannelManager::setPresetChannel("AN/PRC-152", 100, 100, "Invalid");
        ASSERT_FALSE(invalidPreset2, "Invalid preset 100");
        
        // Test setting invalid channel
        bool invalidChannel = PresetChannelAPI::PresetChannelManager::setPresetChannel("AN/PRC-152", 1, 0, "Invalid");
        ASSERT_FALSE(invalidChannel, "Invalid channel 0");
        
        bool invalidChannel2 = PresetChannelAPI::PresetChannelManager::setPresetChannel("AN/PRC-152", 1, 5000, "Invalid");
        ASSERT_FALSE(invalidChannel2, "Invalid channel 5000");
        
        // Test validation errors
        auto errors = PresetChannelAPI::PresetChannelManager::getPresetValidationErrors("AN/PRC-152", 1);
        ASSERT_FALSE(errors.empty(), "Validation errors not empty");
    }

}
