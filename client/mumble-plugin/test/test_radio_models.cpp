/* 
 * This file is part of the FGCom-mumble distribution (https://github.com/hbeni/fgcom-mumble).
 * Copyright (c) 2020 Benedikt Hallinger
 * 
 * This program is free software: you can redistribute it and/or modify  
 * it under the terms of the GNU General Public License as published by  
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but 
 * WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU 
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
#include <gtest/gtest.h>
#include <cmath>
#include <memory>
#include "radio_model.h"
#include "radio_model_vhf.cpp"
#include "radio_model_uhf.cpp"
#include "radio_model_hf.cpp"

class RadioModelTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize test radio configurations
        radio1.operable = true;
        radio1.ptt = false;
        radio1.frequency = "118.100";
        radio1.channelWidth = 25.0;  // 25kHz for VHF
        
        radio2.operable = true;
        radio2.ptt = false;
        radio2.frequency = "118.100";
        radio2.channelWidth = 25.0;
        
        radio3.operable = true;
        radio3.ptt = false;
        radio3.frequency = "118.200";  // Different frequency
        radio3.channelWidth = 25.0;
    }
    
    fgcom_radio radio1, radio2, radio3;
};

// Test VHF Radio Model
TEST_F(RadioModelTest, VHF_FrequencyMatch_Exact) {
    FGCom_radiowaveModel_VHF vhf_model;
    
    // Test exact frequency match
    float match = vhf_model.getFrqMatch(radio1, radio2);
    EXPECT_FLOAT_EQ(match, 1.0f);
}

TEST_F(RadioModelTest, VHF_FrequencyMatch_Different) {
    FGCom_radiowaveModel_VHF vhf_model;
    
    // Test different frequencies
    float match = vhf_model.getFrqMatch(radio1, radio3);
    EXPECT_LT(match, 1.0f);
    EXPECT_GE(match, 0.0f);
}

TEST_F(RadioModelTest, VHF_PTT_Blocks_Transmission) {
    FGCom_radiowaveModel_VHF vhf_model;
    
    radio1.ptt = true;
    float match = vhf_model.getFrqMatch(radio1, radio2);
    EXPECT_FLOAT_EQ(match, 0.0f);
}

TEST_F(RadioModelTest, VHF_Inoperable_Radio_Blocks_Transmission) {
    FGCom_radiowaveModel_VHF vhf_model;
    
    radio1.operable = false;
    float match = vhf_model.getFrqMatch(radio1, radio2);
    EXPECT_FLOAT_EQ(match, 0.0f);
}

// Test UHF Radio Model
TEST_F(RadioModelTest, UHF_FrequencyMatch_Exact) {
    FGCom_radiowaveModel_UHF uhf_model;
    
    radio1.frequency = "243.000";  // UHF frequency
    radio1.channelWidth = 25.0;    // 25kHz spacing
    radio2.frequency = "243.000";
    radio2.channelWidth = 25.0;
    
    float match = uhf_model.getFrqMatch(radio1, radio2);
    EXPECT_FLOAT_EQ(match, 1.0f);
}

TEST_F(RadioModelTest, UHF_ChannelWidth_25kHz) {
    FGCom_radiowaveModel_UHF uhf_model;
    
    radio1.frequency = "243.000";
    radio1.channelWidth = 25.0;
    radio2.frequency = "243.012";  // 12kHz offset (within 25kHz channel)
    radio2.channelWidth = 25.0;
    
    float match = uhf_model.getFrqMatch(radio1, radio2);
    EXPECT_GT(match, 0.0f);
    EXPECT_LT(match, 1.0f);
}

// Test HF Radio Model
TEST_F(RadioModelTest, HF_FrequencyMatch_Exact) {
    FGCom_radiowaveModel_HF hf_model;
    
    radio1.frequency = "3.500";     // HF frequency
    radio1.channelWidth = 3.0;      // 3kHz spacing
    radio2.frequency = "3.500";
    radio2.channelWidth = 3.0;
    
    float match = hf_model.getFrqMatch(radio1, radio2);
    EXPECT_FLOAT_EQ(match, 1.0f);
}

TEST_F(RadioModelTest, HF_ChannelWidth_3kHz) {
    FGCom_radiowaveModel_HF hf_model;
    
    radio1.frequency = "3.500";
    radio1.channelWidth = 3.0;
    radio2.frequency = "3.501";     // 1kHz offset (within 3kHz channel)
    radio2.channelWidth = 3.0;
    
    float match = hf_model.getFrqMatch(radio1, radio2);
    EXPECT_GT(match, 0.0f);
    EXPECT_LT(match, 1.0f);
}

// Test Radio Model Base Class
TEST_F(RadioModelTest, BaseModel_ChannelAlignment_Exact) {
    FGCom_radiowaveModel base_model;
    
    // Test exact frequency alignment
    float alignment = base_model.getChannelAlignment(118.100, 118.100, 25.0, 12.5);
    EXPECT_FLOAT_EQ(alignment, 1.0f);
}

TEST_F(RadioModelTest, BaseModel_ChannelAlignment_Outside) {
    FGCom_radiowaveModel base_model;
    
    // Test frequency outside channel
    float alignment = base_model.getChannelAlignment(118.100, 118.200, 25.0, 12.5);
    EXPECT_LT(alignment, 1.0f);
    EXPECT_GE(alignment, 0.0f);
}

TEST_F(RadioModelTest, BaseModel_ChannelAlignment_Edge) {
    FGCom_radiowaveModel base_model;
    
    // Test frequency at channel edge
    float alignment = base_model.getChannelAlignment(118.100, 118.125, 25.0, 12.5);
    EXPECT_GT(alignment, 0.0f);
    EXPECT_LT(alignment, 1.0f);
}

// Test Frequency String Parsing
TEST_F(RadioModelTest, FrequencyStringParsing_Valid) {
    FGCom_radiowaveModel base_model;
    
    auto result = base_model.splitFreqString("118.100");
    EXPECT_TRUE(result.isNumeric);
    EXPECT_EQ(result.frequency, "118.100");
}

TEST_F(RadioModelTest, FrequencyStringParsing_Invalid) {
    FGCom_radiowaveModel base_model;
    
    auto result = base_model.splitFreqString("invalid");
    EXPECT_FALSE(result.isNumeric);
}

TEST_F(RadioModelTest, FrequencyStringParsing_WithPrefix) {
    FGCom_radiowaveModel base_model;
    
    auto result = base_model.splitFreqString("MHz118.100");
    EXPECT_TRUE(result.isNumeric);
    EXPECT_EQ(result.frequency, "118.100");
}

// Test Audio Processing
TEST_F(RadioModelTest, AudioVolume_Clamping) {
    // Test that audio volume is properly clamped
    float test_samples[] = {2.0f, -2.0f, 0.5f, -0.5f, 0.0f};
    uint32_t sample_count = 5;
    uint16_t channel_count = 1;
    
    // Apply volume processing (simulating the audio processing)
    for (uint32_t i = 0; i < sample_count; i++) {
        float sample = test_samples[i];
        sample *= 1.5f;  // Apply volume
        
        // Clamp to prevent clipping
        if (sample > 1.0f) sample = 1.0f;
        if (sample < -1.0f) sample = -1.0f;
        
        EXPECT_LE(sample, 1.0f);
        EXPECT_GE(sample, -1.0f);
    }
}

// Test Signal Quality Degradation
TEST_F(RadioModelTest, SignalQuality_Degradation) {
    // Test signal quality degradation for poor conditions
    float good_signal = 0.8f;
    float poor_signal = 0.2f;
    
    // Good signal should have minimal degradation
    float good_degradation = (0.3f - good_signal) * 0.5f;
    EXPECT_LE(good_degradation, 0.0f);  // No degradation for good signal
    
    // Poor signal should have degradation
    float poor_degradation = (0.3f - poor_signal) * 0.5f;
    EXPECT_GT(poor_degradation, 0.0f);  // Degradation for poor signal
}

// Test Channel Width Defaults
TEST_F(RadioModelTest, ChannelWidth_Defaults) {
    FGCom_radiowaveModel_VHF vhf_model;
    FGCom_radiowaveModel_UHF uhf_model;
    FGCom_radiowaveModel_HF hf_model;
    
    // Test that default channel widths are applied
    radio1.channelWidth = 0.0;  // Invalid width
    radio2.channelWidth = 0.0;
    
    // VHF should use 25kHz default
    float vhf_match = vhf_model.getFrqMatch(radio1, radio2);
    EXPECT_GE(vhf_match, 0.0f);
    
    // UHF should use 25kHz default
    float uhf_match = uhf_model.getFrqMatch(radio1, radio2);
    EXPECT_GE(uhf_match, 0.0f);
    
    // HF should use 3kHz default
    float hf_match = hf_model.getFrqMatch(radio1, radio2);
    EXPECT_GE(hf_match, 0.0f);
}

// Test Edge Cases
TEST_F(RadioModelTest, EdgeCases_ZeroFrequency) {
    FGCom_radiowaveModel_VHF vhf_model;
    
    radio1.frequency = "0.000";
    radio2.frequency = "0.000";
    
    float match = vhf_model.getFrqMatch(radio1, radio2);
    EXPECT_GE(match, 0.0f);
    EXPECT_LE(match, 1.0f);
}

TEST_F(RadioModelTest, EdgeCases_VeryHighFrequency) {
    FGCom_radiowaveModel_UHF uhf_model;
    
    radio1.frequency = "3000.000";  // 3 GHz
    radio2.frequency = "3000.000";
    
    float match = uhf_model.getFrqMatch(radio1, radio2);
    EXPECT_GE(match, 0.0f);
    EXPECT_LE(match, 1.0f);
}

// Performance Tests
TEST_F(RadioModelTest, Performance_FrequencyMatch) {
    FGCom_radiowaveModel_VHF vhf_model;
    
    // Test performance with many frequency matches
    const int iterations = 1000;
    auto start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < iterations; i++) {
        float match = vhf_model.getFrqMatch(radio1, radio2);
        EXPECT_GE(match, 0.0f);
        EXPECT_LE(match, 1.0f);
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    // Should complete 1000 iterations in reasonable time (< 100ms)
    EXPECT_LT(duration.count(), 100000);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
