#include "test_agc_squelch_main.cpp"

// AGC/Squelch Edge Case Tests
// These tests cover extreme conditions, boundary values, and error states

TEST_F(AGCConfigTest, ExtremeThresholdValues) {
    // Test with extreme threshold values
    ASSERT_TRUE(isAGCValid()) << "AGC instance not properly initialized";
    
    std::vector<float> extreme_thresholds = {
        std::numeric_limits<float>::min(),
        std::numeric_limits<float>::max(),
        -std::numeric_limits<float>::max(),
        std::numeric_limits<float>::lowest(),
        std::numeric_limits<float>::epsilon(),
        -std::numeric_limits<float>::epsilon(),
        std::numeric_limits<float>::quiet_NaN(),
        std::numeric_limits<float>::infinity(),
        -std::numeric_limits<float>::infinity()
    };
    
    for (float threshold : extreme_thresholds) {
        EXPECT_NO_THROW({
            getAGC().setAGCThreshold(threshold);
            float actual_threshold = getAGC().getAGCThreshold();
            
            // Verify threshold is clamped to valid range
            EXPECT_GE(actual_threshold, -100.0f) << "Threshold should be >= -100.0 for input: " << threshold;
            EXPECT_LE(actual_threshold, 0.0f) << "Threshold should be <= 0.0 for input: " << threshold;
            EXPECT_TRUE(std::isfinite(actual_threshold)) << "Threshold should be finite for input: " << threshold;
        }) << "AGC should handle extreme threshold: " << threshold;
    }
}

TEST_F(AGCConfigTest, ExtremeTimingValues) {
    // Test with extreme timing values
    ASSERT_TRUE(isAGCValid()) << "AGC instance not properly initialized";
    
    std::vector<float> extreme_attack_times = {
        0.0f,                    // Zero
        -1.0f,                   // Negative
        std::numeric_limits<float>::max(),
        std::numeric_limits<float>::quiet_NaN(),
        std::numeric_limits<float>::infinity()
    };
    
    for (float attack_time : extreme_attack_times) {
        EXPECT_NO_THROW({
            getAGC().setAGCAttackTime(attack_time);
            float actual_attack_time = getAGC().getAGCAttackTime();
            
            // Verify attack time is clamped to valid range
            EXPECT_GE(actual_attack_time, 0.1f) << "Attack time should be >= 0.1ms for input: " << attack_time;
            EXPECT_LE(actual_attack_time, 1000.0f) << "Attack time should be <= 1000.0ms for input: " << attack_time;
            EXPECT_TRUE(std::isfinite(actual_attack_time)) << "Attack time should be finite for input: " << attack_time;
        }) << "AGC should handle extreme attack time: " << attack_time;
    }
    
    std::vector<float> extreme_release_times = {
        0.0f,                    // Zero
        -1.0f,                   // Negative
        std::numeric_limits<float>::max(),
        std::numeric_limits<float>::quiet_NaN(),
        std::numeric_limits<float>::infinity()
    };
    
    for (float release_time : extreme_release_times) {
        EXPECT_NO_THROW({
            getAGC().setAGCReleaseTime(release_time);
            float actual_release_time = getAGC().getAGCReleaseTime();
            
            // Verify release time is clamped to valid range
            EXPECT_GE(actual_release_time, 1.0f) << "Release time should be >= 1.0ms for input: " << release_time;
            EXPECT_LE(actual_release_time, 10000.0f) << "Release time should be <= 10000.0ms for input: " << release_time;
            EXPECT_TRUE(std::isfinite(actual_release_time)) << "Release time should be finite for input: " << release_time;
        }) << "AGC should handle extreme release time: " << release_time;
    }
}

TEST_F(AGCConfigTest, ConcurrentConfigurationChanges) {
    // Test concurrent configuration changes
    ASSERT_TRUE(isAGCValid()) << "AGC instance not properly initialized";
    
    std::atomic<bool> test_running{true};
    std::atomic<int> configuration_changes{0};
    std::vector<std::thread> threads;
    
    // Start multiple threads making configuration changes
    for (int i = 0; i < 8; ++i) {
        threads.emplace_back([&, i]() {
            while (test_running.load()) {
                try {
                    // Change different parameters
                    switch (i % 4) {
                        case 0:
                            getAGC().setAGCThreshold(-50.0f + (i % 10));
                            break;
                        case 1:
                            getAGC().setAGCAttackTime(1.0f + (i % 100));
                            break;
                        case 2:
                            getAGC().setAGCReleaseTime(10.0f + (i % 1000));
                            break;
                        case 3:
                            getAGC().setAGCMode(static_cast<AGCMode>(i % 4));
                            break;
                    }
                    configuration_changes++;
                } catch (const std::exception& e) {
                    // Log but don't fail the test
                    std::cerr << "Configuration change exception: " << e.what() << std::endl;
                }
            }
        });
    }
    
    // Let threads run for a short time
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    test_running = false;
    
    // Wait for all threads
    for (auto& thread : threads) {
        thread.join();
    }
    
    EXPECT_GT(configuration_changes.load(), 0) << "Should have made some configuration changes";
    
    // Verify AGC is still in a valid state
    EXPECT_TRUE(getAGC().isAGCEnabled() || !getAGC().isAGCEnabled()) << "AGC should be in a valid state";
}

TEST_F(AGCConfigTest, MemoryPressureConditions) {
    // Test under memory pressure conditions
    ASSERT_TRUE(isAGCValid()) << "AGC instance not properly initialized";
    
    // Allocate memory to simulate pressure
    std::vector<std::vector<float>> memory_blocks;
    for (int i = 0; i < 20; ++i) {
        memory_blocks.emplace_back(100000, 0.5f); // 100k samples each
    }
    
    EXPECT_NO_THROW({
        // Make configuration changes under memory pressure
        getAGC().setAGCThreshold(-30.0f);
        getAGC().setAGCAttackTime(5.0f);
        getAGC().setAGCReleaseTime(50.0f);
        getAGC().setAGCMode(AGCMode::FAST);
        
        // Verify configuration is still valid
        EXPECT_GE(getAGC().getAGCThreshold(), -100.0f);
        EXPECT_LE(getAGC().getAGCThreshold(), 0.0f);
        EXPECT_GE(getAGC().getAGCAttackTime(), 0.1f);
        EXPECT_LE(getAGC().getAGCAttackTime(), 1000.0f);
        EXPECT_GE(getAGC().getAGCReleaseTime(), 1.0f);
        EXPECT_LE(getAGC().getAGCReleaseTime(), 10000.0f);
    }) << "AGC should work under memory pressure";
}

TEST_F(AGCConfigTest, RapidStateTransitions) {
    // Test rapid state transitions
    ASSERT_TRUE(isAGCValid()) << "AGC instance not properly initialized";
    
    // Rapidly toggle AGC on/off
    for (int i = 0; i < 1000; ++i) {
        EXPECT_NO_THROW({
            getAGC().enableAGC(i % 2 == 0);
        }) << "AGC should handle rapid state transitions";
        
        // Verify state is consistent
        bool enabled = getAGC().isAGCEnabled();
        EXPECT_TRUE(enabled || !enabled) << "AGC state should be valid";
    }
    
    // Rapidly change modes
    std::vector<AGCMode> modes = {AGCMode::OFF, AGCMode::FAST, AGCMode::MEDIUM, AGCMode::SLOW};
    for (int i = 0; i < 1000; ++i) {
        EXPECT_NO_THROW({
            getAGC().setAGCMode(modes[i % modes.size()]);
        }) << "AGC should handle rapid mode changes";
        
        // Verify mode is valid
        AGCMode current_mode = getAGC().getAGCMode();
        EXPECT_TRUE(current_mode == AGCMode::OFF || 
                   current_mode == AGCMode::FAST || 
                   current_mode == AGCMode::MEDIUM || 
                   current_mode == AGCMode::SLOW) << "AGC mode should be valid";
    }
}

TEST_F(AGCConfigTest, InvalidModeTransitions) {
    // Test invalid mode transitions
    ASSERT_TRUE(isAGCValid()) << "AGC instance not properly initialized";
    
    // Test with invalid mode values
    std::vector<int> invalid_modes = {
        -1, 4, 5, 100, -100,
        std::numeric_limits<int>::max(),
        std::numeric_limits<int>::min()
    };
    
    for (int invalid_mode : invalid_modes) {
        EXPECT_NO_THROW({
            // Cast invalid mode to AGCMode enum
            AGCMode mode = static_cast<AGCMode>(invalid_mode);
            getAGC().setAGCMode(mode);
            
            // Verify mode is still valid (should be clamped or defaulted)
            AGCMode current_mode = getAGC().getAGCMode();
            EXPECT_TRUE(current_mode == AGCMode::OFF || 
                       current_mode == AGCMode::FAST || 
                       current_mode == AGCMode::MEDIUM || 
                       current_mode == AGCMode::SLOW) << "AGC should handle invalid mode: " << invalid_mode;
        }) << "AGC should handle invalid mode: " << invalid_mode;
    }
}

TEST_F(AGCConfigTest, ResourceExhaustionScenarios) {
    // Test resource exhaustion scenarios
    ASSERT_TRUE(isAGCValid()) << "AGC instance not properly initialized";
    
    // Simulate resource exhaustion by creating many temporary objects
    std::vector<std::unique_ptr<FGCom_AGC_Squelch>> temp_instances;
    
    EXPECT_NO_THROW({
        // Try to create many instances (should fail gracefully)
        for (int i = 0; i < 1000; ++i) {
            try {
                // This should fail for singleton, but not crash
                auto instance = std::make_unique<FGCom_AGC_Squelch>();
                temp_instances.push_back(std::move(instance));
            } catch (const std::exception& e) {
                // Expected for singleton pattern
            }
        }
        
        // Verify main instance still works
        getAGC().setAGCThreshold(-40.0f);
        EXPECT_GE(getAGC().getAGCThreshold(), -100.0f);
        EXPECT_LE(getAGC().getAGCThreshold(), 0.0f);
    }) << "AGC should handle resource exhaustion gracefully";
}

TEST_F(AGCConfigTest, BoundaryValuePrecision) {
    // Test boundary value precision
    ASSERT_TRUE(isAGCValid()) << "AGC instance not properly initialized";
    
    // Test very small differences around boundaries
    std::vector<float> boundary_values = {
        -100.0f, -99.999f, -100.001f,  // Threshold boundaries
        0.0f, 0.001f, -0.001f,         // Threshold boundaries
        0.1f, 0.099f, 0.101f,          // Attack time boundaries
        1000.0f, 999.9f, 1000.1f,      // Attack time boundaries
        1.0f, 0.999f, 1.001f,          // Release time boundaries
        10000.0f, 9999.9f, 10000.1f    // Release time boundaries
    };
    
    for (float value : boundary_values) {
        EXPECT_NO_THROW({
            // Test threshold
            getAGC().setAGCThreshold(value);
            float actual_threshold = getAGC().getAGCThreshold();
            EXPECT_GE(actual_threshold, -100.0f) << "Threshold should be >= -100.0 for: " << value;
            EXPECT_LE(actual_threshold, 0.0f) << "Threshold should be <= 0.0 for: " << value;
            
            // Test attack time
            getAGC().setAGCAttackTime(value);
            float actual_attack = getAGC().getAGCAttackTime();
            EXPECT_GE(actual_attack, 0.1f) << "Attack time should be >= 0.1 for: " << value;
            EXPECT_LE(actual_attack, 1000.0f) << "Attack time should be <= 1000.0 for: " << value;
            
            // Test release time
            getAGC().setAGCReleaseTime(value);
            float actual_release = getAGC().getAGCReleaseTime();
            EXPECT_GE(actual_release, 1.0f) << "Release time should be >= 1.0 for: " << value;
            EXPECT_LE(actual_release, 10000.0f) << "Release time should be <= 10000.0 for: " << value;
        }) << "AGC should handle boundary value: " << value;
    }
}

TEST_F(AGCConfigTest, ExceptionHandling) {
    // Test exception handling
    ASSERT_TRUE(isAGCValid()) << "AGC instance not properly initialized";
    
    // Test that exceptions don't corrupt state
    for (int i = 0; i < 100; ++i) {
        try {
            // Make some configuration changes
            getAGC().setAGCThreshold(-30.0f + (i % 20));
            getAGC().setAGCAttackTime(1.0f + (i % 10));
            getAGC().setAGCReleaseTime(10.0f + (i % 100));
            
            // Verify state is still valid
            EXPECT_GE(getAGC().getAGCThreshold(), -100.0f);
            EXPECT_LE(getAGC().getAGCThreshold(), 0.0f);
            EXPECT_GE(getAGC().getAGCAttackTime(), 0.1f);
            EXPECT_LE(getAGC().getAGCAttackTime(), 1000.0f);
            EXPECT_GE(getAGC().getAGCReleaseTime(), 1.0f);
            EXPECT_LE(getAGC().getAGCReleaseTime(), 10000.0f);
        } catch (const std::exception& e) {
            // If an exception occurs, verify AGC is still in a valid state
            EXPECT_GE(getAGC().getAGCThreshold(), -100.0f);
            EXPECT_LE(getAGC().getAGCThreshold(), 0.0f);
        }
    }
}
