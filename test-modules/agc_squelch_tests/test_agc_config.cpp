#include "test_agc_squelch_main.cpp"

// 1.2 AGC Configuration Tests
TEST_F(AGCConfigTest, DefaultState) {
    // Test default AGC state (should be enabled) with proper validation
    ASSERT_TRUE(isAGCValid()) << "AGC instance not properly initialized";
    
    try {
        EXPECT_TRUE(getAGC().isAGCEnabled());
        EXPECT_EQ(getAGC().getAGCMode(), AGCMode::SLOW);
    } catch (const std::exception& e) {
        FAIL() << "Exception in default state test: " << e.what();
    }
}

TEST_F(AGCConfigTest, EnableDisableFunctionality) {
    // Test AGC enable/disable with proper error handling
    ASSERT_TRUE(isAGCValid()) << "AGC instance not properly initialized";
    
    try {
        getAGC().enableAGC(true);
        EXPECT_TRUE(getAGC().isAGCEnabled());
        
        getAGC().enableAGC(false);
        EXPECT_FALSE(getAGC().isAGCEnabled());
    } catch (const std::exception& e) {
        FAIL() << "Exception in enable/disable test: " << e.what();
    }
}

TEST_F(AGCConfigTest, ModeSwitching) {
    // Test all AGC modes with proper validation
    ASSERT_TRUE(isAGCValid()) << "AGC instance not properly initialized";
    
    try {
        getAGC().setAGCMode(AGCMode::OFF);
        EXPECT_EQ(getAGC().getAGCMode(), AGCMode::OFF);
        
        getAGC().setAGCMode(AGCMode::FAST);
        EXPECT_EQ(getAGC().getAGCMode(), AGCMode::FAST);
        
        getAGC().setAGCMode(AGCMode::MEDIUM);
        EXPECT_EQ(getAGC().getAGCMode(), AGCMode::MEDIUM);
        
        getAGC().setAGCMode(AGCMode::SLOW);
        EXPECT_EQ(getAGC().getAGCMode(), AGCMode::SLOW);
    } catch (const std::exception& e) {
        FAIL() << "Exception in mode switching test: " << e.what();
    }
}

TEST_F(AGCConfigTest, ThresholdSettingAndClamping) {
    // Test threshold setting within valid range (-100 to 0 dB) with proper validation
    ASSERT_TRUE(isAGCValid()) << "AGC instance not properly initialized";
    
    try {
        // Test valid threshold setting
        getAGC().setAGCThreshold(-50.0f);
        EXPECT_FLOAT_EQ(getAGC().getAGCThreshold(), -50.0f);
        
        // Test clamping at boundaries with proper validation
        getAGC().setAGCThreshold(-150.0f); // Below minimum
        float clamped_low = getAGC().getAGCThreshold();
        EXPECT_GE(clamped_low, -100.0f) << "Threshold not properly clamped at minimum";
        EXPECT_LE(clamped_low, 0.0f) << "Threshold not properly clamped at minimum";
        
        getAGC().setAGCThreshold(50.0f); // Above maximum
        float clamped_high = getAGC().getAGCThreshold();
        EXPECT_GE(clamped_high, -100.0f) << "Threshold not properly clamped at maximum";
        EXPECT_LE(clamped_high, 0.0f) << "Threshold not properly clamped at maximum";
        
        // Test boundary values with validation
        getAGC().setAGCThreshold(-100.0f);
        EXPECT_FLOAT_EQ(getAGC().getAGCThreshold(), -100.0f);
        
        getAGC().setAGCThreshold(0.0f);
        EXPECT_FLOAT_EQ(getAGC().getAGCThreshold(), 0.0f);
        
    } catch (const std::exception& e) {
        FAIL() << "Exception in threshold setting test: " << e.what();
    }
}

TEST_F(AGCConfigTest, AttackTimeSettingAndClamping) {
    // Test attack time setting within valid range (0.1 to 1000 ms) with proper validation
    ASSERT_TRUE(isAGCValid()) << "AGC instance not properly initialized";
    
    try {
        // Test valid attack time setting
        getAGC().setAGCAttackTime(5.0f);
        EXPECT_FLOAT_EQ(getAGC().getAGCAttackTime(), 5.0f);
        
        // Test clamping at boundaries with validation
        getAGC().setAGCAttackTime(0.05f); // Below minimum
        float clamped_low = getAGC().getAGCAttackTime();
        EXPECT_GE(clamped_low, 0.1f) << "Attack time not properly clamped at minimum";
        EXPECT_LE(clamped_low, 1000.0f) << "Attack time not properly clamped at minimum";
        
        getAGC().setAGCAttackTime(2000.0f); // Above maximum
        float clamped_high = getAGC().getAGCAttackTime();
        EXPECT_GE(clamped_high, 0.1f) << "Attack time not properly clamped at maximum";
        EXPECT_LE(clamped_high, 1000.0f) << "Attack time not properly clamped at maximum";
        
        // Test boundary values with validation
        getAGC().setAGCAttackTime(0.1f);
        EXPECT_FLOAT_EQ(getAGC().getAGCAttackTime(), 0.1f);
        
        getAGC().setAGCAttackTime(1000.0f);
        EXPECT_FLOAT_EQ(getAGC().getAGCAttackTime(), 1000.0f);
        
    } catch (const std::exception& e) {
        FAIL() << "Exception in attack time setting test: " << e.what();
    }
}

TEST_F(AGCConfigTest, ReleaseTimeSettingAndClamping) {
    // Test release time setting within valid range (1 to 10000 ms) with proper validation
    ASSERT_TRUE(isAGCValid()) << "AGC instance not properly initialized";
    
    try {
        // Test valid release time setting
        getAGC().setAGCReleaseTime(100.0f);
        EXPECT_FLOAT_EQ(getAGC().getAGCReleaseTime(), 100.0f);
        
        // Test clamping at boundaries with validation
        getAGC().setAGCReleaseTime(0.5f); // Below minimum
        float clamped_low = getAGC().getAGCReleaseTime();
        EXPECT_GE(clamped_low, 1.0f) << "Release time not properly clamped at minimum";
        EXPECT_LE(clamped_low, 10000.0f) << "Release time not properly clamped at minimum";
        
        getAGC().setAGCReleaseTime(15000.0f); // Above maximum
        float clamped_high = getAGC().getAGCReleaseTime();
        EXPECT_GE(clamped_high, 1.0f) << "Release time not properly clamped at maximum";
        EXPECT_LE(clamped_high, 10000.0f) << "Release time not properly clamped at maximum";
        
        // Test boundary values with validation
        getAGC().setAGCReleaseTime(1.0f);
        EXPECT_FLOAT_EQ(getAGC().getAGCReleaseTime(), 1.0f);
        
        getAGC().setAGCReleaseTime(10000.0f);
        EXPECT_FLOAT_EQ(getAGC().getAGCReleaseTime(), 10000.0f);
        
    } catch (const std::exception& e) {
        FAIL() << "Exception in release time setting test: " << e.what();
    }
}

TEST_F(AGCConfigTest, MaxGainSettingAndClamping) {
    // Test max gain setting within valid range (0 to 60 dB) with proper validation
    ASSERT_TRUE(isAGCValid()) << "AGC instance not properly initialized";
    
    try {
        // Test valid max gain setting
        getAGC().setAGCMaxGain(40.0f);
        EXPECT_FLOAT_EQ(getAGC().getAGCMaxGain(), 40.0f);
        
        // Test clamping at boundaries with validation
        getAGC().setAGCMaxGain(-10.0f); // Below minimum
        float clamped_low = getAGC().getAGCMaxGain();
        EXPECT_GE(clamped_low, 0.0f) << "Max gain not properly clamped at minimum";
        EXPECT_LE(clamped_low, 60.0f) << "Max gain not properly clamped at minimum";
        
        getAGC().setAGCMaxGain(80.0f); // Above maximum
        float clamped_high = getAGC().getAGCMaxGain();
        EXPECT_GE(clamped_high, 0.0f) << "Max gain not properly clamped at maximum";
        EXPECT_LE(clamped_high, 60.0f) << "Max gain not properly clamped at maximum";
        
        // Test boundary values with validation
        getAGC().setAGCMaxGain(0.0f);
        EXPECT_FLOAT_EQ(getAGC().getAGCMaxGain(), 0.0f);
        
        getAGC().setAGCMaxGain(60.0f);
        EXPECT_FLOAT_EQ(getAGC().getAGCMaxGain(), 60.0f);
        
    } catch (const std::exception& e) {
        FAIL() << "Exception in max gain setting test: " << e.what();
    }
}

TEST_F(AGCConfigTest, MinGainSettingAndClamping) {
    // Test min gain setting within valid range (-40 to 0 dB) with proper validation
    ASSERT_TRUE(isAGCValid()) << "AGC instance not properly initialized";
    
    try {
        // Test valid min gain setting
        getAGC().setAGCMinGain(-20.0f);
        EXPECT_FLOAT_EQ(getAGC().getAGCMinGain(), -20.0f);
        
        // Test clamping at boundaries with validation
        getAGC().setAGCMinGain(-50.0f); // Below minimum
        float clamped_low = getAGC().getAGCMinGain();
        EXPECT_GE(clamped_low, -40.0f) << "Min gain not properly clamped at minimum";
        EXPECT_LE(clamped_low, 0.0f) << "Min gain not properly clamped at minimum";
        
        getAGC().setAGCMinGain(10.0f); // Above maximum
        float clamped_high = getAGC().getAGCMinGain();
        EXPECT_GE(clamped_high, -40.0f) << "Min gain not properly clamped at maximum";
        EXPECT_LE(clamped_high, 0.0f) << "Min gain not properly clamped at maximum";
        
        // Test boundary values with validation
        getAGC().setAGCMinGain(-40.0f);
        EXPECT_FLOAT_EQ(getAGC().getAGCMinGain(), -40.0f);
        
        getAGC().setAGCMinGain(0.0f);
        EXPECT_FLOAT_EQ(getAGC().getAGCMinGain(), 0.0f);
        
    } catch (const std::exception& e) {
        FAIL() << "Exception in min gain setting test: " << e.what();
    }
}

TEST_F(AGCConfigTest, ConfigStructGetSetOperations) {
    // Test complete config struct operations with proper validation
    ASSERT_TRUE(isAGCValid()) << "AGC instance not properly initialized";
    
    try {
        AGCConfig test_config;
        test_config.mode = AGCMode::FAST;
        test_config.threshold_db = -50.0f;
        test_config.max_gain_db = 30.0f;
        test_config.min_gain_db = -15.0f;
        test_config.attack_time_ms = 2.0f;
        test_config.release_time_ms = 200.0f;
        
        getAGC().setAGCConfig(test_config);
        AGCConfig retrieved_config = getAGC().getAGCConfig();
        
        EXPECT_EQ(retrieved_config.mode, test_config.mode);
        EXPECT_FLOAT_EQ(retrieved_config.threshold_db, test_config.threshold_db);
        EXPECT_FLOAT_EQ(retrieved_config.max_gain_db, test_config.max_gain_db);
        EXPECT_FLOAT_EQ(retrieved_config.min_gain_db, test_config.min_gain_db);
        EXPECT_FLOAT_EQ(retrieved_config.attack_time_ms, test_config.attack_time_ms);
        EXPECT_FLOAT_EQ(retrieved_config.release_time_ms, test_config.release_time_ms);
        
    } catch (const std::exception& e) {
        FAIL() << "Exception in config struct test: " << e.what();
    }
}

TEST_F(AGCConfigTest, ThreadSafeConfigurationChanges) {
    const int num_threads = 10;
    std::vector<std::thread> threads;
    std::atomic<int> success_count{0};
    
    // Launch threads that modify AGC configuration
    for (int i = 0; i < num_threads; ++i) {
        threads.emplace_back([this, i, &success_count]() {
            try {
                // Each thread sets different configuration
                getAGC().setAGCMode(static_cast<AGCMode>(i % 4));
                getAGC().setAGCThreshold(-30.0f - i * 5.0f);
                getAGC().setAGCAttackTime(1.0f + i * 0.5f);
                getAGC().setAGCReleaseTime(50.0f + i * 10.0f);
                getAGC().setAGCMaxGain(20.0f + i * 2.0f);
                getAGC().setAGCMinGain(-30.0f + i * 2.0f);
                
                // Verify configuration was set
                AGCMode mode = getAGC().getAGCMode();
                float threshold = getAGC().getAGCThreshold();
                float attack = getAGC().getAGCAttackTime();
                float release = getAGC().getAGCReleaseTime();
                float max_gain = getAGC().getAGCMaxGain();
                float min_gain = getAGC().getAGCMinGain();
                
                // Check that values are within expected ranges
                if (mode >= AGCMode::OFF && mode <= AGCMode::SLOW &&
                    threshold >= -100.0f && threshold <= 0.0f &&
                    attack >= 0.1f && attack <= 1000.0f &&
                    release >= 1.0f && release <= 10000.0f &&
                    max_gain >= 0.0f && max_gain <= 60.0f &&
                    min_gain >= -40.0f && min_gain <= 0.0f) {
                    success_count++;
                }
            } catch (const std::exception& e) {
                // Thread-safe operations should not throw
                FAIL() << "Exception in thread: " << e.what();
            }
        });
    }
    
    // Wait for all threads
    for (auto& thread : threads) {
        thread.join();
    }
    
    // All threads should have succeeded
    EXPECT_EQ(success_count.load(), num_threads);
}

// Additional AGC configuration edge case tests
TEST_F(AGCConfigTest, ExtremeValues) {
    // Test with extreme but valid values
    getAGC().setAGCThreshold(-99.9f);
    getAGC().setAGCAttackTime(0.1f);
    getAGC().setAGCReleaseTime(1.0f);
    getAGC().setAGCMaxGain(0.1f);
    getAGC().setAGCMinGain(-39.9f);
    
    EXPECT_FLOAT_EQ(getAGC().getAGCThreshold(), -99.9f);
    EXPECT_FLOAT_EQ(getAGC().getAGCAttackTime(), 0.1f);
    EXPECT_FLOAT_EQ(getAGC().getAGCReleaseTime(), 1.0f);
    EXPECT_FLOAT_EQ(getAGC().getAGCMaxGain(), 0.1f);
    EXPECT_FLOAT_EQ(getAGC().getAGCMinGain(), -39.9f);
}

TEST_F(AGCConfigTest, InvalidInputHandling) {
    // Test handling of NaN and infinity values with proper error handling
    ASSERT_TRUE(isAGCValid()) << "AGC instance not properly initialized";
    
    try {
        // Test NaN handling - should be rejected or clamped
        getAGC().setAGCThreshold(std::numeric_limits<float>::quiet_NaN());
        float result_nan = getAGC().getAGCThreshold();
        EXPECT_FALSE(std::isnan(result_nan)) << "NaN value not properly handled";
        EXPECT_GE(result_nan, -100.0f) << "NaN result not properly clamped";
        EXPECT_LE(result_nan, 0.0f) << "NaN result not properly clamped";
        
        // Test positive infinity handling
        getAGC().setAGCThreshold(std::numeric_limits<float>::infinity());
        float result_inf_pos = getAGC().getAGCThreshold();
        EXPECT_FALSE(std::isinf(result_inf_pos)) << "Positive infinity not properly handled";
        EXPECT_GE(result_inf_pos, -100.0f) << "Positive infinity result not properly clamped";
        EXPECT_LE(result_inf_pos, 0.0f) << "Positive infinity result not properly clamped";
        
        // Test negative infinity handling
        getAGC().setAGCThreshold(-std::numeric_limits<float>::infinity());
        float result_inf_neg = getAGC().getAGCThreshold();
        EXPECT_FALSE(std::isinf(result_inf_neg)) << "Negative infinity not properly handled";
        EXPECT_GE(result_inf_neg, -100.0f) << "Negative infinity result not properly clamped";
        EXPECT_LE(result_inf_neg, 0.0f) << "Negative infinity result not properly clamped";
        
    } catch (const std::exception& e) {
        // It's acceptable for invalid inputs to throw exceptions
        SUCCEED() << "Invalid input properly rejected with exception: " << e.what();
    }
}
