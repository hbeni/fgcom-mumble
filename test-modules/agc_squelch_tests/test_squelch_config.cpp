#include "test_agc_squelch_main.cpp"

// 1.3 Squelch Configuration Tests
TEST_F(SquelchConfigTest, DefaultState) {
    // Test default squelch state (should be enabled)
    ASSERT_TRUE(isAGCValid());
    EXPECT_TRUE(getAGC().isSquelchEnabled());
    EXPECT_FLOAT_EQ(getAGC().getSquelchThreshold(), -80.0f);
    EXPECT_FLOAT_EQ(getAGC().getSquelchHysteresis(), 3.0f);
}

TEST_F(SquelchConfigTest, EnableDisableFunctionality) {
    // Test squelch enable/disable
    ASSERT_TRUE(isAGCValid());
    getAGC().setSquelchEnabled(false);
    EXPECT_FALSE(getAGC().isSquelchEnabled());
    
    getAGC().setSquelchEnabled(true);
    EXPECT_TRUE(getAGC().isSquelchEnabled());
}

TEST_F(SquelchConfigTest, ThresholdSettingAndClamping) {
    // Test threshold setting within valid range (-120 to 0 dB)
    ASSERT_TRUE(isAGCValid());
    getAGC().setSquelchThreshold(-60.0f);
    EXPECT_FLOAT_EQ(getAGC().getSquelchThreshold(), -60.0f);
    
    // Test clamping at boundaries
    getAGC().setSquelchThreshold(-150.0f); // Below minimum
    EXPECT_FLOAT_EQ(getAGC().getSquelchThreshold(), -120.0f);
    
    getAGC().setSquelchThreshold(50.0f); // Above maximum
    EXPECT_FLOAT_EQ(getAGC().getSquelchThreshold(), 0.0f);
    
    // Test boundary values
    getAGC().setSquelchThreshold(-120.0f);
    EXPECT_FLOAT_EQ(getAGC().getSquelchThreshold(), -120.0f);
    
    getAGC().setSquelchThreshold(0.0f);
    EXPECT_FLOAT_EQ(getAGC().getSquelchThreshold(), 0.0f);
}

TEST_F(SquelchConfigTest, HysteresisSettingAndClamping) {
    // Test hysteresis setting within valid range (0 to 20 dB)
    ASSERT_TRUE(isAGCValid());
    getAGC().setSquelchHysteresis(5.0f);
    EXPECT_FLOAT_EQ(getAGC().getSquelchHysteresis(), 5.0f);
    
    // Test clamping at boundaries
    getAGC().setSquelchHysteresis(-5.0f); // Below minimum
    EXPECT_FLOAT_EQ(getAGC().getSquelchHysteresis(), 0.0f);
    
    getAGC().setSquelchHysteresis(25.0f); // Above maximum
    EXPECT_FLOAT_EQ(getAGC().getSquelchHysteresis(), 20.0f);
    
    // Test boundary values
    getAGC().setSquelchHysteresis(0.0f);
    EXPECT_FLOAT_EQ(getAGC().getSquelchHysteresis(), 0.0f);
    
    getAGC().setSquelchHysteresis(20.0f);
    EXPECT_FLOAT_EQ(getAGC().getSquelchHysteresis(), 20.0f);
}

TEST_F(SquelchConfigTest, AttackTimeSettingAndClamping) {
    // Test attack time setting within valid range (0.1 to 1000 ms)
    ASSERT_TRUE(isAGCValid());
    getAGC().setSquelchAttackTime(10.0f);
    EXPECT_FLOAT_EQ(getAGC().getSquelchAttackTime(), 10.0f);
    
    // Test clamping at boundaries
    getAGC().setSquelchAttackTime(0.05f); // Below minimum
    EXPECT_FLOAT_EQ(getAGC().getSquelchAttackTime(), 0.1f);
    
    getAGC().setSquelchAttackTime(2000.0f); // Above maximum
    EXPECT_FLOAT_EQ(getAGC().getSquelchAttackTime(), 1000.0f);
    
    // Test boundary values
    getAGC().setSquelchAttackTime(0.1f);
    EXPECT_FLOAT_EQ(getAGC().getSquelchAttackTime(), 0.1f);
    
    getAGC().setSquelchAttackTime(1000.0f);
    EXPECT_FLOAT_EQ(getAGC().getSquelchAttackTime(), 1000.0f);
}

TEST_F(SquelchConfigTest, ReleaseTimeSettingAndClamping) {
    // Test release time setting within valid range (1 to 10000 ms)
    ASSERT_TRUE(isAGCValid());
    getAGC().setSquelchReleaseTime(50.0f);
    EXPECT_FLOAT_EQ(getAGC().getSquelchReleaseTime(), 50.0f);
    
    // Test clamping at boundaries
    getAGC().setSquelchReleaseTime(0.5f); // Below minimum
    EXPECT_FLOAT_EQ(getAGC().getSquelchReleaseTime(), 1.0f);
    
    getAGC().setSquelchReleaseTime(15000.0f); // Above maximum
    EXPECT_FLOAT_EQ(getAGC().getSquelchReleaseTime(), 10000.0f);
    
    // Test boundary values
    getAGC().setSquelchReleaseTime(1.0f);
    EXPECT_FLOAT_EQ(getAGC().getSquelchReleaseTime(), 1.0f);
    
    getAGC().setSquelchReleaseTime(10000.0f);
    EXPECT_FLOAT_EQ(getAGC().getSquelchReleaseTime(), 10000.0f);
}

TEST_F(SquelchConfigTest, ToneSquelchEnableDisableWithFrequency) {
    // Test tone squelch enable/disable
    ASSERT_TRUE(isAGCValid());
    getAGC().setToneSquelch(true, 1000.0f);
    EXPECT_TRUE(getAGC().isToneSquelchEnabled());
    EXPECT_FLOAT_EQ(getAGC().getToneSquelchFrequency(), 1000.0f);
    
    getAGC().setToneSquelch(false, 500.0f);
    EXPECT_FALSE(getAGC().isToneSquelchEnabled());
    // Frequency should still be set even when disabled
    EXPECT_FLOAT_EQ(getAGC().getToneSquelchFrequency(), 500.0f);
}

TEST_F(SquelchConfigTest, ToneFrequencyClamping) {
    // Test tone frequency clamping within valid range (50 to 3000 Hz)
    ASSERT_TRUE(isAGCValid());
    getAGC().setToneSquelch(true, 1000.0f);
    EXPECT_FLOAT_EQ(getAGC().getToneSquelchFrequency(), 1000.0f);
    
    // Test clamping at boundaries
    getAGC().setToneSquelch(true, 25.0f); // Below minimum
    EXPECT_FLOAT_EQ(getAGC().getToneSquelchFrequency(), 50.0f);
    
    getAGC().setToneSquelch(true, 5000.0f); // Above maximum
    EXPECT_FLOAT_EQ(getAGC().getToneSquelchFrequency(), 3000.0f);
    
    // Test boundary values
    getAGC().setToneSquelch(true, 50.0f);
    EXPECT_FLOAT_EQ(getAGC().getToneSquelchFrequency(), 50.0f);
    
    getAGC().setToneSquelch(true, 3000.0f);
    EXPECT_FLOAT_EQ(getAGC().getToneSquelchFrequency(), 3000.0f);
}

TEST_F(SquelchConfigTest, NoiseSquelchEnableDisableWithThreshold) {
    // Test noise squelch enable/disable
    ASSERT_TRUE(isAGCValid());
    getAGC().setNoiseSquelch(true, -70.0f);
    EXPECT_TRUE(getAGC().isNoiseSquelchEnabled());
    EXPECT_FLOAT_EQ(getAGC().getNoiseSquelchThreshold(), -70.0f);
    
    getAGC().setNoiseSquelch(false, -60.0f);
    EXPECT_FALSE(getAGC().isNoiseSquelchEnabled());
    // Threshold should still be set even when disabled
    EXPECT_FLOAT_EQ(getAGC().getNoiseSquelchThreshold(), -60.0f);
}

TEST_F(SquelchConfigTest, ConfigStructGetSetOperations) {
    // Test complete squelch config struct operations
    ASSERT_TRUE(isAGCValid());
    SquelchConfig test_config;
    test_config.enabled = true;
    test_config.threshold_db = -70.0f;
    test_config.hysteresis_db = 5.0f;
    test_config.attack_time_ms = 15.0f;
    test_config.release_time_ms = 100.0f;
    test_config.tone_squelch = true;
    test_config.tone_frequency_hz = 1500.0f;
    test_config.tone_tolerance_hz = 10.0f;
    test_config.noise_squelch = true;
    test_config.noise_threshold_db = -65.0f;
    
    getAGC().setSquelchConfig(test_config);
    SquelchConfig retrieved_config = getAGC().getSquelchConfig();
    
    EXPECT_EQ(retrieved_config.enabled, test_config.enabled);
    EXPECT_FLOAT_EQ(retrieved_config.threshold_db, test_config.threshold_db);
    EXPECT_FLOAT_EQ(retrieved_config.hysteresis_db, test_config.hysteresis_db);
    EXPECT_FLOAT_EQ(retrieved_config.attack_time_ms, test_config.attack_time_ms);
    EXPECT_FLOAT_EQ(retrieved_config.release_time_ms, test_config.release_time_ms);
    EXPECT_EQ(retrieved_config.tone_squelch, test_config.tone_squelch);
    EXPECT_FLOAT_EQ(retrieved_config.tone_frequency_hz, test_config.tone_frequency_hz);
    EXPECT_FLOAT_EQ(retrieved_config.tone_tolerance_hz, test_config.tone_tolerance_hz);
    EXPECT_EQ(retrieved_config.noise_squelch, test_config.noise_squelch);
    EXPECT_FLOAT_EQ(retrieved_config.noise_threshold_db, test_config.noise_threshold_db);
}

TEST_F(SquelchConfigTest, ThreadSafeConfigurationChanges) {
    ASSERT_TRUE(isAGCValid());
    const int num_threads = 10;
    std::vector<std::thread> threads;
    std::atomic<int> success_count{0};
    
    // Launch threads that modify squelch configuration
    for (int i = 0; i < num_threads; ++i) {
        threads.emplace_back([this, i, &success_count]() {
            try {
                // Each thread sets different configuration
                getAGC().setSquelchEnabled(i % 2 == 0);
                getAGC().setSquelchThreshold(-70.0f - i * 5.0f);
                getAGC().setSquelchHysteresis(2.0f + i * 0.5f);
                getAGC().setSquelchAttackTime(5.0f + i * 2.0f);
                getAGC().setSquelchReleaseTime(50.0f + i * 10.0f);
                getAGC().setToneSquelch(i % 3 == 0, 100.0f + i * 100.0f);
                getAGC().setNoiseSquelch(i % 2 == 1, -60.0f - i * 2.0f);
                
                // Verify configuration was set
                float threshold = getAGC().getSquelchThreshold();
                float hysteresis = getAGC().getSquelchHysteresis();
                float attack = getAGC().getSquelchAttackTime();
                float release = getAGC().getSquelchReleaseTime();
                float tone_freq = getAGC().getToneSquelchFrequency();
                float noise_threshold = getAGC().getNoiseSquelchThreshold();
                
                // Check that values are within expected ranges
                if (threshold >= -120.0f && threshold <= 0.0f &&
                    hysteresis >= 0.0f && hysteresis <= 20.0f &&
                    attack >= 0.1f && attack <= 1000.0f &&
                    release >= 1.0f && release <= 10000.0f &&
                    tone_freq >= 50.0f && tone_freq <= 3000.0f &&
                    noise_threshold >= -120.0f && noise_threshold <= 0.0f) {
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

// Additional squelch configuration edge case tests
TEST_F(SquelchConfigTest, ExtremeValues) {
    // Test with extreme but valid values
    ASSERT_TRUE(isAGCValid());
    getAGC().setSquelchThreshold(-119.9f);
    getAGC().setSquelchHysteresis(0.1f);
    getAGC().setSquelchAttackTime(0.1f);
    getAGC().setSquelchReleaseTime(1.0f);
    getAGC().setToneSquelch(true, 50.1f);
    getAGC().setNoiseSquelch(true, -119.9f);
    
    EXPECT_FLOAT_EQ(getAGC().getSquelchThreshold(), -119.9f);
    EXPECT_FLOAT_EQ(getAGC().getSquelchHysteresis(), 0.1f);
    EXPECT_FLOAT_EQ(getAGC().getSquelchAttackTime(), 0.1f);
    EXPECT_FLOAT_EQ(getAGC().getSquelchReleaseTime(), 1.0f);
    EXPECT_FLOAT_EQ(getAGC().getToneSquelchFrequency(), 50.1f);
    EXPECT_FLOAT_EQ(getAGC().getNoiseSquelchThreshold(), -119.9f);
}

TEST_F(SquelchConfigTest, InvalidInputHandling) {
    // Test handling of NaN and infinity values
    ASSERT_TRUE(isAGCValid());
    getAGC().setSquelchThreshold(std::numeric_limits<float>::quiet_NaN());
    EXPECT_FALSE(std::isnan(getAGC().getSquelchThreshold()));
    
    getAGC().setSquelchThreshold(std::numeric_limits<float>::infinity());
    EXPECT_FALSE(std::isinf(getAGC().getSquelchThreshold()));
    
    getAGC().setSquelchThreshold(-std::numeric_limits<float>::infinity());
    EXPECT_FALSE(std::isinf(getAGC().getSquelchThreshold()));
}

TEST_F(SquelchConfigTest, CombinedToneAndNoiseSquelch) {
    // Test enabling both tone and noise squelch
    ASSERT_TRUE(isAGCValid());
    getAGC().setToneSquelch(true, 1000.0f);
    getAGC().setNoiseSquelch(true, -70.0f);
    
    EXPECT_TRUE(getAGC().isToneSquelchEnabled());
    EXPECT_TRUE(getAGC().isNoiseSquelchEnabled());
    EXPECT_FLOAT_EQ(getAGC().getToneSquelchFrequency(), 1000.0f);
    EXPECT_FLOAT_EQ(getAGC().getNoiseSquelchThreshold(), -70.0f);
    
    // Test disabling one while keeping the other
    getAGC().setToneSquelch(false, 1000.0f);
    EXPECT_FALSE(getAGC().isToneSquelchEnabled());
    EXPECT_TRUE(getAGC().isNoiseSquelchEnabled());
}
