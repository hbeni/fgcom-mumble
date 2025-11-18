#include "test_agc_squelch_main.cpp"

// 1.11 Thread Safety Tests
TEST_F(ThreadSafetyTest, ConcurrentReadWriteOnAllMutexes) {
    // Validate AGC instance is properly initialized
    ASSERT_TRUE(isAGCValid()) << "AGC instance not properly initialized";
    
    const int num_threads = 20;
    const int operations_per_thread = 100;
    std::vector<std::thread> threads;
    std::atomic<int> success_count{0};
    std::atomic<int> error_count{0};
    std::mutex error_log_mutex; // Protect error logging
    
    // Launch threads that perform concurrent read/write operations
    for (int i = 0; i < num_threads; ++i) {
        threads.emplace_back([this, i, operations_per_thread, &success_count, &error_count, &error_log_mutex]() {
            try {
                for (int op = 0; op < operations_per_thread; ++op) {
                    // Mix of read and write operations
                    if (op % 4 == 0) {
                        // AGC configuration operations with proper validation
                        try {
                            getAGC().setAGCMode(static_cast<AGCMode>(op % 4));
                            getAGC().setAGCThreshold(-50.0f - op);
                            getAGC().setAGCAttackTime(1.0f + op * 0.1f);
                            getAGC().setAGCReleaseTime(50.0f + op * 2.0f);
                            getAGC().setAGCMaxGain(20.0f + op);
                            getAGC().setAGCMinGain(-30.0f + op);
                            
                            // Read operations with validation
                            AGCMode mode = getAGC().getAGCMode();
                            float threshold = getAGC().getAGCThreshold();
                            float attack = getAGC().getAGCAttackTime();
                            float release = getAGC().getAGCReleaseTime();
                            float max_gain = getAGC().getAGCMaxGain();
                            float min_gain = getAGC().getAGCMinGain();
                        
                            // Verify values are within expected ranges
                            if (mode >= AGCMode::OFF && mode <= AGCMode::SLOW &&
                                threshold >= -100.0f && threshold <= 0.0f &&
                                attack >= 0.1f && attack <= 1000.0f &&
                                release >= 1.0f && release <= 10000.0f &&
                                max_gain >= 0.0f && max_gain <= 60.0f &&
                                min_gain >= -40.0f && min_gain <= 0.0f) {
                                success_count++;
                            }
                        } catch (const std::exception& e) {
                            error_count++;
                            {
                                std::lock_guard<std::mutex> lock(error_log_mutex);
                                std::cerr << "Exception in AGC operations thread " << i << ": " << e.what() << std::endl;
                            }
                        }
                    } else if (op % 4 == 1) {
                        // Squelch configuration operations
                        getAGC().setSquelchEnabled(op % 2 == 0);
                        getAGC().setSquelchThreshold(-70.0f - op);
                        getAGC().setSquelchHysteresis(2.0f + op * 0.1f);
                        getAGC().setSquelchAttackTime(5.0f + op * 0.5f);
                        getAGC().setSquelchReleaseTime(50.0f + op * 2.0f);
                        getAGC().setToneSquelch(op % 3 == 0, 100.0f + op * 10.0f);
                        getAGC().setNoiseSquelch(op % 2 == 1, -60.0f - op);
                        
                        // Read operations
                        bool enabled = getAGC().isSquelchEnabled();
                        float threshold = getAGC().getSquelchThreshold();
                        float hysteresis = getAGC().getSquelchHysteresis();
                        float attack = getAGC().getSquelchAttackTime();
                        float release = getAGC().getSquelchReleaseTime();
                        bool tone_enabled = getAGC().isToneSquelchEnabled();
                        float tone_freq = getAGC().getToneSquelchFrequency();
                        bool noise_enabled = getAGC().isNoiseSquelchEnabled();
                        float noise_threshold = getAGC().getNoiseSquelchThreshold();
                        
                        // Verify values are within expected ranges
                        if (threshold >= -120.0f && threshold <= 0.0f &&
                            hysteresis >= 0.0f && hysteresis <= 20.0f &&
                            attack >= 0.1f && attack <= 1000.0f &&
                            release >= 1.0f && release <= 10000.0f &&
                            tone_freq >= 50.0f && tone_freq <= 3000.0f &&
                            noise_threshold >= -120.0f && noise_threshold <= 0.0f) {
                            success_count++;
                        }
                    } else if (op % 4 == 2) {
                        // Audio processing operations
                        auto input = generateSineWave(1000.0f, 44100.0f, 1024, 0.1f);
                        std::vector<float> output(1024);
                        getAGC().processAudioSamples(input.data(), output.data(), 1024, 44100.0f);
                        
                        // Read audio processing state
                        bool squelch_open = getAGC().isSquelchOpen();
                        float current_gain = getAGC().getCurrentGain();
                        float signal_level = getAGC().getCurrentSignalLevel();
                        
                        // Verify values are reasonable
                        if (current_gain >= -100.0f && current_gain <= 100.0f &&
                            signal_level >= -200.0f && signal_level <= 100.0f) {
                            success_count++;
                        }
                    } else {
                        // Statistics and monitoring operations
                        AGCStats agc_stats = getAGC().getAGCStats();
                        SquelchStats squelch_stats = getAGC().getSquelchStats();
                        
                        // Verify statistics are reasonable
                        if (agc_stats.current_gain_db >= -100.0f && agc_stats.current_gain_db <= 100.0f &&
                            agc_stats.input_level_db >= -200.0f && agc_stats.input_level_db <= 100.0f &&
                            squelch_stats.current_signal_level_db >= -200.0f && 
                            squelch_stats.current_signal_level_db <= 100.0f) {
                            success_count++;
                        }
                    }
                }
            } catch (const std::exception& e) {
                error_count++;
                std::cerr << "Exception in thread " << i << ": " << e.what() << std::endl;
            }
        });
    }
    
    // Wait for all threads
    for (auto& thread : threads) {
        thread.join();
    }
    
    // All threads should have succeeded
    EXPECT_EQ(error_count.load(), 0) << "Thread safety errors detected";
    EXPECT_GT(success_count.load(), num_threads * operations_per_thread * 0.8) 
        << "Too many thread safety failures: " << success_count.load() << " successes";
}

TEST_F(ThreadSafetyTest, DeadlockDetection) {
    const int num_threads = 10;
    std::vector<std::thread> threads;
    std::atomic<bool> test_completed{false};
    std::atomic<int> deadlock_count{0};
    
    // Launch threads that might cause deadlocks
    for (int i = 0; i < num_threads; ++i) {
        threads.emplace_back([this, i, &test_completed, &deadlock_count]() {
            try {
                auto start_time = std::chrono::high_resolution_clock::now();
                
                // Perform operations that might cause deadlocks
                for (int op = 0; op < 50 && !test_completed.load(); ++op) {
                    // Mix of configuration and processing operations
                    if (op % 3 == 0) {
                        AGCConfig config = getAGC().getAGCConfig();
                        getAGC().setAGCConfig(config);
                    } else if (op % 3 == 1) {
                        SquelchConfig config = getAGC().getSquelchConfig();
                        getAGC().setSquelchConfig(config);
                    } else {
                        auto input = generateSineWave(1000.0f, 44100.0f, 1024, 0.1f);
                        std::vector<float> output(1024);
                        getAGC().processAudioSamples(input.data(), output.data(), 1024, 44100.0f);
                    }
                }
                
                auto end_time = std::chrono::high_resolution_clock::now();
                auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
                
                // If operation took too long, might be a deadlock
                if (duration.count() > 5000) { // 5 seconds
                    deadlock_count++;
                }
            } catch (const std::exception& e) {
                std::cerr << "Exception in deadlock test thread " << i << ": " << e.what() << std::endl;
            }
        });
    }
    
    // Set a timeout for the test
    std::this_thread::sleep_for(std::chrono::seconds(10));
    test_completed.store(true);
    
    // Wait for all threads
    for (auto& thread : threads) {
        thread.join();
    }
    
    // Should not have detected deadlocks
    EXPECT_EQ(deadlock_count.load(), 0) << "Potential deadlocks detected: " << deadlock_count.load();
}

TEST_F(ThreadSafetyTest, RaceConditionTesting) {
    const int num_threads = 20;
    const int operations_per_thread = 50;
    std::vector<std::thread> threads;
    std::atomic<int> race_condition_count{0};
    std::vector<std::atomic<int>> operation_counts(4);
    
    // Initialize operation counters
    for (int i = 0; i < 4; ++i) {
        operation_counts[i].store(0);
    }
    
    // Launch threads that perform concurrent operations
    for (int i = 0; i < num_threads; ++i) {
        threads.emplace_back([this, i, operations_per_thread, &race_condition_count, &operation_counts]() {
            try {
                for (int op = 0; op < operations_per_thread; ++op) {
                    int operation_type = op % 4;
                    operation_counts[operation_type]++;
                    
                    switch (operation_type) {
                        case 0: {
                            // AGC operations
                            getAGC().setAGCMode(static_cast<AGCMode>(op % 4));
                            getAGC().setAGCThreshold(-50.0f - op);
                            AGCMode mode = getAGC().getAGCMode();
                            float threshold = getAGC().getAGCThreshold();
                            
                            // Check for race conditions
                            if (mode < AGCMode::OFF || mode > AGCMode::SLOW ||
                                threshold < -100.0f || threshold > 0.0f) {
                                race_condition_count++;
                            }
                            break;
                        }
                        case 1: {
                            // Squelch operations
                            getAGC().setSquelchEnabled(op % 2 == 0);
                            getAGC().setSquelchThreshold(-70.0f - op);
                            bool enabled = getAGC().isSquelchEnabled();
                            float threshold = getAGC().getSquelchThreshold();
                            
                            // Check for race conditions
                            if (threshold < -120.0f || threshold > 0.0f) {
                                race_condition_count++;
                            }
                            break;
                        }
                        case 2: {
                            // Audio processing
                            auto input = generateSineWave(1000.0f, 44100.0f, 1024, 0.1f);
                            std::vector<float> output(1024);
                            getAGC().processAudioSamples(input.data(), output.data(), 1024, 44100.0f);
                            
                            bool squelch_open = getAGC().isSquelchOpen();
                            float current_gain = getAGC().getCurrentGain();
                            
                            // Check for race conditions
                            if (current_gain < -100.0f || current_gain > 100.0f) {
                                race_condition_count++;
                            }
                            break;
                        }
                        case 3: {
                            // Statistics operations
                            AGCStats agc_stats = getAGC().getAGCStats();
                            SquelchStats squelch_stats = getAGC().getSquelchStats();
                            
                            // Check for race conditions
                            if (agc_stats.current_gain_db < -100.0f || agc_stats.current_gain_db > 100.0f ||
                                squelch_stats.current_signal_level_db < -200.0f || 
                                squelch_stats.current_signal_level_db > 100.0f) {
                                race_condition_count++;
                            }
                            break;
                        }
                    }
                }
            } catch (const std::exception& e) {
                std::cerr << "Exception in race condition test thread " << i << ": " << e.what() << std::endl;
            }
        });
    }
    
    // Wait for all threads
    for (auto& thread : threads) {
        thread.join();
    }
    
    // Should not have detected race conditions
    EXPECT_EQ(race_condition_count.load(), 0) << "Race conditions detected: " << race_condition_count.load();
    
    // Verify all operations were performed
    for (int i = 0; i < 4; ++i) {
        EXPECT_GT(operation_counts[i].load(), 0) << "No operations of type " << i << " were performed";
    }
}

TEST_F(ThreadSafetyTest, AtomicVariableConsistency) {
    const int num_threads = 20;
    const int operations_per_thread = 100;
    std::vector<std::thread> threads;
    std::atomic<int> consistency_errors{0};
    
    // Launch threads that modify atomic variables
    for (int i = 0; i < num_threads; ++i) {
        threads.emplace_back([this, i, operations_per_thread, &consistency_errors]() {
            try {
                for (int op = 0; op < operations_per_thread; ++op) {
                    // Toggle AGC and Squelch enabled states
                    bool agc_enabled = (op + i) % 2 == 0;
                    bool squelch_enabled = (op + i) % 3 == 0;
                    
                    getAGC().enableAGC(agc_enabled);
                    getAGC().setSquelchEnabled(squelch_enabled);
                    
                    // Read back values
                    bool agc_read = getAGC().isAGCEnabled();
                    bool squelch_read = getAGC().isSquelchEnabled();
                    
                    // Check consistency
                    if (agc_read != agc_enabled) {
                        consistency_errors++;
                    }
                    if (squelch_read != squelch_enabled) {
                        consistency_errors++;
                    }
                    
                    // Process audio to trigger internal state changes
                    auto input = generateSineWave(1000.0f, 44100.0f, 1024, 0.1f);
                    std::vector<float> output(1024);
                    getAGC().processAudioSamples(input.data(), output.data(), 1024, 44100.0f);
                    
                    // Read state after processing
                    bool agc_after = getAGC().isAGCEnabled();
                    bool squelch_after = getAGC().isSquelchEnabled();
                    
                    // Check consistency after processing
                    if (agc_after != agc_enabled) {
                        consistency_errors++;
                    }
                    if (squelch_after != squelch_enabled) {
                        consistency_errors++;
                    }
                }
            } catch (const std::exception& e) {
                std::cerr << "Exception in atomic variable test thread " << i << ": " << e.what() << std::endl;
            }
        });
    }
    
    // Wait for all threads
    for (auto& thread : threads) {
        thread.join();
    }
    
    // Should not have consistency errors
    EXPECT_EQ(consistency_errors.load(), 0) << "Atomic variable consistency errors: " << consistency_errors.load();
}

TEST_F(ThreadSafetyTest, LockContentionUnderLoad) {
    const int num_threads = 50;
    const int operations_per_thread = 20;
    std::vector<std::thread> threads;
    std::atomic<int> contention_errors{0};
    std::vector<std::chrono::milliseconds> operation_times;
    std::mutex times_mutex;
    
    // Launch threads that will cause lock contention
    for (int i = 0; i < num_threads; ++i) {
        threads.emplace_back([this, i, operations_per_thread, &contention_errors, &operation_times, &times_mutex]() {
            try {
                for (int op = 0; op < operations_per_thread; ++op) {
                    auto start_time = std::chrono::high_resolution_clock::now();
                    
                    // Perform operations that require locks
                    AGCConfig agc_config = getAGC().getAGCConfig();
                    agc_config.mode = static_cast<AGCMode>(op % 4);
                    agc_config.threshold_db = -50.0f - op;
                    getAGC().setAGCConfig(agc_config);
                    
                    SquelchConfig squelch_config = getAGC().getSquelchConfig();
                    squelch_config.enabled = op % 2 == 0;
                    squelch_config.threshold_db = -70.0f - op;
                    getAGC().setSquelchConfig(squelch_config);
                    
                    // Process audio (also requires locks)
                    auto input = generateSineWave(1000.0f, 44100.0f, 1024, 0.1f);
                    std::vector<float> output(1024);
                    getAGC().processAudioSamples(input.data(), output.data(), 1024, 44100.0f);
                    
                    auto end_time = std::chrono::high_resolution_clock::now();
                    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
                    
                    // Record operation time
                    {
                        std::lock_guard<std::mutex> lock(times_mutex);
                        operation_times.push_back(duration);
                    }
                    
                    // Check for excessive contention (operations taking too long)
                    if (duration.count() > 1000) { // 1 second
                        contention_errors++;
                    }
                }
            } catch (const std::exception& e) {
                std::cerr << "Exception in lock contention test thread " << i << ": " << e.what() << std::endl;
            }
        });
    }
    
    // Wait for all threads
    for (auto& thread : threads) {
        thread.join();
    }
    
    // Calculate statistics
    std::chrono::milliseconds total_time{0};
    std::chrono::milliseconds max_time{0};
    std::chrono::milliseconds min_time{std::chrono::milliseconds::max()};
    
    for (const auto& time : operation_times) {
        total_time += time;
        max_time = std::max(max_time, time);
        min_time = std::min(min_time, time);
    }
    
    std::chrono::milliseconds avg_time = total_time / operation_times.size();
    
    // Should not have excessive contention
    EXPECT_LT(contention_errors.load(), num_threads * operations_per_thread * 0.1) 
        << "Excessive lock contention detected: " << contention_errors.load();
    
    // Average operation time should be reasonable
    EXPECT_LT(avg_time.count(), 100) << "Average operation time too high: " << avg_time.count() << "ms";
    
    std::cout << "Lock contention test results:" << std::endl;
    std::cout << "  Total operations: " << operation_times.size() << std::endl;
    std::cout << "  Average time: " << avg_time.count() << "ms" << std::endl;
    std::cout << "  Max time: " << max_time.count() << "ms" << std::endl;
    std::cout << "  Min time: " << min_time.count() << "ms" << std::endl;
    std::cout << "  Contention errors: " << contention_errors.load() << std::endl;
}
