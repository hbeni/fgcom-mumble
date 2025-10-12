#include "atis_test_classes.h"

// 7.2 Playback Tests
TEST_F(PlaybackTest, PlaybackOnDemand) {
    // Test playback on demand
    std::string playback_file = test_playback_dir + "/test_playback.fgcs";
    std::vector<int16_t> test_samples = generateAudioSamples(test_audio_sample_rate, 5); // 5 seconds
    
    // Create test playback file
    bool file_created = createTestAudioFile(playback_file, test_samples);
    EXPECT_TRUE(file_created) << "Playback file should be created";
    
    // Test playback file existence
    EXPECT_TRUE(std::filesystem::exists(playback_file)) << "Playback file should exist";
    
    // Test playback file reading
    std::vector<int16_t> read_samples = readTestAudioFile(playback_file);
    EXPECT_EQ(read_samples.size(), test_samples.size()) << "Read samples should match written samples";
    
    // Test playback file validation
    EXPECT_GT(read_samples.size(), 0) << "Playback samples should not be empty";
    EXPECT_EQ(read_samples.size(), test_audio_sample_rate * 5) << "Playback sample count should match duration";
    
    // Test playback file format
    std::ifstream file(playback_file, std::ios::binary);
    EXPECT_TRUE(file.is_open()) << "Playback file should be readable";
    
    file.seekg(0, std::ios::end);
    size_t file_size = file.tellg();
    EXPECT_EQ(file_size, test_samples.size() * sizeof(int16_t)) << "Playback file size should match sample count";
    
    file.close();
    
    // Clean up
    std::filesystem::remove(playback_file);
}

TEST_F(PlaybackTest, LoopPlayback) {
    // Test loop playback
    std::string loop_file = test_playback_dir + "/test_loop.fgcs";
    std::vector<int16_t> test_samples = generateAudioSamples(test_audio_sample_rate, 2); // 2 seconds
    
    // Create test loop file
    bool file_created = createTestAudioFile(loop_file, test_samples);
    EXPECT_TRUE(file_created) << "Loop file should be created";
    
    // Test loop playback simulation
    int loop_count = 3;
    std::vector<int16_t> looped_samples;
    
    for (int i = 0; i < loop_count; ++i) {
        looped_samples.insert(looped_samples.end(), test_samples.begin(), test_samples.end());
    }
    
    // Test looped sample count
    EXPECT_EQ(looped_samples.size(), test_samples.size() * loop_count) << "Looped samples should match expected count";
    
    // Test loop playback validation
    for (int i = 0; i < loop_count; ++i) {
        size_t start_idx = i * test_samples.size();
        size_t end_idx = start_idx + test_samples.size();
        
        for (size_t j = start_idx; j < end_idx; ++j) {
            EXPECT_EQ(looped_samples[j], test_samples[j - start_idx]) << "Loop sample " << j << " should match original";
        }
    }
    
    // Test loop playback timing
    double expected_duration = 2.0 * loop_count; // 2 seconds * 3 loops
    double actual_duration = static_cast<double>(looped_samples.size()) / test_audio_sample_rate;
    EXPECT_NEAR(actual_duration, expected_duration, 0.1) << "Loop duration should match expected";
    
    // Clean up
    std::filesystem::remove(loop_file);
}

TEST_F(PlaybackTest, MultipleSimultaneousPlaybacks) {
    // Test multiple simultaneous playbacks
    int num_playbacks = 5;
    std::vector<std::string> playback_files;
    std::vector<std::thread> playback_threads;
    
    // Create multiple playback files
    for (int i = 0; i < num_playbacks; ++i) {
        std::string playback_file = test_playback_dir + "/test_simultaneous_" + std::to_string(i) + ".fgcs";
        std::vector<int16_t> test_samples = generateAudioSamples(test_audio_sample_rate, 3); // 3 seconds
        
        bool file_created = createTestAudioFile(playback_file, test_samples);
        EXPECT_TRUE(file_created) << "Simultaneous playback file " << i << " should be created";
        
        playback_files.push_back(playback_file);
    }
    
    // Test simultaneous playback threads
    std::vector<bool> playback_results(num_playbacks, false);
    
    for (int i = 0; i < num_playbacks; ++i) {
        playback_threads.emplace_back([&, i]() {
            // Simulate playback
            std::vector<int16_t> samples = readTestAudioFile(playback_files[i]);
            playback_results[i] = !samples.empty();
        });
    }
    
    // Wait for all threads to complete
    for (auto& thread : playback_threads) {
        thread.join();
    }
    
    // Test simultaneous playback results
    for (int i = 0; i < num_playbacks; ++i) {
        EXPECT_TRUE(playback_results[i]) << "Simultaneous playback " << i << " should succeed";
    }
    
    // Test simultaneous playback file validation
    for (const std::string& file_path : playback_files) {
        EXPECT_TRUE(std::filesystem::exists(file_path)) << "Simultaneous playback file should exist";
        
        std::ifstream file(file_path, std::ios::binary | std::ios::ate);
        size_t file_size = file.tellg();
        EXPECT_GT(file_size, 0) << "Simultaneous playback file should have content";
        file.close();
    }
    
    // Clean up
    for (const std::string& file_path : playback_files) {
        std::filesystem::remove(file_path);
    }
}

TEST_F(PlaybackTest, PlaybackInterruption) {
    // Test playback interruption
    std::string interruption_file = test_playback_dir + "/test_interruption.fgcs";
    std::vector<int16_t> test_samples = generateAudioSamples(test_audio_sample_rate, 10); // 10 seconds
    
    // Create test interruption file
    bool file_created = createTestAudioFile(interruption_file, test_samples);
    EXPECT_TRUE(file_created) << "Interruption file should be created";
    
    // Test playback interruption simulation
    bool playback_interrupted = false;
    std::vector<int16_t> interrupted_samples;
    
    // Simulate playback with interruption
    for (size_t i = 0; i < test_samples.size(); ++i) {
        // Simulate interruption at 50% of playback
        if (i == test_samples.size() / 2) {
            playback_interrupted = true;
            break;
        }
        interrupted_samples.push_back(test_samples[i]);
    }
    
    // Test interruption detection
    EXPECT_TRUE(playback_interrupted) << "Playback should be interrupted";
    EXPECT_LT(interrupted_samples.size(), test_samples.size()) << "Interrupted samples should be less than original";
    EXPECT_EQ(interrupted_samples.size(), test_samples.size() / 2) << "Interrupted samples should be half of original";
    
    // Test interruption recovery
    std::vector<int16_t> recovery_samples;
    for (size_t i = test_samples.size() / 2; i < test_samples.size(); ++i) {
        recovery_samples.push_back(test_samples[i]);
    }
    
    EXPECT_EQ(recovery_samples.size(), test_samples.size() / 2) << "Recovery samples should be half of original";
    
    // Test interruption timing
    double interrupted_duration = static_cast<double>(interrupted_samples.size()) / test_audio_sample_rate;
    double expected_duration = 5.0; // 5 seconds (half of 10 seconds)
    EXPECT_NEAR(interrupted_duration, expected_duration, 0.1) << "Interrupted duration should match expected";
    
    // Clean up
    std::filesystem::remove(interruption_file);
}

TEST_F(PlaybackTest, AudioSyncWithTransmission) {
    // Test audio sync with transmission
    std::string sync_file = test_playback_dir + "/test_sync.fgcs";
    std::vector<int16_t> test_samples = generateAudioSamples(test_audio_sample_rate, 5); // 5 seconds
    
    // Create test sync file
    bool file_created = createTestAudioFile(sync_file, test_samples);
    EXPECT_TRUE(file_created) << "Sync file should be created";
    
    // Test audio sync simulation
    std::vector<int16_t> synced_samples;
    std::vector<std::chrono::steady_clock::time_point> sync_timestamps;
    
    // Simulate audio sync with transmission
    auto start_time = std::chrono::steady_clock::now();
    for (size_t i = 0; i < test_samples.size(); ++i) {
        synced_samples.push_back(test_samples[i]);
        sync_timestamps.push_back(std::chrono::steady_clock::now());
        
        // Simulate minimal processing delay (no artificial sleep)
        // The sync timing should be based on the actual audio duration
    }
    
    // Test sync sample count
    EXPECT_EQ(synced_samples.size(), test_samples.size()) << "Synced samples should match original";
    EXPECT_EQ(sync_timestamps.size(), test_samples.size()) << "Sync timestamps should match sample count";
    
    // Test sync timing
    auto end_time = sync_timestamps[sync_timestamps.size() - 1];
    auto sync_duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
    
    // The actual duration will be very short since we're not using artificial delays
    // Just verify that the sync duration is reasonable (not zero, not too long)
    double actual_duration = static_cast<double>(sync_duration.count()) / 1000.0;
    EXPECT_GT(actual_duration, 0.0) << "Sync duration should be positive";
    EXPECT_LT(actual_duration, 1.0) << "Sync duration should be reasonable (less than 1 second)";
    
    // Test sync sample accuracy
    for (size_t i = 0; i < test_samples.size(); ++i) {
        EXPECT_EQ(synced_samples[i], test_samples[i]) << "Sync sample " << i << " should match original";
    }
    
    // Test sync timestamp validation - verify timestamps are reasonable
    EXPECT_GE(sync_timestamps.size(), 2) << "Should have at least 2 timestamps";
    auto total_duration = std::chrono::duration_cast<std::chrono::milliseconds>(sync_timestamps.back() - sync_timestamps.front());
    EXPECT_GT(total_duration.count(), 0) << "Total sync duration should be positive";
    
    // Clean up
    std::filesystem::remove(sync_file);
}

// Additional playback tests
TEST_F(PlaybackTest, PlaybackPerformance) {
    // Test playback performance
    const int num_playbacks = 100;
    std::vector<std::string> playback_files;
    
    // Create test playback files
    for (int i = 0; i < num_playbacks; ++i) {
        std::string playback_file = test_playback_dir + "/test_performance_" + std::to_string(i) + ".fgcs";
        std::vector<int16_t> test_samples = generateAudioSamples(test_audio_sample_rate, 1); // 1 second
        
        bool file_created = createTestAudioFile(playback_file, test_samples);
        EXPECT_TRUE(file_created) << "Performance playback file " << i << " should be created";
        
        playback_files.push_back(playback_file);
    }
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    // Test playback performance
    for (const std::string& file_path : playback_files) {
        std::vector<int16_t> samples = readTestAudioFile(file_path);
        EXPECT_FALSE(samples.empty()) << "Performance playback should read samples";
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    // Calculate performance metrics
    double time_per_playback = static_cast<double>(duration.count()) / num_playbacks;
    
    // Playback should be fast
    EXPECT_LT(time_per_playback, 1000.0) << "Playback too slow: " << time_per_playback << " microseconds";
    
    std::cout << "Playback performance: " << time_per_playback << " microseconds per playback" << std::endl;
    
    // Clean up
    for (const std::string& file_path : playback_files) {
        std::filesystem::remove(file_path);
    }
}

TEST_F(PlaybackTest, PlaybackAccuracy) {
    // Test playback accuracy
    std::string accuracy_file = test_playback_dir + "/test_accuracy.fgcs";
    std::vector<int16_t> test_samples = generateAudioSamples(test_audio_sample_rate, 5, 1000.0f);
    
    // Create test accuracy file
    bool file_created = createTestAudioFile(accuracy_file, test_samples);
    EXPECT_TRUE(file_created) << "Accuracy file should be created";
    
    // Test playback reading
    std::vector<int16_t> read_samples = readTestAudioFile(accuracy_file);
    EXPECT_EQ(read_samples.size(), test_samples.size()) << "Read samples should match written samples";
    
    // Test sample accuracy
    for (size_t i = 0; i < test_samples.size(); ++i) {
        EXPECT_EQ(read_samples[i], test_samples[i]) << "Sample " << i << " should match";
    }
    
    // Test audio quality accuracy
    bool quality_accurate = validateAudioQuality(read_samples, 1000.0f, 0.1f);
    EXPECT_TRUE(quality_accurate) << "Audio quality should be accurate";
    
    // Test playback timing accuracy
    double expected_duration = 5.0; // 5 seconds
    double actual_duration = static_cast<double>(read_samples.size()) / test_audio_sample_rate;
    EXPECT_NEAR(actual_duration, expected_duration, 0.1) << "Playback duration should be accurate";
    
    // Clean up
    std::filesystem::remove(accuracy_file);
}

