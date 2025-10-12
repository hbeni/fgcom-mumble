#include "atis_test_classes.h"

// 7.1 Recording Tests
TEST_F(RecordingTest, VoiceRecordingStartStop) {
    // Test voice recording start/stop
    std::string recording_file = test_recording_dir + "/test_recording.fgcs";
    std::vector<int16_t> test_samples = generateAudioSamples(test_audio_sample_rate, 5); // 5 seconds
    
    // Test recording start
    bool recording_started = createTestAudioFile(recording_file, test_samples);
    EXPECT_TRUE(recording_started) << "Recording should start successfully";
    
    // Test recording file creation
    EXPECT_TRUE(std::filesystem::exists(recording_file)) << "Recording file should be created";
    
    // Test recording file size
    std::ifstream file(recording_file, std::ios::binary | std::ios::ate);
    EXPECT_TRUE(file.is_open()) << "Recording file should be readable";
    
    size_t file_size = file.tellg();
    EXPECT_GT(file_size, 0) << "Recording file should have content";
    EXPECT_EQ(file_size, test_samples.size() * sizeof(int16_t)) << "Recording file size should match sample count";
    
    file.close();
    
    // Test recording stop
    std::filesystem::remove(recording_file);
    EXPECT_FALSE(std::filesystem::exists(recording_file)) << "Recording file should be removed after stop";
}

TEST_F(RecordingTest, RecordingDurationLimits) {
    // Test recording duration limits
    std::vector<int> test_durations = {1, 10, 60, 120, 150}; // seconds
    
    for (int duration : test_durations) {
        std::string recording_file = test_recording_dir + "/test_duration_" + std::to_string(duration) + ".fgcs";
        std::vector<int16_t> test_samples = generateAudioSamples(test_audio_sample_rate, duration);
        
        // Test recording duration validation
        bool is_valid_duration = isValidRecordingDuration(duration);
        
        if (duration <= test_recording_duration_max && duration >= test_recording_duration_min) {
            EXPECT_TRUE(is_valid_duration) << "Duration " << duration << " should be valid";
            
            // Test recording creation
            bool recording_created = createTestAudioFile(recording_file, test_samples);
            EXPECT_TRUE(recording_created) << "Recording should be created for valid duration";
            
            // Test recording file size
            std::ifstream file(recording_file, std::ios::binary | std::ios::ate);
            size_t file_size = file.tellg();
            EXPECT_EQ(file_size, test_samples.size() * sizeof(int16_t)) << "Recording file size should match duration";
            file.close();
            
        } else {
            EXPECT_FALSE(is_valid_duration) << "Duration " << duration << " should be invalid";
        }
        
        // Clean up
        std::filesystem::remove(recording_file);
    }
    
    // Test maximum recording duration
    int max_duration = test_recording_duration_max;
    std::string max_recording_file = test_recording_dir + "/test_max_duration.fgcs";
    std::vector<int16_t> max_samples = generateAudioSamples(test_audio_sample_rate, max_duration);
    
    bool max_recording_created = createTestAudioFile(max_recording_file, max_samples);
    EXPECT_TRUE(max_recording_created) << "Maximum duration recording should be created";
    
    // Test recording duration enforcement
    int exceeded_duration = max_duration + 10;
    std::string exceeded_recording_file = test_recording_dir + "/test_exceeded_duration.fgcs";
    std::vector<int16_t> exceeded_samples = generateAudioSamples(test_audio_sample_rate, exceeded_duration);
    
    // Should be truncated to maximum duration
    std::vector<int16_t> truncated_samples(exceeded_samples.begin(), exceeded_samples.begin() + max_duration * test_audio_sample_rate);
    bool exceeded_recording_created = createTestAudioFile(exceeded_recording_file, truncated_samples);
    EXPECT_TRUE(exceeded_recording_created) << "Exceeded duration recording should be truncated";
    
    // Clean up
    std::filesystem::remove(max_recording_file);
    std::filesystem::remove(exceeded_recording_file);
}

TEST_F(RecordingTest, AudioQualityVerification) {
    // Test audio quality verification
    std::vector<float> test_frequencies = {440.0f, 880.0f, 1320.0f, 1760.0f}; // Hz
    int test_duration = 2; // seconds
    
    for (float frequency : test_frequencies) {
        std::string recording_file = test_recording_dir + "/test_quality_" + std::to_string(static_cast<int>(frequency)) + ".fgcs";
        std::vector<int16_t> test_samples = generateAudioSamples(test_audio_sample_rate, test_duration, frequency);
        
        // Test recording creation
        bool recording_created = createTestAudioFile(recording_file, test_samples);
        EXPECT_TRUE(recording_created) << "Recording should be created for frequency " << frequency;
        
        // Test audio quality validation
        bool quality_valid = validateAudioQuality(test_samples, frequency, 0.1f);
        EXPECT_TRUE(quality_valid) << "Audio quality should be valid for frequency " << frequency;
        
        // Test audio sample validation
        EXPECT_GT(test_samples.size(), 0) << "Audio samples should not be empty";
        EXPECT_EQ(test_samples.size(), test_audio_sample_rate * test_duration) << "Audio sample count should match duration";
        
        // Test audio sample range
        for (int16_t sample : test_samples) {
            EXPECT_GE(sample, -32768) << "Audio sample should be >= -32768";
            EXPECT_LE(sample, 32767) << "Audio sample should be <= 32767";
        }
        
        // Clean up
        std::filesystem::remove(recording_file);
    }
    
    // Test audio quality with noise
    std::string noise_recording_file = test_recording_dir + "/test_noise.fgcs";
    std::vector<int16_t> noise_samples = generateAudioSamples(test_audio_sample_rate, test_duration, 1000.0f);
    
    // Add noise to samples
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(-1000, 1000);
    
    for (size_t i = 0; i < noise_samples.size(); ++i) {
        noise_samples[i] += dis(gen);
    }
    
    bool noise_recording_created = createTestAudioFile(noise_recording_file, noise_samples);
    EXPECT_TRUE(noise_recording_created) << "Noise recording should be created";
    
    // Test noise quality validation
    bool noise_quality_valid = validateAudioQuality(noise_samples, 1000.0f, 0.2f); // Higher tolerance for noise
    EXPECT_TRUE(noise_quality_valid) << "Noise audio quality should be valid";
    
    // Clean up
    std::filesystem::remove(noise_recording_file);
}

TEST_F(RecordingTest, FileFormatCorrectness) {
    // Test file format correctness
    std::string recording_file = test_recording_dir + "/test_format.fgcs";
    std::vector<int16_t> test_samples = generateAudioSamples(test_audio_sample_rate, 5);
    
    // Test FGCS header generation
    std::string callsign = test_airport_code;
    std::string frequency = std::to_string(test_frequency_atis);
    std::string location = "40.7128,-74.0060,100.0";
    
    std::string header = generateFGCSHeader(callsign, frequency, location);
    EXPECT_FALSE(header.empty()) << "FGCS header should not be empty";
    EXPECT_TRUE(header.find("1.1 FGCS") != std::string::npos) << "FGCS header should contain version";
    EXPECT_TRUE(header.find(callsign) != std::string::npos) << "FGCS header should contain callsign";
    EXPECT_TRUE(header.find(frequency) != std::string::npos) << "FGCS header should contain frequency";
    EXPECT_TRUE(header.find(location) != std::string::npos) << "FGCS header should contain location";
    
    // Test file format validation
    std::ofstream file(recording_file, std::ios::binary);
    EXPECT_TRUE(file.is_open()) << "Recording file should be writable";
    
    // Write header
    file.write(header.c_str(), header.length());
    
    // Write audio samples
    file.write(reinterpret_cast<const char*>(test_samples.data()), test_samples.size() * sizeof(int16_t));
    file.close();
    
    // Test file format reading
    std::ifstream read_file(recording_file, std::ios::binary);
    EXPECT_TRUE(read_file.is_open()) << "Recording file should be readable";
    
    // Read header
    std::string line;
    std::getline(read_file, line);
    EXPECT_EQ(line, "1.1 FGCS") << "First line should be version";
    
    std::getline(read_file, line);
    EXPECT_EQ(line, callsign) << "Second line should be callsign";
    
    std::getline(read_file, line);
    EXPECT_EQ(line, frequency) << "Third line should be frequency";
    
    std::getline(read_file, line);
    EXPECT_EQ(line, location) << "Fourth line should be location";
    
    std::getline(read_file, line);
    EXPECT_EQ(line, test_time_stamp) << "Fifth line should be timestamp";
    
    read_file.close();
    
    // Clean up
    std::filesystem::remove(recording_file);
}

TEST_F(RecordingTest, StorageManagement) {
    // Test storage management
    std::vector<std::string> test_files;
    int num_files = 10;
    
    // Create multiple recording files
    for (int i = 0; i < num_files; ++i) {
        std::string recording_file = test_recording_dir + "/test_storage_" + std::to_string(i) + ".fgcs";
        std::vector<int16_t> test_samples = generateAudioSamples(test_audio_sample_rate, 5);
        
        bool recording_created = createTestAudioFile(recording_file, test_samples);
        EXPECT_TRUE(recording_created) << "Recording file " << i << " should be created";
        
        test_files.push_back(recording_file);
    }
    
    // Test storage directory
    EXPECT_TRUE(std::filesystem::exists(test_recording_dir)) << "Recording directory should exist";
    
    // Test file count
    int file_count = 0;
    for (const auto& entry : std::filesystem::directory_iterator(test_recording_dir)) {
        if (entry.is_regular_file()) {
            file_count++;
        }
    }
    EXPECT_EQ(file_count, num_files) << "File count should match created files";
    
    // Test file sizes
    for (const std::string& file_path : test_files) {
        EXPECT_TRUE(std::filesystem::exists(file_path)) << "Recording file should exist";
        
        std::ifstream file(file_path, std::ios::binary | std::ios::ate);
        size_t file_size = file.tellg();
        EXPECT_GT(file_size, 0) << "Recording file should have content";
        file.close();
    }
    
    // Test storage cleanup
    for (const std::string& file_path : test_files) {
        std::filesystem::remove(file_path);
        EXPECT_FALSE(std::filesystem::exists(file_path)) << "Recording file should be removed";
    }
    
    // Test directory cleanup
    std::filesystem::remove(test_recording_dir);
    EXPECT_FALSE(std::filesystem::exists(test_recording_dir)) << "Recording directory should be removed";
}

// Additional recording tests
TEST_F(RecordingTest, RecordingPerformance) {
    // Test recording performance
    const int num_recordings = 100;
    std::vector<std::string> recording_files;
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    // Test recording creation performance
    for (int i = 0; i < num_recordings; ++i) {
        std::string recording_file = test_recording_dir + "/test_performance_" + std::to_string(i) + ".fgcs";
        std::vector<int16_t> test_samples = generateAudioSamples(test_audio_sample_rate, 1); // 1 second
        
        bool recording_created = createTestAudioFile(recording_file, test_samples);
        EXPECT_TRUE(recording_created) << "Recording " << i << " should be created";
        
        recording_files.push_back(recording_file);
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    // Calculate performance metrics
    double time_per_recording = static_cast<double>(duration.count()) / num_recordings;
    
    // Recording should be fast
    EXPECT_LT(time_per_recording, 1000.0) << "Recording too slow: " << time_per_recording << " microseconds";
    
    std::cout << "Recording performance: " << time_per_recording << " microseconds per recording" << std::endl;
    
    // Clean up
    for (const std::string& file_path : recording_files) {
        std::filesystem::remove(file_path);
    }
}

TEST_F(RecordingTest, RecordingAccuracy) {
    // Test recording accuracy
    std::string recording_file = test_recording_dir + "/test_accuracy.fgcs";
    std::vector<int16_t> test_samples = generateAudioSamples(test_audio_sample_rate, 5, 1000.0f);
    
    // Test recording creation
    bool recording_created = createTestAudioFile(recording_file, test_samples);
    EXPECT_TRUE(recording_created) << "Recording should be created";
    
    // Test recording reading
    std::vector<int16_t> read_samples = readTestAudioFile(recording_file);
    EXPECT_EQ(read_samples.size(), test_samples.size()) << "Read samples should match written samples";
    
    // Test sample accuracy
    for (size_t i = 0; i < test_samples.size(); ++i) {
        EXPECT_EQ(read_samples[i], test_samples[i]) << "Sample " << i << " should match";
    }
    
    // Test audio quality accuracy
    bool quality_accurate = validateAudioQuality(read_samples, 1000.0f, 0.1f);
    EXPECT_TRUE(quality_accurate) << "Audio quality should be accurate";
    
    // Clean up
    std::filesystem::remove(recording_file);
}

