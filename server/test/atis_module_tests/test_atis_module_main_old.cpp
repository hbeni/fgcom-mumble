#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <thread>
#include <vector>
#include <chrono>
#include <memory>
#include <random>
#include <cmath>
#include <fstream>
#include <sstream>
#include <map>
#include <set>
#include <algorithm>
#include <numeric>
#include <filesystem>
#include "atis_functions.h"

// ATIS module test fixtures and utilities
#include "atis_test_classes.h"

// Test implementations start here
        
        // Test audio parameters
        test_audio_sample_rate = 48000;
        test_audio_bit_depth = 16;
        test_audio_channels = 1;
        test_audio_format = "PCM";
        
        // Test ATIS content
        test_airport_code = "KJFK";
        test_airport_name = "John F. Kennedy International Airport";
        test_runway_info = "Runway 04L/22R, Runway 04R/22L";
        test_weather_info = "Wind 270 at 15 knots, visibility 10 miles, ceiling 2500 feet";
        test_time_stamp = "2024-01-15T10:30:00Z";
        
        // Test phonetic alphabet
        test_phonetic_alphabet = {
            {"A", "Alpha"}, {"B", "Bravo"}, {"C", "Charlie"}, {"D", "Delta"},
            {"E", "Echo"}, {"F", "Foxtrot"}, {"G", "Golf"}, {"H", "Hotel"},
            {"I", "India"}, {"J", "Juliet"}, {"K", "Kilo"}, {"L", "Lima"},
            {"M", "Mike"}, {"N", "November"}, {"O", "Oscar"}, {"P", "Papa"},
            {"Q", "Quebec"}, {"R", "Romeo"}, {"S", "Sierra"}, {"T", "Tango"},
            {"U", "Uniform"}, {"V", "Victor"}, {"W", "Whiskey"}, {"X", "X-ray"},
            {"Y", "Yankee"}, {"Z", "Zulu"}
        };
        
        // Test file paths
        test_recording_dir = "/tmp/atis_recordings";
        test_playback_dir = "/tmp/atis_playback";
        test_sample_file = "test_sample.fgcs";
        
        // Create test directories
        std::filesystem::create_directories(test_recording_dir);
        std::filesystem::create_directories(test_playback_dir);
    }
    
    void TearDown() override {
        // Clean up test directories
        std::filesystem::remove_all(test_recording_dir);
        std::filesystem::remove_all(test_playback_dir);
    }
    
    // Test parameters
    double test_frequency_atis, test_frequency_record, test_frequency_test;
    int test_recording_duration_max, test_recording_duration_min, test_recording_duration_test;
    int test_audio_sample_rate, test_audio_bit_depth, test_audio_channels;
    std::string test_audio_format;
    std::string test_airport_code, test_airport_name, test_runway_info, test_weather_info, test_time_stamp;
    std::map<std::string, std::string> test_phonetic_alphabet;
    std::string test_recording_dir, test_playback_dir, test_sample_file;
    
    // Helper functions for test data generation
    std::vector<int16_t> generateAudioSamples(int sample_rate, int duration_seconds, float frequency = 1000.0f) {
        std::vector<int16_t> samples(sample_rate * duration_seconds);
        for (size_t i = 0; i < samples.size(); ++i) {
            float sample = 0.5f * std::sin(2.0f * M_PI * frequency * i / sample_rate);
            samples[i] = static_cast<int16_t>(sample * 32767.0f);
        }
        return samples;
    }
    
    std::string generateATISContent(const std::string& airport_code, const std::string& weather_info, const std::string& runway_info) {
        std::stringstream content;
        content << "This is " << airport_code << " information ";
        content << weather_info << ". ";
        content << runway_info << ". ";
        content << "Advise you have information ";
        return content.str();
    }
    
    std::string convertToPhonetic(const std::string& text) {
        std::string phonetic;
        for (char c : text) {
            if (std::isalpha(c)) {
                std::string letter(1, std::toupper(c));
                if (test_phonetic_alphabet.find(letter) != test_phonetic_alphabet.end()) {
                    phonetic += test_phonetic_alphabet[letter] + " ";
                }
            } else {
                phonetic += c;
            }
        }
        return phonetic;
    }
    
    std::string generateFGCSHeader(const std::string& callsign, const std::string& frequency, const std::string& location) {
        std::stringstream header;
        header << "1.1 FGCS\n";
        header << callsign << "\n";
        header << frequency << "\n";
        header << location << "\n";
        header << test_time_stamp << "\n";
        return header.str();
    }
    
    std::string generateWeatherInfo() {
        std::stringstream weather;
        weather << "Wind 270 at 15 knots, ";
        weather << "visibility 10 miles, ";
        weather << "ceiling 2500 feet, ";
        weather << "temperature 15 degrees Celsius, ";
        weather << "dew point 10 degrees Celsius";
        return weather.str();
    }
    
    std::string generateRunwayInfo() {
        std::stringstream runway;
        runway << "Runway 04L/22R, ";
        runway << "Runway 04R/22L, ";
        runway << "Runway 13L/31R, ";
        runway << "Runway 13R/31L";
        return runway.str();
    }
    
    std::string generateNOTAMInfo() {
        std::stringstream notam;
        notam << "NOTAM 001: Runway 04L closed for maintenance, ";
        notam << "NOTAM 002: Taxiway Alpha closed, ";
        notam << "NOTAM 003: ILS 04L out of service";
        return notam.str();
    }
    
    // Helper to create test audio file
    bool createTestAudioFile(const std::string& filename, const std::vector<int16_t>& samples) {
        std::ofstream file(filename, std::ios::binary);
        if (!file.is_open()) {
            return false;
        }
        
        file.write(reinterpret_cast<const char*>(samples.data()), samples.size() * sizeof(int16_t));
        file.close();
        return true;
    }
    
    // Helper to read test audio file
    std::vector<int16_t> readTestAudioFile(const std::string& filename) {
        std::ifstream file(filename, std::ios::binary);
        if (!file.is_open()) {
            return {};
        }
        
        file.seekg(0, std::ios::end);
        size_t file_size = file.tellg();
        file.seekg(0, std::ios::beg);
        
        std::vector<int16_t> samples(file_size / sizeof(int16_t));
        file.read(reinterpret_cast<char*>(samples.data()), file_size);
        file.close();
        
        return samples;
    }
    
    // Helper to validate audio quality
    bool validateAudioQuality(const std::vector<int16_t>& samples, float expected_frequency, float tolerance = 0.1f) {
        if (samples.empty()) {
            return false;
        }
        
        // Simple frequency analysis (Goertzel algorithm)
        float sample_rate = test_audio_sample_rate;
        float target_frequency = expected_frequency;
        float omega = 2.0f * M_PI * target_frequency / sample_rate;
        
        float cos_omega = std::cos(omega);
        float sin_omega = std::sin(omega);
        float coeff = 2.0f * cos_omega;
        
        float q1 = 0.0f, q2 = 0.0f;
        for (int16_t sample : samples) {
            float normalized_sample = static_cast<float>(sample) / 32767.0f;
            float q0 = coeff * q1 - q2 + normalized_sample;
            q2 = q1;
            q1 = q0;
        }
        
        float magnitude = std::sqrt(q1 * q1 + q2 * q2 - q1 * q2 * coeff);
        
        // Use sin_omega and magnitude for frequency validation
        float frequency_strength = magnitude / samples.size();
        float omega_factor = std::abs(sin_omega) + std::abs(cos_omega);
        
        // Check if the target frequency is present within tolerance
        return frequency_strength > tolerance && omega_factor > 0.1f;
    }
    
    // Helper to measure execution time
    template<typename Func>
    auto measureTime(Func&& func) -> decltype(func()) {
        auto start = std::chrono::high_resolution_clock::now();
        auto result = func();
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        std::cout << "Execution time: " << duration.count() << " microseconds" << std::endl;
        return result;
    }
    
    // Helper to validate airport code
    bool isValidAirportCode(const std::string& code) {
        if (code.length() != 4) {
            return false;
        }
        
        // Check if it's a valid ICAO code (4 letters)
        for (char c : code) {
            if (!std::isalpha(c)) {
                return false;
            }
        }
        
        return true;
    }
    
    // Helper to validate frequency
    bool isValidFrequency(double frequency) {
        return frequency >= 118.0 && frequency <= 137.0;
    }
    
    // Helper to validate recording duration
    bool isValidRecordingDuration(int duration) {
        return duration >= test_recording_duration_min && duration <= test_recording_duration_max;
    }
    
    // Helper to validate audio format
    bool isValidAudioFormat(const std::string& format) {
        return format == "PCM" || format == "WAV" || format == "MP3" || format == "OGG";
    }
    
    // Helper to validate time stamp
    bool isValidTimeStamp(const std::string& timestamp) {
        // Simple timestamp validation (ISO 8601 format)
        return timestamp.length() == 20 && timestamp[4] == '-' && timestamp[7] == '-' && timestamp[10] == 'T';
    }
    
    // Helper to validate audio frequency
    bool validateAudioFrequency(const std::vector<int16_t>& samples, float target_frequency, float tolerance) {
        if (samples.empty()) {
            return false;
        }
        
        // Simple frequency validation using FFT-like approach
        int sample_rate = test_audio_sample_rate;
        int num_samples = samples.size();
        
        // Calculate frequency components
        double sin_omega = std::sin(2.0 * M_PI * target_frequency / sample_rate);
        double cos_omega = std::cos(2.0 * M_PI * target_frequency / sample_rate);
        
        double real_sum = 0.0;
        double imag_sum = 0.0;
        
        for (int i = 0; i < num_samples; ++i) {
            double sample = static_cast<double>(samples[i]) / 32767.0;
            real_sum += sample * std::cos(2.0 * M_PI * target_frequency * i / sample_rate);
            imag_sum += sample * std::sin(2.0 * M_PI * target_frequency * i / sample_rate);
        }
        
        double magnitude = std::sqrt(real_sum * real_sum + imag_sum * imag_sum);
        
        // Use the calculated values to determine frequency presence
        double frequency_strength = magnitude / num_samples;
        double omega_factor = std::abs(sin_omega) + std::abs(cos_omega);
        
        // Check if the target frequency is present within tolerance
        return frequency_strength > tolerance && omega_factor > 0.1;
    }
    
    
};

// Test suite for recording tests
class RecordingTest : public ATIS_Module_Test {
protected:
    void SetUp() override {
        ATIS_Module_Test::SetUp();
    }
};

// Test suite for playback tests
class PlaybackTest : public ATIS_Module_Test {
protected:
    void SetUp() override {
        ATIS_Module_Test::SetUp();
    }
};

// Test suite for ATIS content tests
class ATISContentTest : public ATIS_Module_Test {
protected:
    void SetUp() override {
        ATIS_Module_Test::SetUp();
    }
};



// ATIS Weather Integration Tests
class ATISWeatherIntegrationTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize ATIS weather integration test parameters
        weather_api_key = "test_api_key";
        airports = {"KJFK", "ENGM", "EGLL", "KLAX"};
        wind_threshold = 10.0;
        temperature_threshold = 2.0;
        pressure_threshold = 0.68;
        update_interval = 60;
    }
    
    std::string weather_api_key;
    std::vector<std::string> airports;
    double wind_threshold;
    double temperature_threshold;
    double pressure_threshold;
    int update_interval;
};

TEST_F(ATISWeatherIntegrationTest, WeatherDataFetching) {
    // Test weather data fetching from API
    for (const auto& airport : airports) {
        std::string weather_data = fetchWeatherData(airport, weather_api_key);
        EXPECT_FALSE(weather_data.empty()) << "Should fetch weather data for " << airport;
        
        // Validate weather data format
        EXPECT_TRUE(weather_data.find("wind") != std::string::npos) << "Should contain wind information";
        EXPECT_TRUE(weather_data.find("temperature") != std::string::npos) << "Should contain temperature";
        EXPECT_TRUE(weather_data.find("pressure") != std::string::npos) << "Should contain pressure";
    }
}

TEST_F(ATISWeatherIntegrationTest, WeatherChangeDetection) {
    // Test weather change detection
    std::string old_weather = "Wind 270 at 15 knots, temperature 15C, pressure 1013.25";
    std::string new_weather = "Wind 280 at 18 knots, temperature 17C, pressure 1012.50";
    
    bool significant_change = detectWeatherChange(old_weather, new_weather, 
                                             wind_threshold, temperature_threshold, pressure_threshold);
    EXPECT_TRUE(significant_change) << "Should detect significant weather change";
}

TEST_F(ATISWeatherIntegrationTest, ATISLetterSystem) {
    // Test ATIS letter designation system
    std::string letter = getATISLetter("KJFK");
    EXPECT_FALSE(letter.empty()) << "Should generate ATIS letter";
    EXPECT_TRUE(letter.length() == 1) << "ATIS letter should be single character";
    EXPECT_TRUE(std::isalpha(letter[0])) << "ATIS letter should be alphabetic";
}

TEST_F(ATISWeatherIntegrationTest, AutomaticATISGeneration) {
    // Test automatic ATIS generation based on weather changes
    std::string airport = "KJFK";
    std::string weather_data = "Wind 270 at 15 knots, visibility 10 miles, ceiling 2500 feet";
    
    std::string atis_content = generateAutomaticATIS(airport, weather_data);
    EXPECT_FALSE(atis_content.empty()) << "Should generate ATIS content";
    EXPECT_TRUE(atis_content.find(airport) != std::string::npos) << "Should contain airport code";
    EXPECT_TRUE(atis_content.find("Wind") != std::string::npos) << "Should contain weather information";
}

TEST_F(ATISWeatherIntegrationTest, WeatherThresholds) {
    // Test weather change thresholds
    double wind_change = 5.0;
    double temperature_change = 1.0;
    double pressure_change = 0.3;
    
    EXPECT_FALSE(shouldUpdateATIS(wind_change, temperature_change, pressure_change, 
                                 wind_threshold, temperature_threshold, pressure_threshold))
        << "Should not update ATIS for minor changes";
    
    wind_change = 15.0;
    temperature_change = 3.0;
    pressure_change = 1.0;
    
    EXPECT_TRUE(shouldUpdateATIS(wind_change, temperature_change, pressure_change,
                                wind_threshold, temperature_threshold, pressure_threshold))
        << "Should update ATIS for significant changes";
}

TEST_F(ATISWeatherIntegrationTest, NetworkGPUScalingIntegration) {
    // Test integration with dynamic GPU scaling for ATIS generation
    int user_count = 75;
    int optimal_gpus = calculateOptimalGPUsForATIS(user_count);
    
    EXPECT_GE(optimal_gpus, 1) << "Should allocate at least 1 GPU for ATIS generation";
    EXPECT_LE(optimal_gpus, 8) << "Should not exceed maximum GPU allocation";
}

// Helper functions for ATIS weather integration tests
// Function implementations moved to atis_functions.cpp

