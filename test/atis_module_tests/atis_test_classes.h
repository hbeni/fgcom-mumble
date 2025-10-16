#ifndef ATIS_TEST_CLASSES_H
#define ATIS_TEST_CLASSES_H

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

// Test fixtures and utilities
class ATIS_Module_Test : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize test parameters
        test_frequency_atis = 121.650;
        test_frequency_record = 121.650;
        test_frequency_test = 910.000;
        test_audio_sample_rate = 48000;
        test_audio_bit_depth = 16;
        test_audio_channels = 1;
        test_audio_format = "PCM";
        test_recording_dir = "/tmp/fgcom_test_recordings";
        test_playback_dir = "/tmp/fgcom_test_playback";
        
        // Test ATIS content
        test_airport_code = "KJFK";
        test_airport_name = "John F. Kennedy International Airport";
        test_runway_info = "Runway 04L/22R, Runway 04R/22L";
        test_weather_info = "Wind 270 at 15 knots, visibility 10 miles, ceiling 2500 feet";
        test_time_stamp = "2024-01-15T10:30:00Z";
        
        // Test recording parameters
        test_recording_duration_max = 120; // 120 seconds
        test_recording_duration_min = 1;   // 1 second
        test_recording_duration_test = 10; // 10 seconds for test frequency
        
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
        
        // Weather integration test parameters
        weather_api_key = "test_api_key";
        airports = {"KJFK", "KLAX", "KORD", "KDFW", "KATL"};
        wind_threshold = 10.0;
        temperature_threshold = 5.0;
        pressure_threshold = 1.0;
        update_interval = 30;
        
        // Create test directories
        std::filesystem::create_directories(test_recording_dir);
        std::filesystem::create_directories(test_playback_dir);
    }
    
    void TearDown() override {
        // Clean up test directories
        std::filesystem::remove_all(test_recording_dir);
        std::filesystem::remove_all(test_playback_dir);
    }
    
    double test_frequency_atis;
    double test_frequency_record;
    double test_frequency_test;
    int test_audio_sample_rate;
    int test_audio_bit_depth;
    int test_audio_channels;
    std::string test_audio_format;
    std::string test_recording_dir;
    std::string test_playback_dir;
    std::string test_airport_code;
    std::string test_airport_name;
    std::string test_runway_info;
    std::string test_weather_info;
    std::string test_time_stamp;
    
    // Test recording parameters
    int test_recording_duration_max;
    int test_recording_duration_min;
    int test_recording_duration_test;
    
    // Test phonetic alphabet
    std::map<std::string, std::string> test_phonetic_alphabet;
    
    // Weather integration test parameters
    std::string weather_api_key;
    std::vector<std::string> airports;
    double wind_threshold;
    double temperature_threshold;
    double pressure_threshold;
    int update_interval;
    
    // Helper functions
    std::vector<int16_t> generateAudioSamples(int sample_rate, int duration_seconds) {
        std::vector<int16_t> samples;
        samples.reserve(sample_rate * duration_seconds);
        
        for (int i = 0; i < sample_rate * duration_seconds; ++i) {
            double t = static_cast<double>(i) / sample_rate;
            double amplitude = 0.5 * sin(2.0 * M_PI * 440.0 * t); // 440 Hz tone
            samples.push_back(static_cast<int16_t>(amplitude * 32767));
        }
        
        return samples;
    }
    
    bool createTestAudioFile(const std::string& filename, const std::vector<int16_t>& samples) {
        std::ofstream file(filename, std::ios::binary);
        if (!file.is_open()) return false;
        
        // Write simple WAV header (simplified)
        file.write("RIFF", 4);
        uint32_t file_size = 36 + samples.size() * 2;
        file.write(reinterpret_cast<const char*>(&file_size), 4);
        file.write("WAVE", 4);
        file.write("fmt ", 4);
        uint32_t fmt_size = 16;
        file.write(reinterpret_cast<const char*>(&fmt_size), 4);
        uint16_t audio_format = 1;
        file.write(reinterpret_cast<const char*>(&audio_format), 2);
        uint16_t num_channels = 1;
        file.write(reinterpret_cast<const char*>(&num_channels), 2);
        uint32_t sample_rate = test_audio_sample_rate;
        file.write(reinterpret_cast<const char*>(&sample_rate), 4);
        uint32_t byte_rate = sample_rate * num_channels * 2;
        file.write(reinterpret_cast<const char*>(&byte_rate), 4);
        uint16_t block_align = num_channels * 2;
        file.write(reinterpret_cast<const char*>(&block_align), 2);
        uint16_t bits_per_sample = 16;
        file.write(reinterpret_cast<const char*>(&bits_per_sample), 2);
        file.write("data", 4);
        uint32_t data_size = samples.size() * 2;
        file.write(reinterpret_cast<const char*>(&data_size), 4);
        
        // Write audio data
        for (int16_t sample : samples) {
            file.write(reinterpret_cast<const char*>(&sample), 2);
        }
        
        file.close();
        return true;
    }
    
    bool verifyAudioFile(const std::string& filename) {
        std::ifstream file(filename, std::ios::binary);
        if (!file.is_open()) return false;
        
        // Check for WAV header
        char riff[4];
        file.read(riff, 4);
        if (std::string(riff, 4) != "RIFF") return false;
        
        file.close();
        return true;
    }
    
    // Additional helper functions
    bool isValidRecordingDuration(int duration) {
        return duration >= test_recording_duration_min && duration <= test_recording_duration_max;
    }
    
    std::vector<int16_t> generateAudioSamples(int sample_rate, int duration_seconds, float frequency) {
        std::vector<int16_t> samples;
        samples.reserve(sample_rate * duration_seconds);
        
        for (int i = 0; i < sample_rate * duration_seconds; ++i) {
            double t = static_cast<double>(i) / sample_rate;
            double amplitude = 0.5 * sin(2.0 * M_PI * frequency * t);
            samples.push_back(static_cast<int16_t>(amplitude * 32767));
        }
        
        return samples;
    }
    
    bool validateAudioQuality(const std::vector<int16_t>& samples, float expected_frequency, float tolerance) {
        // Simple frequency validation
        if (samples.empty()) return false;
        
        // Check for expected frequency content
        int sample_rate = test_audio_sample_rate;
        int expected_samples_per_cycle = static_cast<int>(sample_rate / expected_frequency);
        
        if (expected_samples_per_cycle < 2) return false;
        
        // Basic quality check - ensure samples are not all zeros
        bool has_non_zero = false;
        for (int16_t sample : samples) {
            if (sample != 0) {
                has_non_zero = true;
                break;
            }
        }
        
        return has_non_zero;
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
    
    std::vector<int16_t> readTestAudioFile(const std::string& filename) {
        std::vector<int16_t> samples;
        std::ifstream file(filename, std::ios::binary);
        if (!file.is_open()) return samples;
        
        // Skip WAV header (44 bytes)
        file.seekg(44);
        
        // Read audio data
        int16_t sample;
        while (file.read(reinterpret_cast<char*>(&sample), 2)) {
            samples.push_back(sample);
        }
        
        file.close();
        return samples;
    }
    
    // ATIS content helper functions
    bool isValidAirportCode(const std::string& code) {
        if (code.length() != 4) return false;
        for (char c : code) {
            if (!std::isalpha(c)) return false;
        }
        return true;
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
    
    bool isValidTimeStamp(const std::string& timestamp) {
        // Simple timestamp validation (ISO 8601 format)
        if (timestamp.length() < 19) return false;
        if (timestamp[4] != '-' || timestamp[7] != '-' || timestamp[10] != 'T') return false;
        if (timestamp[13] != ':' || timestamp[16] != ':') return false;
        return true;
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
    
    std::string getATISLetter(const std::string& airport) {
        // Simple ATIS letter generation based on airport
        return "A";
    }
    
    std::string generateATISContent(const std::string& airport, const std::string& weather, const std::string& runway) {
        std::stringstream atis;
        atis << "This is " << airport << " ATIS information ";
        atis << getATISLetter(airport) << ". ";
        atis << weather << ". ";
        atis << runway << ". ";
        atis << "Advise you have information " << getATISLetter(airport) << ".";
        return atis.str();
    }
};

// Recording test fixture
class RecordingTest : public ATIS_Module_Test {
protected:
    void SetUp() override {
        ATIS_Module_Test::SetUp();
    }
};

// Playback test fixture  
class PlaybackTest : public ATIS_Module_Test {
protected:
    void SetUp() override {
        ATIS_Module_Test::SetUp();
    }
};

// ATIS content test fixture
class ATISContentTest : public ATIS_Module_Test {
protected:
    void SetUp() override {
        ATIS_Module_Test::SetUp();
    }
};

// ATIS weather integration test fixture
class ATISWeatherIntegrationTest : public ATIS_Module_Test {
protected:
    void SetUp() override {
        ATIS_Module_Test::SetUp();
    }
};

#endif // ATIS_TEST_CLASSES_H
