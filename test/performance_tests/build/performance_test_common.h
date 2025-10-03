#ifndef PERFORMANCE_TEST_COMMON_H
#define PERFORMANCE_TEST_COMMON_H

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <chrono>
#include <thread>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <random>
#include <algorithm>
#include <numeric>
#include <cmath>
#include <queue>
#include <set>
#include <unordered_map>
#include <functional>
#include <fstream>
#include <sstream>
#include <regex>
#include <exception>
#include <future>
#include <array>
#include <cstring>
#include <chrono>
#include <ratio>

// Mock classes for performance testing
class MockAudioEncoder {
public:
    MockAudioEncoder() = default;
    
    virtual ~MockAudioEncoder() = default;
    
    // Audio encoding methods
    virtual std::vector<uint8_t> encodeAudio(const std::vector<float>& audio_data) {
        auto start_time = std::chrono::high_resolution_clock::now();
        
        // Simulate audio encoding
        std::vector<uint8_t> encoded_data;
        encoded_data.reserve(audio_data.size() * sizeof(float));
        
        for (float sample : audio_data) {
            // Convert float to bytes (simplified)
            uint8_t* bytes = reinterpret_cast<uint8_t*>(&sample);
            for (size_t i = 0; i < sizeof(float); ++i) {
                encoded_data.push_back(bytes[i]);
            }
        }
        
        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
        
        // Simulate encoding latency
        std::this_thread::sleep_for(std::chrono::microseconds(100));
        
        return encoded_data;
    }
    
    virtual double getEncodingLatency() const {
        return 0.1; // 100 microseconds
    }
    
    virtual size_t getEncodedSize(const std::vector<float>& audio_data) const {
        return audio_data.size() * sizeof(float);
    }
};

class MockNetworkTransmitter {
public:
    MockNetworkTransmitter() = default;
    
    virtual ~MockNetworkTransmitter() = default;
    
    // Network transmission methods
    virtual bool transmitPacket(const std::vector<uint8_t>& packet_data) {
        (void)packet_data; // Suppress unused parameter warning
        auto start_time = std::chrono::high_resolution_clock::now();
        
        // Simulate network transmission
        std::this_thread::sleep_for(std::chrono::microseconds(50));
        
        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
        
        return true;
    }
    
    virtual double getTransmissionLatency() const {
        return 0.05; // 50 microseconds
    }
    
    virtual size_t getMaxPacketSize() const {
        return 1500; // Ethernet MTU
    }
};

class MockPropagationCalculator {
public:
    MockPropagationCalculator() = default;
    
    virtual ~MockPropagationCalculator() = default;
    
    // Propagation calculation methods
    virtual double calculatePropagation(double distance, double frequency, double altitude1, double altitude2) {
        (void)altitude1; (void)altitude2; // Suppress unused parameter warnings
        auto start_time = std::chrono::high_resolution_clock::now();
        
        // Simulate propagation calculation
        double result = distance * frequency / 1000.0;
        
        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
        
        return result;
    }
    
    virtual double getCalculationLatency() const {
        return 0.01; // 10 microseconds
    }
};

class MockJitterBuffer {
public:
    MockJitterBuffer() = default;
    
    virtual ~MockJitterBuffer() = default;
    
    // Jitter buffer methods
    virtual void addPacket(const std::vector<uint8_t>& packet_data, uint64_t timestamp) {
        packets.push_back({packet_data, timestamp});
    }
    
    virtual std::vector<uint8_t> getPacket() {
        if (packets.empty()) {
            return {};
        }
        
        auto packet = packets.front();
        packets.pop_front();
        return packet.first;
    }
    
    virtual size_t getBufferSize() const {
        return packets.size();
    }
    
    virtual double getJitter() const {
        return 0.5; // 0.5ms jitter
    }
    
    virtual void reset() {
        packets.clear();
    }
    
private:
    std::deque<std::pair<std::vector<uint8_t>, uint64_t>> packets;
};

class MockThroughputMeter {
public:
    MockThroughputMeter() = default;
    
    virtual ~MockThroughputMeter() = default;
    
    // Throughput measurement methods
    virtual void recordData(size_t bytes) {
        total_bytes += bytes;
        measurement_count++;
    }
    
    virtual double getThroughput() const {
        return static_cast<double>(total_bytes) / measurement_count;
    }
    
    virtual void reset() {
        total_bytes = 0;
        measurement_count = 0;
    }
    
private:
    size_t total_bytes = 0;
    size_t measurement_count = 0;
};

// Helper functions
inline std::vector<float> generateTestAudio(int samples) {
    std::vector<float> audio_data;
    audio_data.reserve(samples);
    
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_real_distribution<float> dis(-1.0f, 1.0f);
    
    for (int i = 0; i < samples; ++i) {
        audio_data.push_back(dis(gen));
    }
    
    return audio_data;
}

inline std::vector<uint8_t> generateTestPacket(int size) {
    std::vector<uint8_t> packet_data;
    packet_data.reserve(size);
    
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint8_t> dis(0, 255);
    
    for (int i = 0; i < size; ++i) {
        packet_data.push_back(dis(gen));
    }
    
    return packet_data;
}

// Test fixture classes
class PerformanceTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize test parameters
        test_audio_data = generateTestAudio(1024);
        test_packet_data = generateTestPacket(1024);
        test_frequencies = {121.5, 243.0, 118.0, 137.0, 144.0};
        test_distances = {1000.0, 5000.0, 10000.0, 50000.0, 100000.0};
        test_altitudes = {1000.0, 5000.0, 10000.0, 20000.0, 40000.0};
        
        // Initialize mock objects
        mock_audio_encoder = std::make_unique<MockAudioEncoder>();
        mock_network_transmitter = std::make_unique<MockNetworkTransmitter>();
        mock_propagation_calculator = std::make_unique<MockPropagationCalculator>();
        mock_jitter_buffer = std::make_unique<MockJitterBuffer>();
        mock_throughput_meter = std::make_unique<MockThroughputMeter>();
    }
    
    void TearDown() override {
        // Clean up mock objects
        mock_audio_encoder.reset();
        mock_network_transmitter.reset();
        mock_propagation_calculator.reset();
        mock_jitter_buffer.reset();
        mock_throughput_meter.reset();
    }
    
    // Test parameters
    std::vector<float> test_audio_data;
    std::vector<uint8_t> test_packet_data;
    std::vector<double> test_frequencies;
    std::vector<double> test_distances;
    std::vector<double> test_altitudes;
    
    // Mock objects
    std::unique_ptr<MockAudioEncoder> mock_audio_encoder;
    std::unique_ptr<MockNetworkTransmitter> mock_network_transmitter;
    std::unique_ptr<MockPropagationCalculator> mock_propagation_calculator;
    std::unique_ptr<MockJitterBuffer> mock_jitter_buffer;
    std::unique_ptr<MockThroughputMeter> mock_throughput_meter;
};

class LatencyTest : public PerformanceTest {
protected:
    void SetUp() override {
        PerformanceTest::SetUp();
    }
};

class ThroughputTest : public PerformanceTest {
protected:
    void SetUp() override {
        PerformanceTest::SetUp();
    }
};

#endif // PERFORMANCE_TEST_COMMON_H
