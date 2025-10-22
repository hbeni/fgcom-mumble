#include "performance_test_common.h"

// Test suite for latency tests
TEST_F(LatencyTest, AudioEncodingLatency) {
    // Test audio encoding latency
    std::vector<float> audio_data = generateTestAudio(1024);
    
    auto start_time = std::chrono::high_resolution_clock::now();
    std::vector<uint8_t> encoded_data = mock_audio_encoder->encodeAudio(audio_data);
    auto end_time = std::chrono::high_resolution_clock::now();
    
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    // Audio encoding should be reasonably fast
    EXPECT_LT(duration.count(), 1000) << "Audio encoding too slow: " << duration.count() << " microseconds";
    
    // Encoded data should not be empty
    EXPECT_FALSE(encoded_data.empty()) << "Encoded data should not be empty";
    
    // Encoded data size should be reasonable
    EXPECT_GT(encoded_data.size(), 0) << "Encoded data size should be greater than 0";
}

TEST_F(LatencyTest, NetworkTransmissionLatency) {
    // Test network transmission latency
    std::vector<uint8_t> packet_data = generateTestPacket(1024);
    
    auto start_time = std::chrono::high_resolution_clock::now();
    bool transmitted = mock_network_transmitter->transmitPacket(packet_data);
    auto end_time = std::chrono::high_resolution_clock::now();
    
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    // Network transmission should succeed
    EXPECT_TRUE(transmitted) << "Network transmission should succeed";
    
    // Network transmission should be reasonably fast
    EXPECT_LT(duration.count(), 1000) << "Network transmission too slow: " << duration.count() << " microseconds";
}

TEST_F(LatencyTest, PropagationCalculationLatency) {
    // Test propagation calculation latency
    double distance = 10000.0;
    double frequency = 121.5;
    double altitude1 = 1000.0;
    double altitude2 = 2000.0;
    
    auto start_time = std::chrono::high_resolution_clock::now();
    double propagation = mock_propagation_calculator->calculatePropagation(distance, frequency, altitude1, altitude2);
    auto end_time = std::chrono::high_resolution_clock::now();
    
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    // Propagation calculation should be reasonably fast
    EXPECT_LT(duration.count(), 1000) << "Propagation calculation too slow: " << duration.count() << " microseconds";
    
    // Propagation result should be reasonable
    EXPECT_GT(propagation, 0.0) << "Propagation result should be positive";
    
    // Test with different distances
    for (double dist : test_distances) {
        auto start = std::chrono::high_resolution_clock::now();
        double result = mock_propagation_calculator->calculatePropagation(dist, frequency, altitude1, altitude2);
        auto end = std::chrono::high_resolution_clock::now();
        
        auto calc_duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        EXPECT_LT(calc_duration.count(), 1000) << "Propagation calculation too slow for distance " << dist;
        EXPECT_GT(result, 0.0) << "Propagation result should be positive for distance " << dist;
    }
    
    // Test with different frequencies
    for (double freq : test_frequencies) {
        auto start = std::chrono::high_resolution_clock::now();
        double result = mock_propagation_calculator->calculatePropagation(distance, freq, altitude1, altitude2);
        auto end = std::chrono::high_resolution_clock::now();
        
        auto calc_duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        EXPECT_LT(calc_duration.count(), 1000) << "Propagation calculation too slow for frequency " << freq;
        EXPECT_GT(result, 0.0) << "Propagation result should be positive for frequency " << freq;
    }
    
    // Test with different altitudes
    for (double alt1 : test_altitudes) {
        auto start = std::chrono::high_resolution_clock::now();
        double result = mock_propagation_calculator->calculatePropagation(distance, frequency, alt1, altitude2);
        auto end = std::chrono::high_resolution_clock::now();
        
        auto calc_duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        EXPECT_LT(calc_duration.count(), 1000) << "Propagation calculation too slow for altitude " << alt1;
        EXPECT_GT(result, 0.0) << "Propagation result should be positive for altitude " << alt1;
    }
}

TEST_F(LatencyTest, TotalEndToEndLatency) {
    // Test total end-to-end latency
    std::vector<float> audio_data = generateTestAudio(1024);
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    // Audio encoding
    std::vector<uint8_t> encoded_data = mock_audio_encoder->encodeAudio(audio_data);
    EXPECT_FALSE(encoded_data.empty()) << "Encoded data should not be empty";
    
    // Network transmission
    bool transmitted = mock_network_transmitter->transmitPacket(encoded_data);
    EXPECT_TRUE(transmitted) << "Network transmission should succeed";
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    // Total end-to-end latency should be reasonable
    EXPECT_LT(duration.count(), 2000) << "Total end-to-end latency too slow: " << duration.count() << " microseconds";
}

TEST_F(LatencyTest, JitterMeasurement) {
    // Test jitter measurement
    const int num_packets = 100;
    std::vector<uint64_t> timestamps;
    
    for (int i = 0; i < num_packets; ++i) {
        std::vector<uint8_t> packet_data = generateTestPacket(1024);
        uint64_t timestamp = i * 1000; // 1ms intervals
        mock_jitter_buffer->addPacket(packet_data, timestamp);
        timestamps.push_back(timestamp);
    }
    
    // Jitter buffer should contain packets
    EXPECT_EQ(mock_jitter_buffer->getBufferSize(), num_packets) << "Jitter buffer should contain all packets";
    
    // Test jitter measurement
    double jitter = mock_jitter_buffer->getJitter();
    EXPECT_GE(jitter, 0.0) << "Jitter should be non-negative";
    
    // Test with different packet sizes
    std::vector<int> packet_sizes = {512, 1024, 2048, 4096};
    for (int size : packet_sizes) {
        mock_jitter_buffer->reset();
        
        for (int i = 0; i < 10; ++i) {
            std::vector<uint8_t> packet_data = generateTestPacket(size);
            mock_jitter_buffer->addPacket(packet_data, i * 1000);
        }
        
        EXPECT_EQ(mock_jitter_buffer->getBufferSize(), 10) << "Jitter buffer should contain 10 packets for size " << size;
    }
}

TEST_F(LatencyTest, LatencyPerformance) {
    // Test latency performance under load
    const int num_iterations = 1000;
    std::vector<double> latencies;
    
    for (int i = 0; i < num_iterations; ++i) {
        std::vector<float> audio_data = generateTestAudio(1024);
        
        auto start = std::chrono::high_resolution_clock::now();
        std::vector<uint8_t> encoded_data = mock_audio_encoder->encodeAudio(audio_data);
        bool transmitted = mock_network_transmitter->transmitPacket(encoded_data);
        auto end = std::chrono::high_resolution_clock::now();
        
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        latencies.push_back(duration.count());
        
        EXPECT_TRUE(transmitted) << "Transmission should succeed in iteration " << i;
    }
    
    // Calculate statistics
    double total_latency = std::accumulate(latencies.begin(), latencies.end(), 0.0);
    double average_latency = total_latency / num_iterations;
    
    // Average latency should be reasonable
    EXPECT_LT(average_latency, 1000.0) << "Average latency too high: " << average_latency << " microseconds";
    
    // Test propagation calculation performance
    double distance = 10000.0;
    double frequency = 121.5;
    double altitude1 = 1000.0;
    double altitude2 = 2000.0;
    
    for (int i = 0; i < 100; ++i) {
        auto start = std::chrono::high_resolution_clock::now();
        double propagation = mock_propagation_calculator->calculatePropagation(distance, frequency, altitude1, altitude2);
        auto end = std::chrono::high_resolution_clock::now();
        
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        EXPECT_LT(duration.count(), 1000) << "Propagation calculation too slow in iteration " << i;
        EXPECT_GT(propagation, 0.0) << "Propagation result should be positive in iteration " << i;
    }
}

TEST_F(LatencyTest, LatencyAccuracy) {
    // Test latency accuracy
    std::vector<float> audio_data = generateTestAudio(1024);
    
    // Test audio encoding accuracy
    std::vector<uint8_t> encoded_data = mock_audio_encoder->encodeAudio(audio_data);
    EXPECT_FALSE(encoded_data.empty()) << "Encoded data should not be empty";
    EXPECT_GT(encoded_data.size(), 0) << "Encoded data size should be greater than 0";
    
    // Test network transmission accuracy
    bool transmitted = mock_network_transmitter->transmitPacket(encoded_data);
    EXPECT_TRUE(transmitted) << "Network transmission should succeed";
    
    // Test propagation calculation accuracy
    double distance = 10000.0;
    double frequency = 121.5;
    double altitude1 = 1000.0;
    double altitude2 = 2000.0;
    
    double propagation = mock_propagation_calculator->calculatePropagation(distance, frequency, altitude1, altitude2);
    EXPECT_GT(propagation, 0.0) << "Propagation result should be positive";
    
    // Test jitter buffer accuracy
    std::vector<uint8_t> packet_data = generateTestPacket(1024);
    mock_jitter_buffer->addPacket(packet_data, 1000);
    EXPECT_EQ(mock_jitter_buffer->getBufferSize(), 1) << "Jitter buffer should contain 1 packet";
    
    std::vector<uint8_t> retrieved_packet = mock_jitter_buffer->getPacket();
    EXPECT_FALSE(retrieved_packet.empty()) << "Retrieved packet should not be empty";
    EXPECT_EQ(retrieved_packet.size(), packet_data.size()) << "Retrieved packet size should match original";
}
