#include "performance_test_common.h"

// Test suite for throughput tests
TEST_F(ThroughputTest, AudioEncodingThroughput) {
    // Test audio encoding throughput
    const int num_samples = 1024;
    const int num_iterations = 100;
    
    std::vector<float> audio_data = generateTestAudio(num_samples);
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < num_iterations; ++i) {
        std::vector<uint8_t> encoded_data = mock_audio_encoder->encodeAudio(audio_data);
        EXPECT_FALSE(encoded_data.empty()) << "Encoded data should not be empty";
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    // Calculate throughput
    double total_data = num_samples * num_iterations * sizeof(float);
    double throughput = total_data / (duration.count() / 1000000.0); // bytes per second
    
    // Throughput should be reasonable
    EXPECT_GT(throughput, 1000000.0) << "Audio encoding throughput too low: " << throughput << " bytes/second";
}

TEST_F(ThroughputTest, NetworkTransmissionThroughput) {
    // Test network transmission throughput
    const int packet_size = 1024;
    const int num_packets = 1000;
    
    std::vector<uint8_t> packet_data = generateTestPacket(packet_size);
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < num_packets; ++i) {
        bool transmitted = mock_network_transmitter->transmitPacket(packet_data);
        EXPECT_TRUE(transmitted) << "Network transmission should succeed";
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    // Calculate throughput
    double total_data = packet_size * num_packets;
    double throughput = total_data / (duration.count() / 1000000.0); // bytes per second
    
    // Throughput should be reasonable
    EXPECT_GT(throughput, 1000000.0) << "Network transmission throughput too low: " << throughput << " bytes/second";
}

TEST_F(ThroughputTest, PropagationCalculationThroughput) {
    // Test propagation calculation throughput
    const int num_calculations = 10000;
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < num_calculations; ++i) {
        double distance = 1000.0 + (i % 10000) * 10.0;
        double frequency = 121.5 + (i % 100) * 0.1;
        double altitude1 = 1000.0 + (i % 1000) * 10.0;
        double altitude2 = 2000.0 + (i % 1000) * 10.0;
        
        double propagation = mock_propagation_calculator->calculatePropagation(distance, frequency, altitude1, altitude2);
        EXPECT_GT(propagation, 0.0) << "Propagation result should be positive";
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    // Calculate throughput (calculations per second)
    double throughput = num_calculations / (duration.count() / 1000000.0);
    
    // Throughput should be reasonable
    EXPECT_GT(throughput, 1000.0) << "Propagation calculation throughput too low: " << throughput << " calculations/second";
}

TEST_F(ThroughputTest, JitterBufferThroughput) {
    // Test jitter buffer throughput
    const int num_packets = 1000;
    const int packet_size = 1024;
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    // Add packets to buffer
    for (int i = 0; i < num_packets; ++i) {
        std::vector<uint8_t> packet_data = generateTestPacket(packet_size);
        mock_jitter_buffer->addPacket(packet_data, i * 1000);
    }
    
    // Retrieve packets from buffer
    for (int i = 0; i < num_packets; ++i) {
        std::vector<uint8_t> retrieved_packet = mock_jitter_buffer->getPacket();
        EXPECT_FALSE(retrieved_packet.empty()) << "Retrieved packet should not be empty";
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    // Calculate throughput
    double total_data = packet_size * num_packets;
    double throughput = total_data / (duration.count() / 1000000.0); // bytes per second
    
    // Throughput should be reasonable
    EXPECT_GT(throughput, 1000000.0) << "Jitter buffer throughput too low: " << throughput << " bytes/second";
}

TEST_F(ThroughputTest, EndToEndThroughput) {
    // Test end-to-end throughput
    const int num_iterations = 100;
    const int audio_samples = 1024;
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < num_iterations; ++i) {
        // Generate audio data
        std::vector<float> audio_data = generateTestAudio(audio_samples);
        
        // Encode audio
        std::vector<uint8_t> encoded_data = mock_audio_encoder->encodeAudio(audio_data);
        EXPECT_FALSE(encoded_data.empty()) << "Encoded data should not be empty";
        
        // Transmit over network
        bool transmitted = mock_network_transmitter->transmitPacket(encoded_data);
        EXPECT_TRUE(transmitted) << "Network transmission should succeed";
        
        // Add to jitter buffer
        mock_jitter_buffer->addPacket(encoded_data, i * 1000);
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    // Calculate throughput
    double total_data = audio_samples * num_iterations * sizeof(float);
    double throughput = total_data / (duration.count() / 1000000.0); // bytes per second
    
    // Throughput should be reasonable
    EXPECT_GT(throughput, 100000.0) << "End-to-end throughput too low: " << throughput << " bytes/second";
}

TEST_F(ThroughputTest, ThroughputPerformance) {
    // Test throughput performance under load
    const int num_iterations = 1000;
    std::vector<double> throughputs;
    
    for (int iteration = 0; iteration < 10; ++iteration) {
        auto start_time = std::chrono::high_resolution_clock::now();
        
        for (int i = 0; i < num_iterations; ++i) {
            std::vector<float> audio_data = generateTestAudio(1024);
            std::vector<uint8_t> encoded_data = mock_audio_encoder->encodeAudio(audio_data);
            bool transmitted = mock_network_transmitter->transmitPacket(encoded_data);
            EXPECT_TRUE(transmitted) << "Transmission should succeed";
        }
        
        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
        
        double throughput = num_iterations / (duration.count() / 1000000.0);
        throughputs.push_back(throughput);
    }
    
    // Calculate average throughput
    double total_throughput = std::accumulate(throughputs.begin(), throughputs.end(), 0.0);
    double average_throughput = total_throughput / throughputs.size();
    
    // Average throughput should be reasonable
    EXPECT_GT(average_throughput, 100.0) << "Average throughput too low: " << average_throughput << " operations/second";
}

TEST_F(ThroughputTest, ThroughputAccuracy) {
    // Test throughput accuracy
    const int num_samples = 1024;
    const int num_iterations = 100;
    
    std::vector<float> audio_data = generateTestAudio(num_samples);
    
    // Test audio encoding accuracy
    for (int i = 0; i < num_iterations; ++i) {
        std::vector<uint8_t> encoded_data = mock_audio_encoder->encodeAudio(audio_data);
        EXPECT_FALSE(encoded_data.empty()) << "Encoded data should not be empty";
        EXPECT_GT(encoded_data.size(), 0) << "Encoded data size should be greater than 0";
    }
    
    // Test network transmission accuracy
    std::vector<uint8_t> packet_data = generateTestPacket(1024);
    for (int i = 0; i < num_iterations; ++i) {
        bool transmitted = mock_network_transmitter->transmitPacket(packet_data);
        EXPECT_TRUE(transmitted) << "Network transmission should succeed";
    }
    
    // Test jitter buffer accuracy
    for (int i = 0; i < num_iterations; ++i) {
        std::vector<uint8_t> test_packet = generateTestPacket(1024);
        mock_jitter_buffer->addPacket(test_packet, i * 1000);
    }
    
    EXPECT_EQ(mock_jitter_buffer->getBufferSize(), num_iterations) << "Jitter buffer should contain all packets";
    
    // Test throughput meter accuracy
    for (int i = 0; i < num_iterations; ++i) {
        mock_throughput_meter->recordData(1024);
    }
    
    double throughput = mock_throughput_meter->getThroughput();
    EXPECT_GT(throughput, 0.0) << "Throughput should be positive";
}
