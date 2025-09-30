#include "test_performance_main.cpp"

// 15.1 Latency Tests
TEST_F(LatencyTest, AudioEncodingLatency) {
    // Test audio encoding latency
    std::vector<float> audio_data = generateTestAudio(1024);
    
    auto start_time = std::chrono::high_resolution_clock::now();
    std::vector<uint8_t> encoded_data = mock_audio_encoder->encodeAudio(audio_data);
    auto end_time = std::chrono::high_resolution_clock::now();
    
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    double latency_ms = duration.count() / 1000.0;
    
    EXPECT_GT(encoded_data.size(), 0) << "Encoded audio data should not be empty";
    EXPECT_LT(latency_ms, 10.0) << "Audio encoding latency should be less than 10ms";
    
    // Test encoding latency with different audio sizes
    std::vector<int> audio_sizes = {512, 1024, 2048, 4096, 8192};
    for (int size : audio_sizes) {
        std::vector<float> test_audio = generateTestAudio(size);
        
        auto start_time = std::chrono::high_resolution_clock::now();
        std::vector<uint8_t> encoded = mock_audio_encoder->encodeAudio(test_audio);
        auto end_time = std::chrono::high_resolution_clock::now();
        
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
        double latency_ms = duration.count() / 1000.0;
        
        EXPECT_GT(encoded.size(), 0) << "Encoded audio data should not be empty for size " << size;
        EXPECT_LT(latency_ms, 20.0) << "Audio encoding latency should be less than 20ms for size " << size;
    }
    
    // Test encoding latency with different frequencies
    std::vector<double> test_frequencies = {440.0, 880.0, 1760.0, 3520.0, 7040.0};
    for (double freq : test_frequencies) {
        std::vector<float> test_audio;
        for (int i = 0; i < 1024; ++i) {
            test_audio.push_back(static_cast<float>(sin(2 * M_PI * freq * i / 44100.0)));
        }
        
        auto start_time = std::chrono::high_resolution_clock::now();
        std::vector<uint8_t> encoded = mock_audio_encoder->encodeAudio(test_audio);
        auto end_time = std::chrono::high_resolution_clock::now();
        
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
        double latency_ms = duration.count() / 1000.0;
        
        EXPECT_GT(encoded.size(), 0) << "Encoded audio data should not be empty for frequency " << freq;
        EXPECT_LT(latency_ms, 15.0) << "Audio encoding latency should be less than 15ms for frequency " << freq;
    }
}

TEST_F(LatencyTest, NetworkTransmissionLatency) {
    // Test network transmission latency
    std::vector<uint8_t> packet_data = generateTestPacket(1024);
    
    auto start_time = std::chrono::high_resolution_clock::now();
    bool transmitted = mock_network_transmitter->transmitPacket(packet_data);
    auto end_time = std::chrono::high_resolution_clock::now();
    
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    double latency_ms = duration.count() / 1000.0;
    
    EXPECT_TRUE(transmitted) << "Packet transmission should succeed";
    EXPECT_LT(latency_ms, 5.0) << "Network transmission latency should be less than 5ms";
    
    // Test transmission latency with different packet sizes
    std::vector<int> packet_sizes = {512, 1024, 2048, 4096, 8192};
    for (int size : packet_sizes) {
        std::vector<uint8_t> test_packet = generateTestPacket(size);
        
        auto start_time = std::chrono::high_resolution_clock::now();
        bool transmitted = mock_network_transmitter->transmitPacket(test_packet);
        auto end_time = std::chrono::high_resolution_clock::now();
        
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
        double latency_ms = duration.count() / 1000.0;
        
        EXPECT_TRUE(transmitted) << "Packet transmission should succeed for size " << size;
        EXPECT_LT(latency_ms, 10.0) << "Network transmission latency should be less than 10ms for size " << size;
    }
    
    // Test transmission latency with multiple packets
    const int num_packets = 100;
    auto start_time = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < num_packets; ++i) {
        std::vector<uint8_t> test_packet = generateTestPacket(1024);
        bool transmitted = mock_network_transmitter->transmitPacket(test_packet);
        EXPECT_TRUE(transmitted) << "Packet transmission should succeed for packet " << i;
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    double total_latency_ms = duration.count() / 1000.0;
    double avg_latency_ms = total_latency_ms / num_packets;
    
    EXPECT_LT(avg_latency_ms, 5.0) << "Average network transmission latency should be less than 5ms";
    
    // Test packet count
    int packets_transmitted = mock_network_transmitter->getPacketsTransmitted();
    EXPECT_EQ(packets_transmitted, num_packets) << "Should have transmitted " << num_packets << " packets";
}

TEST_F(LatencyTest, PropagationCalculationLatency) {
    // Test propagation calculation latency
    double distance = 10000.0;
    double frequency = 144.0;
    double altitude1 = 1000.0;
    double altitude2 = 2000.0;
    
    auto start_time = std::chrono::high_resolution_clock::now();
    double propagation = mock_propagation_calculator->calculatePropagation(distance, frequency, altitude1, altitude2);
    auto end_time = std::chrono::high_resolution_clock::now();
    
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    double latency_ms = duration.count() / 1000.0;
    
    EXPECT_GE(propagation, 0.0) << "Propagation should be non-negative";
    EXPECT_LT(latency_ms, 1.0) << "Propagation calculation latency should be less than 1ms";
    
    // Test propagation calculation latency with different distances
    for (double dist : test_distances) {
        auto start_time = std::chrono::high_resolution_clock::now();
        double propagation = mock_propagation_calculator->calculatePropagation(dist, frequency, altitude1, altitude2);
        auto end_time = std::chrono::high_resolution_clock::now();
        
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
        double latency_ms = duration.count() / 1000.0;
        
        EXPECT_GE(propagation, 0.0) << "Propagation should be non-negative for distance " << dist;
        EXPECT_LT(latency_ms, 2.0) << "Propagation calculation latency should be less than 2ms for distance " << dist;
    }
    
    // Test propagation calculation latency with different frequencies
    for (double freq : test_frequencies) {
        auto start_time = std::chrono::high_resolution_clock::now();
        double propagation = mock_propagation_calculator->calculatePropagation(distance, freq, altitude1, altitude2);
        auto end_time = std::chrono::high_resolution_clock::now();
        
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
        double latency_ms = duration.count() / 1000.0;
        
        EXPECT_GE(propagation, 0.0) << "Propagation should be non-negative for frequency " << freq;
        EXPECT_LT(latency_ms, 2.0) << "Propagation calculation latency should be less than 2ms for frequency " << freq;
    }
    
    // Test propagation calculation latency with different altitudes
    for (double alt1 : test_altitudes) {
        for (double alt2 : test_altitudes) {
            auto start_time = std::chrono::high_resolution_clock::now();
            double propagation = mock_propagation_calculator->calculatePropagation(distance, frequency, alt1, alt2);
            auto end_time = std::chrono::high_resolution_clock::now();
            
            auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
            double latency_ms = duration.count() / 1000.0;
            
            EXPECT_GE(propagation, 0.0) << "Propagation should be non-negative for altitudes " << alt1 << ", " << alt2;
            EXPECT_LT(latency_ms, 3.0) << "Propagation calculation latency should be less than 3ms for altitudes " << alt1 << ", " << alt2;
        }
    }
}

TEST_F(LatencyTest, TotalEndToEndLatency) {
    // Test total end-to-end latency
    std::vector<float> audio_data = generateTestAudio(1024);
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    // Audio encoding
    std::vector<uint8_t> encoded_data = mock_audio_encoder->encodeAudio(audio_data);
    
    // Network transmission
    bool transmitted = mock_network_transmitter->transmitPacket(encoded_data);
    
    // Network reception
    std::vector<uint8_t> received_data = mock_network_transmitter->receivePacket();
    
    // Audio decoding
    std::vector<float> decoded_data = mock_audio_encoder->decodeAudio(received_data);
    
    auto end_time = std::chrono::high_resolution_clock::now();
    
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    double total_latency_ms = duration.count() / 1000.0;
    
    EXPECT_GT(encoded_data.size(), 0) << "Encoded audio data should not be empty";
    EXPECT_TRUE(transmitted) << "Packet transmission should succeed";
    EXPECT_GT(received_data.size(), 0) << "Received data should not be empty";
    EXPECT_GT(decoded_data.size(), 0) << "Decoded audio data should not be empty";
    EXPECT_LT(total_latency_ms, 50.0) << "Total end-to-end latency should be less than 50ms";
    
    // Test end-to-end latency with different audio sizes
    std::vector<int> audio_sizes = {512, 1024, 2048, 4096};
    for (int size : audio_sizes) {
        std::vector<float> test_audio = generateTestAudio(size);
        
        auto start_time = std::chrono::high_resolution_clock::now();
        
        std::vector<uint8_t> encoded = mock_audio_encoder->encodeAudio(test_audio);
        bool transmitted = mock_network_transmitter->transmitPacket(encoded);
        std::vector<uint8_t> received = mock_network_transmitter->receivePacket();
        std::vector<float> decoded = mock_audio_encoder->decodeAudio(received);
        
        auto end_time = std::chrono::high_resolution_clock::now();
        
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
        double total_latency_ms = duration.count() / 1000.0;
        
        EXPECT_GT(encoded.size(), 0) << "Encoded audio data should not be empty for size " << size;
        EXPECT_TRUE(transmitted) << "Packet transmission should succeed for size " << size;
        EXPECT_GT(received.size(), 0) << "Received data should not be empty for size " << size;
        EXPECT_GT(decoded.size(), 0) << "Decoded audio data should not be empty for size " << size;
        EXPECT_LT(total_latency_ms, 100.0) << "Total end-to-end latency should be less than 100ms for size " << size;
    }
}

TEST_F(LatencyTest, JitterMeasurement) {
    // Test jitter measurement
    const int num_packets = 100;
    std::vector<double> latencies;
    
    for (int i = 0; i < num_packets; ++i) {
        std::vector<uint8_t> packet_data = generateTestPacket(1024);
        
        auto start_time = std::chrono::high_resolution_clock::now();
        mock_jitter_buffer->addPacket(packet_data, i * 1000); // 1ms intervals
        auto end_time = std::chrono::high_resolution_clock::now();
        
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
        double latency_ms = duration.count() / 1000.0;
        latencies.push_back(latency_ms);
    }
    
    // Calculate jitter statistics
    double min_latency = *std::min_element(latencies.begin(), latencies.end());
    double max_latency = *std::max_element(latencies.begin(), latencies.end());
    double avg_latency = std::accumulate(latencies.begin(), latencies.end(), 0.0) / latencies.size();
    
    // Calculate jitter (standard deviation)
    double variance = 0.0;
    for (double latency : latencies) {
        variance += pow(latency - avg_latency, 2);
    }
    double jitter = sqrt(variance / latencies.size());
    
    EXPECT_GT(min_latency, 0.0) << "Minimum latency should be positive";
    EXPECT_LT(max_latency, 10.0) << "Maximum latency should be less than 10ms";
    EXPECT_LT(avg_latency, 5.0) << "Average latency should be less than 5ms";
    EXPECT_LT(jitter, 2.0) << "Jitter should be less than 2ms";
    
    // Test jitter with different packet sizes
    std::vector<int> packet_sizes = {512, 1024, 2048, 4096};
    for (int size : packet_sizes) {
        std::vector<double> size_latencies;
        
        for (int i = 0; i < 50; ++i) {
            std::vector<uint8_t> packet_data = generateTestPacket(size);
            
            auto start_time = std::chrono::high_resolution_clock::now();
            mock_jitter_buffer->addPacket(packet_data, i * 1000);
            auto end_time = std::chrono::high_resolution_clock::now();
            
            auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
            double latency_ms = duration.count() / 1000.0;
            size_latencies.push_back(latency_ms);
        }
        
        double size_avg_latency = std::accumulate(size_latencies.begin(), size_latencies.end(), 0.0) / size_latencies.size();
        EXPECT_LT(size_avg_latency, 10.0) << "Average latency should be less than 10ms for size " << size;
    }
}

// Additional latency tests
TEST_F(LatencyTest, LatencyPerformance) {
    // Test latency performance
    const int num_operations = 1000;
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    // Test latency operations
    for (int i = 0; i < num_operations; ++i) {
        std::vector<float> audio_data = generateTestAudio(1024);
        std::vector<uint8_t> encoded_data = mock_audio_encoder->encodeAudio(audio_data);
        bool transmitted = mock_network_transmitter->transmitPacket(encoded_data);
        std::vector<uint8_t> received_data = mock_network_transmitter->receivePacket();
        std::vector<float> decoded_data = mock_audio_encoder->decodeAudio(received_data);
        
        double distance = 10000.0 + i * 100.0;
        double frequency = 144.0 + i * 0.1;
        double altitude1 = 1000.0 + i * 10.0;
        double altitude2 = 2000.0 + i * 20.0;
        double propagation = mock_propagation_calculator->calculatePropagation(distance, frequency, altitude1, altitude2);
        
        EXPECT_GT(encoded_data.size(), 0) << "Encoded audio data should not be empty";
        EXPECT_TRUE(transmitted) << "Packet transmission should succeed";
        EXPECT_GT(received_data.size(), 0) << "Received data should not be empty";
        EXPECT_GT(decoded_data.size(), 0) << "Decoded audio data should not be empty";
        EXPECT_GE(propagation, 0.0) << "Propagation should be non-negative";
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    // Calculate performance metrics
    double time_per_operation = static_cast<double>(duration.count()) / num_operations;
    
    // Latency operations should be fast
    EXPECT_LT(time_per_operation, 1000.0) << "Latency operations too slow: " << time_per_operation << " microseconds";
    
    std::cout << "Latency performance: " << time_per_operation << " microseconds per operation" << std::endl;
}

TEST_F(LatencyTest, LatencyAccuracy) {
    // Test latency accuracy
    std::vector<float> audio_data = generateTestAudio(1024);
    
    // Test audio encoding accuracy
    std::vector<uint8_t> encoded_data = mock_audio_encoder->encodeAudio(audio_data);
    EXPECT_GT(encoded_data.size(), 0) << "Audio encoding should be accurate";
    
    // Test network transmission accuracy
    bool transmitted = mock_network_transmitter->transmitPacket(encoded_data);
    EXPECT_TRUE(transmitted) << "Network transmission should be accurate";
    
    // Test network reception accuracy
    std::vector<uint8_t> received_data = mock_network_transmitter->receivePacket();
    EXPECT_GT(received_data.size(), 0) << "Network reception should be accurate";
    
    // Test audio decoding accuracy
    std::vector<float> decoded_data = mock_audio_encoder->decodeAudio(received_data);
    EXPECT_GT(decoded_data.size(), 0) << "Audio decoding should be accurate";
    
    // Test propagation calculation accuracy
    double distance = 10000.0;
    double frequency = 144.0;
    double altitude1 = 1000.0;
    double altitude2 = 2000.0;
    double propagation = mock_propagation_calculator->calculatePropagation(distance, frequency, altitude1, altitude2);
    EXPECT_GE(propagation, 0.0) << "Propagation calculation should be accurate";
    
    // Test jitter buffer accuracy
    std::vector<uint8_t> packet_data = generateTestPacket(1024);
    mock_jitter_buffer->addPacket(packet_data, 1000);
    std::vector<uint8_t> retrieved_data = mock_jitter_buffer->getNextPacket();
    EXPECT_GT(retrieved_data.size(), 0) << "Jitter buffer should be accurate";
    
    // Test latency measurement accuracy
    double encoding_latency = mock_audio_encoder->getEncodingLatency();
    EXPECT_GE(encoding_latency, 0.0) << "Encoding latency should be accurate";
    
    double transmission_latency = mock_network_transmitter->getTransmissionLatency();
    EXPECT_GE(transmission_latency, 0.0) << "Transmission latency should be accurate";
    
    double calculation_latency = mock_propagation_calculator->getCalculationLatency();
    EXPECT_GE(calculation_latency, 0.0) << "Calculation latency should be accurate";
    
    double buffer_latency = mock_jitter_buffer->getBufferLatency();
    EXPECT_GE(buffer_latency, 0.0) << "Buffer latency should be accurate";
}

