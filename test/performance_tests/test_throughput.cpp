#include "test_performance_main.cpp"

// 15.2 Throughput Tests
TEST_F(ThroughputTest, MaximumSimultaneousTransmissions) {
    // Test maximum simultaneous transmissions
    const int num_transmissions = 100;
    std::vector<std::thread> transmission_threads;
    
    mock_throughput_meter->startMeasurement();
    
    // Test simultaneous transmissions
    for (int i = 0; i < num_transmissions; ++i) {
        transmission_threads.emplace_back([this, i]() {
            std::vector<uint8_t> packet_data = generateTestPacket(1024);
            bool transmitted = mock_network_transmitter->transmitPacket(packet_data);
            EXPECT_TRUE(transmitted) << "Transmission " << i << " should succeed";
            mock_throughput_meter->recordBytes(packet_data.size());
            mock_throughput_meter->recordPacket();
        });
    }
    
    // Wait for all transmissions to complete
    for (auto& thread : transmission_threads) {
        thread.join();
    }
    
    mock_throughput_meter->endMeasurement();
    
    // Test throughput metrics
    double throughput_mbps = mock_throughput_meter->getThroughputMbps();
    double packets_per_second = mock_throughput_meter->getPacketsPerSecond();
    double measurement_duration = mock_throughput_meter->getMeasurementDuration();
    
    EXPECT_GT(throughput_mbps, 0.0) << "Throughput should be positive";
    EXPECT_GT(packets_per_second, 0.0) << "Packets per second should be positive";
    EXPECT_GT(measurement_duration, 0.0) << "Measurement duration should be positive";
    
    // Test with different packet sizes
    std::vector<int> packet_sizes = {512, 1024, 2048, 4096, 8192};
    for (int size : packet_sizes) {
        mock_throughput_meter->startMeasurement();
        
        std::vector<std::thread> size_transmission_threads;
        for (int i = 0; i < 50; ++i) {
            size_transmission_threads.emplace_back([this, size]() {
                std::vector<uint8_t> packet_data = generateTestPacket(size);
                bool transmitted = mock_network_transmitter->transmitPacket(packet_data);
                EXPECT_TRUE(transmitted) << "Transmission should succeed for size " << size;
                mock_throughput_meter->recordBytes(packet_data.size());
                mock_throughput_meter->recordPacket();
            });
        }
        
        for (auto& thread : size_transmission_threads) {
            thread.join();
        }
        
        mock_throughput_meter->endMeasurement();
        
        double size_throughput_mbps = mock_throughput_meter->getThroughputMbps();
        double size_packets_per_second = mock_throughput_meter->getPacketsPerSecond();
        
        EXPECT_GT(size_throughput_mbps, 0.0) << "Throughput should be positive for size " << size;
        EXPECT_GT(size_packets_per_second, 0.0) << "Packets per second should be positive for size " << size;
    }
}

TEST_F(ThroughputTest, PacketsPerSecond) {
    // Test packets per second
    const int num_packets = 1000;
    const int packet_size = 1024;
    
    mock_throughput_meter->startMeasurement();
    
    // Test packet transmission
    for (int i = 0; i < num_packets; ++i) {
        std::vector<uint8_t> packet_data = generateTestPacket(packet_size);
        bool transmitted = mock_network_transmitter->transmitPacket(packet_data);
        EXPECT_TRUE(transmitted) << "Packet transmission should succeed";
        mock_throughput_meter->recordBytes(packet_data.size());
        mock_throughput_meter->recordPacket();
    }
    
    mock_throughput_meter->endMeasurement();
    
    // Test throughput metrics
    double throughput_mbps = mock_throughput_meter->getThroughputMbps();
    double packets_per_second = mock_throughput_meter->getPacketsPerSecond();
    double measurement_duration = mock_throughput_meter->getMeasurementDuration();
    
    EXPECT_GT(throughput_mbps, 0.0) << "Throughput should be positive";
    EXPECT_GT(packets_per_second, 0.0) << "Packets per second should be positive";
    EXPECT_GT(measurement_duration, 0.0) << "Measurement duration should be positive";
    
    // Test with different packet counts
    std::vector<int> packet_counts = {100, 500, 1000, 2000, 5000};
    for (int count : packet_counts) {
        mock_throughput_meter->startMeasurement();
        
        for (int i = 0; i < count; ++i) {
            std::vector<uint8_t> packet_data = generateTestPacket(packet_size);
            bool transmitted = mock_network_transmitter->transmitPacket(packet_data);
            EXPECT_TRUE(transmitted) << "Packet transmission should succeed for count " << count;
            mock_throughput_meter->recordBytes(packet_data.size());
            mock_throughput_meter->recordPacket();
        }
        
        mock_throughput_meter->endMeasurement();
        
        double count_throughput_mbps = mock_throughput_meter->getThroughputMbps();
        double count_packets_per_second = mock_throughput_meter->getPacketsPerSecond();
        
        EXPECT_GT(count_throughput_mbps, 0.0) << "Throughput should be positive for count " << count;
        EXPECT_GT(count_packets_per_second, 0.0) << "Packets per second should be positive for count " << count;
    }
}

TEST_F(ThroughputTest, BandwidthUtilization) {
    // Test bandwidth utilization
    const int num_packets = 1000;
    const int packet_size = 1024;
    
    mock_throughput_meter->startMeasurement();
    
    // Test bandwidth utilization
    for (int i = 0; i < num_packets; ++i) {
        std::vector<uint8_t> packet_data = generateTestPacket(packet_size);
        bool transmitted = mock_network_transmitter->transmitPacket(packet_data);
        EXPECT_TRUE(transmitted) << "Packet transmission should succeed";
        mock_throughput_meter->recordBytes(packet_data.size());
        mock_throughput_meter->recordPacket();
    }
    
    mock_throughput_meter->endMeasurement();
    
    // Test bandwidth utilization metrics
    double throughput_mbps = mock_throughput_meter->getThroughputMbps();
    double packets_per_second = mock_throughput_meter->getPacketsPerSecond();
    double measurement_duration = mock_throughput_meter->getMeasurementDuration();
    
    EXPECT_GT(throughput_mbps, 0.0) << "Throughput should be positive";
    EXPECT_GT(packets_per_second, 0.0) << "Packets per second should be positive";
    EXPECT_GT(measurement_duration, 0.0) << "Measurement duration should be positive";
    
    // Test bandwidth utilization with different packet sizes
    std::vector<int> packet_sizes = {512, 1024, 2048, 4096, 8192};
    for (int size : packet_sizes) {
        mock_throughput_meter->startMeasurement();
        
        for (int i = 0; i < 500; ++i) {
            std::vector<uint8_t> packet_data = generateTestPacket(size);
            bool transmitted = mock_network_transmitter->transmitPacket(packet_data);
            EXPECT_TRUE(transmitted) << "Packet transmission should succeed for size " << size;
            mock_throughput_meter->recordBytes(packet_data.size());
            mock_throughput_meter->recordPacket();
        }
        
        mock_throughput_meter->endMeasurement();
        
        double size_throughput_mbps = mock_throughput_meter->getThroughputMbps();
        double size_packets_per_second = mock_throughput_meter->getPacketsPerSecond();
        
        EXPECT_GT(size_throughput_mbps, 0.0) << "Throughput should be positive for size " << size;
        EXPECT_GT(size_packets_per_second, 0.0) << "Packets per second should be positive for size " << size;
    }
}

TEST_F(ThroughputTest, CPUUtilizationPerClient) {
    // Test CPU utilization per client
    const int num_clients = 100;
    const int num_operations_per_client = 100;
    
    mock_throughput_meter->startMeasurement();
    
    // Test CPU utilization per client
    std::vector<std::thread> client_threads;
    for (int client = 0; client < num_clients; ++client) {
        client_threads.emplace_back([this, num_operations_per_client, client]() {
            for (int op = 0; op < num_operations_per_client; ++op) {
                // Test audio encoding
                std::vector<float> audio_data = generateTestAudio(1024);
                std::vector<uint8_t> encoded_data = mock_audio_encoder->encodeAudio(audio_data);
                
                // Test network transmission
                bool transmitted = mock_network_transmitter->transmitPacket(encoded_data);
                EXPECT_TRUE(transmitted) << "Transmission should succeed for client " << client;
                
                // Test propagation calculation
                double distance = 10000.0 + client * 100.0;
                double frequency = 144.0 + client * 0.1;
                double altitude1 = 1000.0 + client * 10.0;
                double altitude2 = 2000.0 + client * 20.0;
                double propagation = mock_propagation_calculator->calculatePropagation(distance, frequency, altitude1, altitude2);
                
                EXPECT_GT(encoded_data.size(), 0) << "Encoded audio data should not be empty for client " << client;
                EXPECT_GE(propagation, 0.0) << "Propagation should be non-negative for client " << client;
                
                mock_throughput_meter->recordBytes(encoded_data.size());
                mock_throughput_meter->recordPacket();
            }
        });
    }
    
    // Wait for all clients to complete
    for (auto& thread : client_threads) {
        thread.join();
    }
    
    mock_throughput_meter->endMeasurement();
    
    // Test CPU utilization metrics
    double throughput_mbps = mock_throughput_meter->getThroughputMbps();
    double packets_per_second = mock_throughput_meter->getPacketsPerSecond();
    double measurement_duration = mock_throughput_meter->getMeasurementDuration();
    
    EXPECT_GT(throughput_mbps, 0.0) << "Throughput should be positive";
    EXPECT_GT(packets_per_second, 0.0) << "Packets per second should be positive";
    EXPECT_GT(measurement_duration, 0.0) << "Measurement duration should be positive";
    
    // Test CPU utilization with different client counts
    std::vector<int> client_counts = {10, 50, 100, 200, 500};
    for (int count : client_counts) {
        mock_throughput_meter->startMeasurement();
        
        std::vector<std::thread> count_client_threads;
        for (int client = 0; client < count; ++client) {
            count_client_threads.emplace_back([this, client]() {
                for (int op = 0; op < 50; ++op) {
                    std::vector<float> audio_data = generateTestAudio(1024);
                    std::vector<uint8_t> encoded_data = mock_audio_encoder->encodeAudio(audio_data);
                    bool transmitted = mock_network_transmitter->transmitPacket(encoded_data);
                    EXPECT_TRUE(transmitted) << "Transmission should succeed for client " << client;
                    mock_throughput_meter->recordBytes(encoded_data.size());
                    mock_throughput_meter->recordPacket();
                }
            });
        }
        
        for (auto& thread : count_client_threads) {
            thread.join();
        }
        
        mock_throughput_meter->endMeasurement();
        
        double count_throughput_mbps = mock_throughput_meter->getThroughputMbps();
        double count_packets_per_second = mock_throughput_meter->getPacketsPerSecond();
        
        EXPECT_GT(count_throughput_mbps, 0.0) << "Throughput should be positive for client count " << count;
        EXPECT_GT(count_packets_per_second, 0.0) << "Packets per second should be positive for client count " << count;
    }
}

// Additional throughput tests
TEST_F(ThroughputTest, ThroughputPerformance) {
    // Test throughput performance
    const int num_operations = 1000;
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    // Test throughput operations
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
    
    // Throughput operations should be fast
    EXPECT_LT(time_per_operation, 1000.0) << "Throughput operations too slow: " << time_per_operation << " microseconds";
    
    std::cout << "Throughput performance: " << time_per_operation << " microseconds per operation" << std::endl;
}

TEST_F(ThroughputTest, ThroughputAccuracy) {
    // Test throughput accuracy
    const int num_packets = 100;
    const int packet_size = 1024;
    
    mock_throughput_meter->startMeasurement();
    
    // Test throughput accuracy
    for (int i = 0; i < num_packets; ++i) {
        std::vector<uint8_t> packet_data = generateTestPacket(packet_size);
        bool transmitted = mock_network_transmitter->transmitPacket(packet_data);
        EXPECT_TRUE(transmitted) << "Packet transmission should succeed";
        mock_throughput_meter->recordBytes(packet_data.size());
        mock_throughput_meter->recordPacket();
    }
    
    mock_throughput_meter->endMeasurement();
    
    // Test throughput accuracy metrics
    double throughput_mbps = mock_throughput_meter->getThroughputMbps();
    double packets_per_second = mock_throughput_meter->getPacketsPerSecond();
    double measurement_duration = mock_throughput_meter->getMeasurementDuration();
    
    EXPECT_GT(throughput_mbps, 0.0) << "Throughput should be accurate";
    EXPECT_GT(packets_per_second, 0.0) << "Packets per second should be accurate";
    EXPECT_GT(measurement_duration, 0.0) << "Measurement duration should be accurate";
    
    // Test throughput accuracy with different packet sizes
    std::vector<int> packet_sizes = {512, 1024, 2048, 4096};
    for (int size : packet_sizes) {
        mock_throughput_meter->startMeasurement();
        
        for (int i = 0; i < 50; ++i) {
            std::vector<uint8_t> packet_data = generateTestPacket(size);
            bool transmitted = mock_network_transmitter->transmitPacket(packet_data);
            EXPECT_TRUE(transmitted) << "Packet transmission should succeed for size " << size;
            mock_throughput_meter->recordBytes(packet_data.size());
            mock_throughput_meter->recordPacket();
        }
        
        mock_throughput_meter->endMeasurement();
        
        double size_throughput_mbps = mock_throughput_meter->getThroughputMbps();
        double size_packets_per_second = mock_throughput_meter->getPacketsPerSecond();
        
        EXPECT_GT(size_throughput_mbps, 0.0) << "Throughput should be accurate for size " << size;
        EXPECT_GT(size_packets_per_second, 0.0) << "Packets per second should be accurate for size " << size;
    }
    
    // Test throughput accuracy with different client counts
    std::vector<int> client_counts = {10, 50, 100};
    for (int count : client_counts) {
        mock_throughput_meter->startMeasurement();
        
        std::vector<std::thread> count_client_threads;
        for (int client = 0; client < count; ++client) {
            count_client_threads.emplace_back([this, client]() {
                for (int op = 0; op < 25; ++op) {
                    std::vector<uint8_t> packet_data = generateTestPacket(1024);
                    bool transmitted = mock_network_transmitter->transmitPacket(packet_data);
                    EXPECT_TRUE(transmitted) << "Packet transmission should succeed for client " << client;
                    mock_throughput_meter->recordBytes(packet_data.size());
                    mock_throughput_meter->recordPacket();
                }
            });
        }
        
        for (auto& thread : count_client_threads) {
            thread.join();
        }
        
        mock_throughput_meter->endMeasurement();
        
        double count_throughput_mbps = mock_throughput_meter->getThroughputMbps();
        double count_packets_per_second = mock_throughput_meter->getPacketsPerSecond();
        
        EXPECT_GT(count_throughput_mbps, 0.0) << "Throughput should be accurate for client count " << count;
        EXPECT_GT(count_packets_per_second, 0.0) << "Packets per second should be accurate for client count " << count;
    }
}

