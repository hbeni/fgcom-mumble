#include "test_network_module_main.cpp"

// 5.1 UDP Protocol Tests
TEST_F(UDPProtocolTest, PacketTransmission) {
    // Test UDP packet transmission
    int sender_sock = createUDPSocket();
    int receiver_sock = createUDPSocket();
    
    ASSERT_GE(sender_sock, 0) << "Failed to create sender socket";
    ASSERT_GE(receiver_sock, 0) << "Failed to create receiver socket";
    
    // Bind receiver to test port
    ASSERT_TRUE(bindSocket(receiver_sock, test_udp_port)) << "Failed to bind receiver socket";
    
    // Test simple message transmission
    std::string message = generateUDPMessage(test_message_simple);
    ASSERT_TRUE(sendUDPPacket(sender_sock, message, "127.0.0.1", test_udp_port)) << "Failed to send UDP packet";
    
    // Test message reception
    std::string received = receiveUDPPacket(receiver_sock, test_timeout_medium);
    ASSERT_FALSE(received.empty()) << "Failed to receive UDP packet";
    ASSERT_EQ(received, message) << "Received message doesn't match sent message";
    
    // Test complex message
    std::string complex_message = generateUDPMessage(test_message_complex);
    ASSERT_TRUE(sendUDPPacket(sender_sock, complex_message, "127.0.0.1", test_udp_port)) << "Failed to send complex UDP packet";
    
    std::string complex_received = receiveUDPPacket(receiver_sock, test_timeout_medium);
    ASSERT_FALSE(complex_received.empty()) << "Failed to receive complex UDP packet";
    ASSERT_EQ(complex_received, complex_message) << "Received complex message doesn't match sent message";
    
    close(sender_sock);
    close(receiver_sock);
}

TEST_F(UDPProtocolTest, PacketReception) {
    // Test UDP packet reception
    int receiver_sock = createUDPSocket();
    ASSERT_GE(receiver_sock, 0) << "Failed to create receiver socket";
    
    ASSERT_TRUE(bindSocket(receiver_sock, test_udp_port)) << "Failed to bind receiver socket";
    
    // Test reception timeout
    std::string received = receiveUDPPacket(receiver_sock, test_timeout_short);
    ASSERT_TRUE(received.empty()) << "Should not receive packet with short timeout";
    
    // Test reception with data
    int sender_sock = createUDPSocket();
    ASSERT_GE(sender_sock, 0) << "Failed to create sender socket";
    
    std::string message = generateUDPMessage(test_message_simple);
    ASSERT_TRUE(sendUDPPacket(sender_sock, message, "127.0.0.1", test_udp_port)) << "Failed to send UDP packet";
    
    received = receiveUDPPacket(receiver_sock, test_timeout_medium);
    ASSERT_FALSE(received.empty()) << "Failed to receive UDP packet";
    ASSERT_EQ(received, message) << "Received message doesn't match sent message";
    
    close(sender_sock);
    close(receiver_sock);
}

TEST_F(UDPProtocolTest, PacketLossHandling) {
    // Test packet loss handling
    int sender_sock = createUDPSocket();
    int receiver_sock = createUDPSocket();
    
    ASSERT_GE(sender_sock, 0) << "Failed to create sender socket";
    ASSERT_GE(receiver_sock, 0) << "Failed to create receiver socket";
    
    ASSERT_TRUE(bindSocket(receiver_sock, test_udp_port)) << "Failed to bind receiver socket";
    
    // Test multiple packet transmission
    std::vector<std::string> messages;
    for (int i = 0; i < 10; ++i) {
        std::string message = generateUDPMessage("LAT=40.7128,LON=-74.0060,ALT=" + std::to_string(100.0 + i));
        messages.push_back(message);
        ASSERT_TRUE(sendUDPPacket(sender_sock, message, "127.0.0.1", test_udp_port)) << "Failed to send UDP packet " << i;
    }
    
    // Test packet reception with potential loss
    std::vector<std::string> received_messages;
    for (int i = 0; i < 10; ++i) {
        std::string received = receiveUDPPacket(receiver_sock, test_timeout_short);
        if (!received.empty()) {
            received_messages.push_back(received);
        }
    }
    
    // Should receive at least some packets
    ASSERT_GT(received_messages.size(), 0) << "Should receive at least some packets";
    ASSERT_LE(received_messages.size(), 10) << "Should not receive more packets than sent";
    
    // Test packet loss detection
    int lost_packets = 10 - received_messages.size();
    ASSERT_GE(lost_packets, 0) << "Lost packets count should be non-negative";
    
    close(sender_sock);
    close(receiver_sock);
}

TEST_F(UDPProtocolTest, OutOfOrderPacketHandling) {
    // Test out-of-order packet handling
    int sender_sock = createUDPSocket();
    int receiver_sock = createUDPSocket();
    
    ASSERT_GE(sender_sock, 0) << "Failed to create sender socket";
    ASSERT_GE(receiver_sock, 0) << "Failed to create receiver socket";
    
    ASSERT_TRUE(bindSocket(receiver_sock, test_udp_port)) << "Failed to bind receiver socket";
    
    // Send packets in reverse order
    std::vector<std::string> messages;
    for (int i = 9; i >= 0; --i) {
        std::string message = generateUDPMessage("LAT=40.7128,LON=-74.0060,ALT=" + std::to_string(100.0 + i));
        messages.push_back(message);
        ASSERT_TRUE(sendUDPPacket(sender_sock, message, "127.0.0.1", test_udp_port)) << "Failed to send UDP packet " << i;
    }
    
    // Receive packets and check order
    std::vector<std::string> received_messages;
    for (int i = 0; i < 10; ++i) {
        std::string received = receiveUDPPacket(receiver_sock, test_timeout_short);
        if (!received.empty()) {
            received_messages.push_back(received);
        }
    }
    
    // Should receive all packets
    ASSERT_EQ(received_messages.size(), 10) << "Should receive all packets";
    
    // Test out-of-order detection
    bool out_of_order = false;
    for (size_t i = 1; i < received_messages.size(); ++i) {
        if (received_messages[i] != messages[i]) {
            out_of_order = true;
            break;
        }
    }
    
    // Packets should be received out of order
    ASSERT_TRUE(out_of_order) << "Packets should be received out of order";
    
    close(sender_sock);
    close(receiver_sock);
}

TEST_F(UDPProtocolTest, DuplicatePacketDetection) {
    // Test duplicate packet detection
    int sender_sock = createUDPSocket();
    int receiver_sock = createUDPSocket();
    
    ASSERT_GE(sender_sock, 0) << "Failed to create sender socket";
    ASSERT_GE(receiver_sock, 0) << "Failed to create receiver socket";
    
    ASSERT_TRUE(bindSocket(receiver_sock, test_udp_port)) << "Failed to bind receiver socket";
    
    // Send same packet multiple times
    std::string message = generateUDPMessage(test_message_simple);
    for (int i = 0; i < 5; ++i) {
        ASSERT_TRUE(sendUDPPacket(sender_sock, message, "127.0.0.1", test_udp_port)) << "Failed to send duplicate UDP packet " << i;
    }
    
    // Receive packets and check for duplicates
    std::vector<std::string> received_messages;
    for (int i = 0; i < 5; ++i) {
        std::string received = receiveUDPPacket(receiver_sock, test_timeout_short);
        if (!received.empty()) {
            received_messages.push_back(received);
        }
    }
    
    // Should receive all packets
    ASSERT_EQ(received_messages.size(), 5) << "Should receive all packets";
    
    // Test duplicate detection
    std::set<std::string> unique_messages;
    for (const std::string& msg : received_messages) {
        unique_messages.insert(msg);
    }
    
    // All messages should be identical (duplicates)
    ASSERT_EQ(unique_messages.size(), 1) << "All messages should be identical";
    
    close(sender_sock);
    close(receiver_sock);
}

TEST_F(UDPProtocolTest, JitterBufferManagement) {
    // Test jitter buffer management
    int sender_sock = createUDPSocket();
    int receiver_sock = createUDPSocket();
    
    ASSERT_GE(sender_sock, 0) << "Failed to create sender socket";
    ASSERT_GE(receiver_sock, 0) << "Failed to create receiver socket";
    
    ASSERT_TRUE(bindSocket(receiver_sock, test_udp_port)) << "Failed to bind receiver socket";
    
    // Send packets with varying delays
    std::vector<std::string> messages;
    for (int i = 0; i < 10; ++i) {
        std::string message = generateUDPMessage("LAT=40.7128,LON=-74.0060,ALT=" + std::to_string(100.0 + i));
        messages.push_back(message);
        
        // Simulate jitter by varying send times
        if (i % 2 == 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        } else {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        
        ASSERT_TRUE(sendUDPPacket(sender_sock, message, "127.0.0.1", test_udp_port)) << "Failed to send UDP packet " << i;
    }
    
    // Test jitter buffer management
    std::vector<std::string> received_messages;
    std::vector<std::chrono::steady_clock::time_point> receive_times;
    
    for (int i = 0; i < 10; ++i) {
        auto start_time = std::chrono::steady_clock::now();
        std::string received = receiveUDPPacket(receiver_sock, test_timeout_medium);
        auto end_time = std::chrono::steady_clock::now();
        
        if (!received.empty()) {
            received_messages.push_back(received);
            receive_times.push_back(end_time);
        }
    }
    
    // Should receive all packets
    ASSERT_EQ(received_messages.size(), 10) << "Should receive all packets";
    
    // Test jitter calculation
    std::vector<double> jitter_values;
    for (size_t i = 1; i < receive_times.size(); ++i) {
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(receive_times[i] - receive_times[i-1]);
        jitter_values.push_back(duration.count());
    }
    
    // Calculate jitter statistics
    double avg_jitter = std::accumulate(jitter_values.begin(), jitter_values.end(), 0.0) / jitter_values.size();
    double max_jitter = *std::max_element(jitter_values.begin(), jitter_values.end());
    double min_jitter = *std::min_element(jitter_values.begin(), jitter_values.end());
    
    ASSERT_GT(avg_jitter, 0.0) << "Average jitter should be positive";
    ASSERT_GT(max_jitter, min_jitter) << "Max jitter should be greater than min jitter";
    
    close(sender_sock);
    close(receiver_sock);
}

// Additional UDP protocol tests
TEST_F(UDPProtocolTest, UDPProtocolPerformance) {
    // Test UDP protocol performance
    const int num_packets = 1000;
    int sender_sock = createUDPSocket();
    int receiver_sock = createUDPSocket();
    
    ASSERT_GE(sender_sock, 0) << "Failed to create sender socket";
    ASSERT_GE(receiver_sock, 0) << "Failed to create receiver socket";
    
    ASSERT_TRUE(bindSocket(receiver_sock, test_udp_port)) << "Failed to bind receiver socket";
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    // Send packets
    for (int i = 0; i < num_packets; ++i) {
        std::string message = generateUDPMessage("LAT=40.7128,LON=-74.0060,ALT=" + std::to_string(100.0 + i));
        ASSERT_TRUE(sendUDPPacket(sender_sock, message, "127.0.0.1", test_udp_port)) << "Failed to send UDP packet " << i;
    }
    
    // Receive packets
    int received_count = 0;
    for (int i = 0; i < num_packets; ++i) {
        std::string received = receiveUDPPacket(receiver_sock, test_timeout_short);
        if (!received.empty()) {
            received_count++;
        }
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    // Calculate performance metrics
    double time_per_packet = static_cast<double>(duration.count()) / num_packets;
    double packets_per_second = 1000000.0 / time_per_packet;
    
    // UDP should be fast
    EXPECT_LT(time_per_packet, 1000.0) << "UDP packet processing too slow: " << time_per_packet << " microseconds";
    EXPECT_GT(packets_per_second, 1000.0) << "UDP packet rate too low: " << packets_per_second << " packets/second";
    
    std::cout << "UDP protocol performance: " << time_per_packet << " microseconds per packet" << std::endl;
    std::cout << "UDP protocol rate: " << packets_per_second << " packets/second" << std::endl;
    
    close(sender_sock);
    close(receiver_sock);
}

TEST_F(UDPProtocolTest, UDPProtocolReliability) {
    // Test UDP protocol reliability
    int sender_sock = createUDPSocket();
    int receiver_sock = createUDPSocket();
    
    ASSERT_GE(sender_sock, 0) << "Failed to create sender socket";
    ASSERT_GE(receiver_sock, 0) << "Failed to create receiver socket";
    
    ASSERT_TRUE(bindSocket(receiver_sock, test_udp_port)) << "Failed to bind receiver socket";
    
    // Test reliability with different packet sizes
    std::vector<int> packet_sizes = {64, 128, 256, 512, 1024};
    
    for (int size : packet_sizes) {
        std::string message = generateUDPMessage("LAT=40.7128,LON=-74.0060,ALT=100.5");
        message.resize(size, 'X'); // Pad to desired size
        
        ASSERT_TRUE(sendUDPPacket(sender_sock, message, "127.0.0.1", test_udp_port)) << "Failed to send UDP packet of size " << size;
        
        std::string received = receiveUDPPacket(receiver_sock, test_timeout_medium);
        ASSERT_FALSE(received.empty()) << "Failed to receive UDP packet of size " << size;
        ASSERT_EQ(received.length(), message.length()) << "Received packet size doesn't match sent size";
    }
    
    close(sender_sock);
    close(receiver_sock);
}

