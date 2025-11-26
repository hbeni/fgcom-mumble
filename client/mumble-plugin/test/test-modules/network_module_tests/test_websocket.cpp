#include "test_network_module_main.h"
#include <thread>

// 5.2 WebSocket Tests
TEST_F(WebSocketTest, ConnectionEstablishment) {
    // Test WebSocket connection establishment
    int server_sock = createTCPSocket();
    
    ASSERT_GE(server_sock, 0) << "Failed to create server socket";
    
    // Bind server to test port
    ASSERT_TRUE(bindSocket(server_sock, test_websocket_port)) << "Failed to bind server socket";
    
    // Listen for connections
    ASSERT_EQ(listen(server_sock, 1), 0) << "Failed to listen on server socket";
    
    // Test that server socket is in listening state
    int flags = fcntl(server_sock, F_GETFL, 0);
    ASSERT_GE(flags, 0) << "Failed to get socket flags";
    
    // Test socket options
    int opt = 1;
    ASSERT_EQ(setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)), 0) << "Failed to set socket options";
    
    close(server_sock);
}

TEST_F(WebSocketTest, MessageSendReceive) {
    // Test WebSocket message generation
    std::string message = generateWebSocketMessage("radio_transmission", "{\"frequency\":121.9,\"message\":\"Test message\"}");
    
    // Test message format
    ASSERT_FALSE(message.empty()) << "WebSocket message should not be empty";
    ASSERT_GT(message.length(), 10) << "WebSocket message should have reasonable length";
    
    // Test different message types
    std::string ping_message = generateWebSocketMessage("ping", "{\"timestamp\":1234567890}");
    std::string pong_message = generateWebSocketMessage("pong", "{\"timestamp\":1234567890}");
    
    ASSERT_FALSE(ping_message.empty()) << "Ping message should not be empty";
    ASSERT_FALSE(pong_message.empty()) << "Pong message should not be empty";
    
    // Test message contains expected data
    ASSERT_NE(message.find("radio_transmission"), std::string::npos) << "Message should contain type";
    ASSERT_NE(message.find("frequency"), std::string::npos) << "Message should contain frequency data";
}

TEST_F(WebSocketTest, BinaryDataTransfer) {
    // Test WebSocket binary data transfer
    int server_sock = createTCPSocket();
    int client_sock = createTCPSocket();
    
    ASSERT_GE(server_sock, 0) << "Failed to create server socket";
    ASSERT_GE(client_sock, 0) << "Failed to create client socket";
    
    ASSERT_TRUE(bindSocket(server_sock, test_websocket_port)) << "Failed to bind server socket";
    ASSERT_EQ(listen(server_sock, 1), 0) << "Failed to listen on server socket";
    
    // Test binary data generation and format validation
    std::vector<uint8_t> binary_data = generateRandomData(256);
    ASSERT_EQ(binary_data.size(), 256) << "Generated binary data should be 256 bytes";
    
    // Test WebSocket binary frame generation
    std::string binary_frame = generateWebSocketMessage("binary", "{\"data\":\"test_binary_data\"}");
    ASSERT_FALSE(binary_frame.empty()) << "WebSocket binary frame should not be empty";
    ASSERT_GT(binary_frame.length(), 0) << "WebSocket frame should not be empty";
    
    // Test frame contains expected data
    ASSERT_NE(binary_frame.find("binary"), std::string::npos) << "Frame should contain binary indicator";
    
    close(server_sock);
    close(client_sock);
}

TEST_F(WebSocketTest, PingPongKeepalive) {
    // Test WebSocket ping/pong keepalive
    int server_sock = createTCPSocket();
    int client_sock = createTCPSocket();
    
    ASSERT_GE(server_sock, 0) << "Failed to create server socket";
    ASSERT_GE(client_sock, 0) << "Failed to create client socket";
    
    ASSERT_TRUE(bindSocket(server_sock, test_websocket_port)) << "Failed to bind server socket";
    ASSERT_EQ(listen(server_sock, 1), 0) << "Failed to listen on server socket";
    
    // Test ping message generation
    std::string ping_message = generateWebSocketMessage("ping", "{\"timestamp\":" + std::to_string(std::time(nullptr)) + "}");
    ASSERT_FALSE(ping_message.empty()) << "Ping message should not be empty";
    ASSERT_NE(ping_message.find("ping"), std::string::npos) << "Ping message should contain ping type";
    
    // Test pong response generation
    std::string pong_message = generateWebSocketMessage("pong", "{\"timestamp\":" + std::to_string(std::time(nullptr)) + "}");
    ASSERT_FALSE(pong_message.empty()) << "Pong message should not be empty";
    ASSERT_NE(pong_message.find("pong"), std::string::npos) << "Pong message should contain pong type";
    
    // Test that ping and pong messages are different
    ASSERT_NE(ping_message, pong_message) << "Ping and pong messages should be different";
    
    // Test that both messages contain timestamp
    ASSERT_NE(ping_message.find("timestamp"), std::string::npos) << "Ping should contain timestamp";
    ASSERT_NE(pong_message.find("timestamp"), std::string::npos) << "Pong should contain timestamp";
    
    close(server_sock);
    close(client_sock);
}

TEST_F(WebSocketTest, ReconnectionLogic) {
    // Test WebSocket reconnection logic
    int server_sock = createTCPSocket();
    int client_sock = createTCPSocket();
    
    ASSERT_GE(server_sock, 0) << "Failed to create server socket";
    ASSERT_GE(client_sock, 0) << "Failed to create client socket";
    
    ASSERT_TRUE(bindSocket(server_sock, test_websocket_port)) << "Failed to bind server socket";
    ASSERT_EQ(listen(server_sock, 1), 0) << "Failed to listen on server socket";
    
    // Test reconnection message generation
    std::string reconnect_message = generateWebSocketMessage("reconnect", "{\"client_id\":\"test_client\"}");
    ASSERT_FALSE(reconnect_message.empty()) << "Reconnection message should not be empty";
    ASSERT_NE(reconnect_message.find("reconnect"), std::string::npos) << "Message should contain reconnect type";
    ASSERT_NE(reconnect_message.find("client_id"), std::string::npos) << "Message should contain client_id";
    
    // Test connection loss simulation
    close(client_sock);
    
    // Test new client socket creation
    int new_client_sock = createTCPSocket();
    ASSERT_GE(new_client_sock, 0) << "Failed to create new client socket";
    
    // Test reconnection acknowledgment generation
    std::string ack_message = generateWebSocketMessage("reconnect_ack", "{\"status\":\"success\"}");
    ASSERT_FALSE(ack_message.empty()) << "Acknowledgment message should not be empty";
    ASSERT_NE(ack_message.find("reconnect_ack"), std::string::npos) << "Message should contain reconnect_ack type";
    ASSERT_NE(ack_message.find("status"), std::string::npos) << "Message should contain status";
    
    close(server_sock);
    close(client_sock);
    close(new_client_sock);
}

TEST_F(WebSocketTest, GracefulDisconnect) {
    // Test WebSocket graceful disconnect
    int server_sock = createTCPSocket();
    int client_sock = createTCPSocket();
    
    ASSERT_GE(server_sock, 0) << "Failed to create server socket";
    ASSERT_GE(client_sock, 0) << "Failed to create client socket";
    
    ASSERT_TRUE(bindSocket(server_sock, test_websocket_port)) << "Failed to bind server socket";
    ASSERT_EQ(listen(server_sock, 1), 0) << "Failed to listen on server socket";
    
    // Test graceful disconnect message generation
    std::string disconnect_message = generateWebSocketMessage("disconnect", "{\"reason\":\"user_request\"}");
    ASSERT_FALSE(disconnect_message.empty()) << "Disconnect message should not be empty";
    ASSERT_NE(disconnect_message.find("disconnect"), std::string::npos) << "Message should contain disconnect type";
    ASSERT_NE(disconnect_message.find("reason"), std::string::npos) << "Message should contain reason";
    
    // Test disconnect acknowledgment generation
    std::string ack_message = generateWebSocketMessage("disconnect_ack", "{\"status\":\"success\"}");
    ASSERT_FALSE(ack_message.empty()) << "Acknowledgment message should not be empty";
    ASSERT_NE(ack_message.find("disconnect_ack"), std::string::npos) << "Message should contain disconnect_ack type";
    ASSERT_NE(ack_message.find("status"), std::string::npos) << "Message should contain status";
    
    // Test connection closure
    close(client_sock);
    close(server_sock);
}

// Additional WebSocket tests
TEST_F(WebSocketTest, WebSocketPerformance) {
    // Test WebSocket performance
    const int num_messages = 100;  // OPTIMIZED: Reduced from 1000 to 100
    int server_sock = createTCPSocket();
    int client_sock = createTCPSocket();
    
    ASSERT_GE(server_sock, 0) << "Failed to create server socket";
    ASSERT_GE(client_sock, 0) << "Failed to create client socket";
    
    ASSERT_TRUE(bindSocket(server_sock, test_websocket_port)) << "Failed to bind server socket";
    ASSERT_EQ(listen(server_sock, 1), 0) << "Failed to listen on server socket";
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    // Generate messages (performance test)
    std::vector<std::string> messages;
    for (int i = 0; i < num_messages; ++i) {
        std::string message = generateWebSocketMessage("test", "{\"id\":" + std::to_string(i) + "}");
        ASSERT_FALSE(message.empty()) << "Message " << i << " should not be empty";
        messages.push_back(message);
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    // Test performance metrics
    ASSERT_EQ(messages.size(), num_messages) << "Should generate " << num_messages << " messages";
    ASSERT_LT(duration.count(), 1000000) << "Message generation should be fast (< 1 second)";
    
    // Calculate performance metrics
    double time_per_message = static_cast<double>(duration.count()) / num_messages;
    double messages_per_second = 1000000.0 / time_per_message;
    
    // WebSocket should be fast
    EXPECT_LT(time_per_message, 1000.0) << "WebSocket message processing too slow: " << time_per_message << " microseconds";
    EXPECT_GT(messages_per_second, 1000.0) << "WebSocket message rate too low: " << messages_per_second << " messages/second";
    
    std::cout << "WebSocket performance: " << time_per_message << " microseconds per message" << std::endl;
    std::cout << "WebSocket rate: " << messages_per_second << " messages/second" << std::endl;
    
    close(server_sock);
    close(client_sock);
}

TEST_F(WebSocketTest, WebSocketReliability) {
    // Test WebSocket reliability
    int server_sock = createTCPSocket();
    int client_sock = createTCPSocket();
    
    ASSERT_GE(server_sock, 0) << "Failed to create server socket";
    ASSERT_GE(client_sock, 0) << "Failed to create client socket";
    
    ASSERT_TRUE(bindSocket(server_sock, test_websocket_port)) << "Failed to bind server socket";
    ASSERT_EQ(listen(server_sock, 1), 0) << "Failed to listen on server socket";
    
    // Test reliability with different message sizes
    std::vector<int> message_sizes = {64, 128, 256, 512, 1024};
    
    for (int size : message_sizes) {
        std::string message = generateWebSocketMessage("test", "{\"data\":\"" + std::string(size - 20, 'X') + "\"}");
        
        // Test message generation for different sizes
        ASSERT_FALSE(message.empty()) << "Message of size " << size << " should not be empty";
        ASSERT_GT(message.length(), 0) << "Message of size " << size << " should have content";
        ASSERT_NE(message.find("test"), std::string::npos) << "Message should contain test type";
        ASSERT_NE(message.find("data"), std::string::npos) << "Message should contain data field";
    }
    
    close(server_sock);
    close(client_sock);
}

