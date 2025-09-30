#include "test_network_module_main.cpp"

// 5.2 WebSocket Tests
TEST_F(WebSocketTest, ConnectionEstablishment) {
    // Test WebSocket connection establishment
    int server_sock = createTCPSocket();
    int client_sock = createTCPSocket();
    
    ASSERT_GE(server_sock, 0) << "Failed to create server socket";
    ASSERT_GE(client_sock, 0) << "Failed to create client socket";
    
    // Bind server to test port
    ASSERT_TRUE(bindSocket(server_sock, test_websocket_port)) << "Failed to bind server socket";
    
    // Listen for connections
    ASSERT_EQ(listen(server_sock, 1), 0) << "Failed to listen on server socket";
    
    // Test connection establishment
    struct sockaddr_in client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    
    // Accept connection (non-blocking)
    int accepted_sock = accept(server_sock, (struct sockaddr*)&client_addr, &client_addr_len);
    
    // Connection should be established
    ASSERT_GE(accepted_sock, 0) << "Failed to accept WebSocket connection";
    
    // Test connection state
    int flags = fcntl(accepted_sock, F_GETFL, 0);
    ASSERT_GE(flags, 0) << "Failed to get socket flags";
    
    close(server_sock);
    close(client_sock);
    close(accepted_sock);
}

TEST_F(WebSocketTest, MessageSendReceive) {
    // Test WebSocket message send/receive
    int server_sock = createTCPSocket();
    int client_sock = createTCPSocket();
    
    ASSERT_GE(server_sock, 0) << "Failed to create server socket";
    ASSERT_GE(client_sock, 0) << "Failed to create client socket";
    
    ASSERT_TRUE(bindSocket(server_sock, test_websocket_port)) << "Failed to bind server socket";
    ASSERT_EQ(listen(server_sock, 1), 0) << "Failed to listen on server socket";
    
    // Test message transmission
    std::string message = generateWebSocketMessage("radio_transmission", "{\"frequency\":121.9,\"message\":\"Test message\"}");
    
    // Send message
    ssize_t sent = send(client_sock, message.c_str(), message.length(), 0);
    ASSERT_EQ(sent, static_cast<ssize_t>(message.length())) << "Failed to send WebSocket message";
    
    // Receive message
    char buffer[1024];
    ssize_t received = recv(server_sock, buffer, sizeof(buffer) - 1, 0);
    ASSERT_GT(received, 0) << "Failed to receive WebSocket message";
    
    buffer[received] = '\0';
    std::string received_message(buffer);
    ASSERT_EQ(received_message, message) << "Received message doesn't match sent message";
    
    close(server_sock);
    close(client_sock);
}

TEST_F(WebSocketTest, BinaryDataTransfer) {
    // Test WebSocket binary data transfer
    int server_sock = createTCPSocket();
    int client_sock = createTCPSocket();
    
    ASSERT_GE(server_sock, 0) << "Failed to create server socket";
    ASSERT_GE(client_sock, 0) << "Failed to create client socket";
    
    ASSERT_TRUE(bindSocket(server_sock, test_websocket_port)) << "Failed to bind server socket";
    ASSERT_EQ(listen(server_sock, 1), 0) << "Failed to listen on server socket";
    
    // Test binary data transmission
    std::vector<uint8_t> binary_data = generateRandomData(256);
    
    // Send binary data
    ssize_t sent = send(client_sock, binary_data.data(), binary_data.size(), 0);
    ASSERT_EQ(sent, static_cast<ssize_t>(binary_data.size())) << "Failed to send binary data";
    
    // Receive binary data
    std::vector<uint8_t> received_data(binary_data.size());
    ssize_t received = recv(server_sock, received_data.data(), received_data.size(), 0);
    ASSERT_EQ(received, static_cast<ssize_t>(binary_data.size())) << "Failed to receive binary data";
    
    // Compare binary data
    ASSERT_EQ(received_data, binary_data) << "Received binary data doesn't match sent data";
    
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
    
    // Test ping message
    std::string ping_message = generateWebSocketMessage("ping", "{\"timestamp\":" + std::to_string(std::time(nullptr)) + "}");
    
    // Send ping
    ssize_t sent = send(client_sock, ping_message.c_str(), ping_message.length(), 0);
    ASSERT_EQ(sent, static_cast<ssize_t>(ping_message.length())) << "Failed to send ping message";
    
    // Receive ping
    char buffer[1024];
    ssize_t received = recv(server_sock, buffer, sizeof(buffer) - 1, 0);
    ASSERT_GT(received, 0) << "Failed to receive ping message";
    
    buffer[received] = '\0';
    std::string received_ping(buffer);
    ASSERT_EQ(received_ping, ping_message) << "Received ping doesn't match sent ping";
    
    // Test pong response
    std::string pong_message = generateWebSocketMessage("pong", "{\"timestamp\":" + std::to_string(std::time(nullptr)) + "}");
    
    // Send pong
    sent = send(server_sock, pong_message.c_str(), pong_message.length(), 0);
    ASSERT_EQ(sent, static_cast<ssize_t>(pong_message.length())) << "Failed to send pong message";
    
    // Receive pong
    received = recv(client_sock, buffer, sizeof(buffer) - 1, 0);
    ASSERT_GT(received, 0) << "Failed to receive pong message";
    
    buffer[received] = '\0';
    std::string received_pong(buffer);
    ASSERT_EQ(received_pong, pong_message) << "Received pong doesn't match sent pong";
    
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
    
    // Test initial connection
    struct sockaddr_in client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    int accepted_sock = accept(server_sock, (struct sockaddr*)&client_addr, &client_addr_len);
    ASSERT_GE(accepted_sock, 0) << "Failed to accept initial connection";
    
    // Test connection loss
    close(accepted_sock);
    
    // Test reconnection
    int new_client_sock = createTCPSocket();
    ASSERT_GE(new_client_sock, 0) << "Failed to create new client socket";
    
    // Test reconnection message
    std::string reconnect_message = generateWebSocketMessage("reconnect", "{\"client_id\":\"test_client\"}");
    
    // Send reconnection message
    ssize_t sent = send(new_client_sock, reconnect_message.c_str(), reconnect_message.length(), 0);
    ASSERT_EQ(sent, static_cast<ssize_t>(reconnect_message.length())) << "Failed to send reconnection message";
    
    // Test reconnection acknowledgment
    std::string ack_message = generateWebSocketMessage("reconnect_ack", "{\"status\":\"success\"}");
    
    // Send acknowledgment
    sent = send(server_sock, ack_message.c_str(), ack_message.length(), 0);
    ASSERT_EQ(sent, static_cast<ssize_t>(ack_message.length())) << "Failed to send reconnection acknowledgment";
    
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
    
    // Test graceful disconnect message
    std::string disconnect_message = generateWebSocketMessage("disconnect", "{\"reason\":\"user_request\"}");
    
    // Send disconnect message
    ssize_t sent = send(client_sock, disconnect_message.c_str(), disconnect_message.length(), 0);
    ASSERT_EQ(sent, static_cast<ssize_t>(disconnect_message.length())) << "Failed to send disconnect message";
    
    // Test disconnect acknowledgment
    std::string ack_message = generateWebSocketMessage("disconnect_ack", "{\"status\":\"success\"}");
    
    // Send acknowledgment
    sent = send(server_sock, ack_message.c_str(), ack_message.length(), 0);
    ASSERT_EQ(sent, static_cast<ssize_t>(ack_message.length())) << "Failed to send disconnect acknowledgment";
    
    // Test connection closure
    close(client_sock);
    close(server_sock);
}

// Additional WebSocket tests
TEST_F(WebSocketTest, WebSocketPerformance) {
    // Test WebSocket performance
    const int num_messages = 1000;
    int server_sock = createTCPSocket();
    int client_sock = createTCPSocket();
    
    ASSERT_GE(server_sock, 0) << "Failed to create server socket";
    ASSERT_GE(client_sock, 0) << "Failed to create client socket";
    
    ASSERT_TRUE(bindSocket(server_sock, test_websocket_port)) << "Failed to bind server socket";
    ASSERT_EQ(listen(server_sock, 1), 0) << "Failed to listen on server socket";
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    // Send messages
    for (int i = 0; i < num_messages; ++i) {
        std::string message = generateWebSocketMessage("test", "{\"id\":" + std::to_string(i) + "}");
        ssize_t sent = send(client_sock, message.c_str(), message.length(), 0);
        ASSERT_EQ(sent, static_cast<ssize_t>(message.length())) << "Failed to send message " << i;
    }
    
    // Receive messages
    int received_count = 0;
    char buffer[1024];
    for (int i = 0; i < num_messages; ++i) {
        ssize_t received = recv(server_sock, buffer, sizeof(buffer) - 1, 0);
        if (received > 0) {
            received_count++;
        }
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
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
        
        // Send message
        ssize_t sent = send(client_sock, message.c_str(), message.length(), 0);
        ASSERT_EQ(sent, static_cast<ssize_t>(message.length())) << "Failed to send message of size " << size;
        
        // Receive message
        char buffer[1024];
        ssize_t received = recv(server_sock, buffer, sizeof(buffer) - 1, 0);
        ASSERT_GT(received, 0) << "Failed to receive message of size " << size;
        ASSERT_EQ(received, static_cast<ssize_t>(message.length())) << "Received message size doesn't match sent size";
    }
    
    close(server_sock);
    close(client_sock);
}

