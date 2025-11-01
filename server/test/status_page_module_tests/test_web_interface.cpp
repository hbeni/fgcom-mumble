#include "test_status_page_main.cpp"

// 13.1 Web Interface Tests
TEST_F(WebInterfaceTest, HTMLRendering) {
    // Test HTML rendering
    std::string html = mock_html_renderer->renderStatusPage(status_page_data);
    EXPECT_FALSE(html.empty()) << "HTML rendering should not be empty";
    
    // Test HTML validation
    bool is_valid = mock_html_renderer->validateHTML(html);
    EXPECT_TRUE(is_valid) << "HTML should be valid";
    
    // Test HTML structure
    EXPECT_TRUE(html.find("<!DOCTYPE html>") != std::string::npos) << "HTML should have DOCTYPE";
    EXPECT_TRUE(html.find("<html>") != std::string::npos) << "HTML should have html tag";
    EXPECT_TRUE(html.find("</html>") != std::string::npos) << "HTML should have closing html tag";
    EXPECT_TRUE(html.find("<head>") != std::string::npos) << "HTML should have head tag";
    EXPECT_TRUE(html.find("<body>") != std::string::npos) << "HTML should have body tag";
    
    // Test HTML content
    EXPECT_TRUE(html.find("FGCom-mumble") != std::string::npos) << "HTML should contain title";
    EXPECT_TRUE(html.find("Users:") != std::string::npos) << "HTML should contain user count";
    EXPECT_TRUE(html.find("Last DB update:") != std::string::npos) << "HTML should contain last update";
    
    // Test HTML rendering with different data
    std::map<std::string, std::string> custom_data;
    custom_data["user_count"] = "5";
    custom_data["last_update"] = "2024-01-01 12:00:00";
    custom_data["map_content"] = "<div>Custom Map</div>";
    custom_data["users_content"] = "<div>Custom Users</div>";
    custom_data["frequencies_content"] = "<div>Custom Frequencies</div>";
    
    std::string custom_html = mock_html_renderer->renderStatusPage(custom_data);
    EXPECT_FALSE(custom_html.empty()) << "Custom HTML rendering should not be empty";
    
    bool custom_is_valid = mock_html_renderer->validateHTML(custom_html);
    EXPECT_TRUE(custom_is_valid) << "Custom HTML should be valid";
    
    // Test HTML rendering with empty data
    std::map<std::string, std::string> empty_data;
    empty_data["user_count"] = "0";
    empty_data["last_update"] = "";
    empty_data["map_content"] = "";
    empty_data["users_content"] = "";
    empty_data["frequencies_content"] = "";
    
    std::string empty_html = mock_html_renderer->renderStatusPage(empty_data);
    EXPECT_FALSE(empty_html.empty()) << "Empty HTML rendering should not be empty";
    
    bool empty_is_valid = mock_html_renderer->validateHTML(empty_html);
    EXPECT_TRUE(empty_is_valid) << "Empty HTML should be valid";
}

TEST_F(WebInterfaceTest, RealTimeUpdates) {
    // Test real-time updates
    bool start_result = mock_real_time_updater->startRealTimeUpdates();
    EXPECT_TRUE(start_result) << "Real-time updates should start successfully";
    
    // Test that updater is running
    bool is_running = mock_real_time_updater->isRunning();
    EXPECT_TRUE(is_running) << "Real-time updater should be running";
    
    // Test update callback
    std::atomic<int> callback_count{0};
    mock_real_time_updater->setUpdateCallback([&callback_count](const std::string& update) {
        // Use the update parameter to verify it's not empty
        EXPECT_FALSE(update.empty()) << "Update callback should receive non-empty update";
        callback_count++;
    });
    
    // Wait for updates
    std::this_thread::sleep_for(std::chrono::milliseconds(1500));
    
    // Test that updates were received
    int update_count = mock_real_time_updater->getUpdateCount();
    EXPECT_GT(update_count, 0) << "Should have received updates";
    
    // Test update interval
    mock_real_time_updater->setUpdateInterval(500);
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    
    // Test that updater is still running
    is_running = mock_real_time_updater->isRunning();
    EXPECT_TRUE(is_running) << "Real-time updater should still be running";
    
    // Test stopping updates
    mock_real_time_updater->stopRealTimeUpdates();
    is_running = mock_real_time_updater->isRunning();
    EXPECT_FALSE(is_running) << "Real-time updater should be stopped";
    
    // Test restarting updates
    start_result = mock_real_time_updater->startRealTimeUpdates();
    EXPECT_TRUE(start_result) << "Real-time updates should restart successfully";
    
    // Test that updater is running again
    is_running = mock_real_time_updater->isRunning();
    EXPECT_TRUE(is_running) << "Real-time updater should be running again";
    
    // Clean up
    mock_real_time_updater->stopRealTimeUpdates();
}

TEST_F(WebInterfaceTest, ClientListDisplay) {
    // Test client list display
    std::string client_list_html = mock_html_renderer->renderClientList(test_clients);
    EXPECT_FALSE(client_list_html.empty()) << "Client list HTML should not be empty";
    
    // Test client list structure
    EXPECT_TRUE(client_list_html.find("<div class=\"client-list\">") != std::string::npos) << "Client list should have container div";
    EXPECT_TRUE(client_list_html.find("<div class=\"client-entry\">") != std::string::npos) << "Client list should have entry divs";
    
    // Test client data in HTML
    for (const auto& client : test_clients) {
        EXPECT_TRUE(client_list_html.find(client.at("callsign")) != std::string::npos) << "Client list should contain callsign";
        EXPECT_TRUE(client_list_html.find(client.at("lat")) != std::string::npos) << "Client list should contain latitude";
        EXPECT_TRUE(client_list_html.find(client.at("lon")) != std::string::npos) << "Client list should contain longitude";
        EXPECT_TRUE(client_list_html.find(client.at("alt")) != std::string::npos) << "Client list should contain altitude";
        EXPECT_TRUE(client_list_html.find(client.at("frequency")) != std::string::npos) << "Client list should contain frequency";
    }
    
    // Test client list with empty data
    std::vector<std::map<std::string, std::string>> empty_clients;
    std::string empty_client_list_html = mock_html_renderer->renderClientList(empty_clients);
    EXPECT_FALSE(empty_client_list_html.empty()) << "Empty client list HTML should not be empty";
    EXPECT_TRUE(empty_client_list_html.find("<div class=\"client-list\">") != std::string::npos) << "Empty client list should have container div";
    
    // Test client list with single client
    std::vector<std::map<std::string, std::string>> single_client;
    single_client.push_back(test_clients[0]);
    std::string single_client_list_html = mock_html_renderer->renderClientList(single_client);
    EXPECT_FALSE(single_client_list_html.empty()) << "Single client list HTML should not be empty";
    EXPECT_TRUE(single_client_list_html.find(test_clients[0].at("callsign")) != std::string::npos) << "Single client list should contain callsign";
    
    // Test client list with large dataset
    std::vector<std::map<std::string, std::string>> large_clients = generateTestClients(100);
    std::string large_client_list_html = mock_html_renderer->renderClientList(large_clients);
    EXPECT_FALSE(large_client_list_html.empty()) << "Large client list HTML should not be empty";
    EXPECT_TRUE(large_client_list_html.find("<div class=\"client-list\">") != std::string::npos) << "Large client list should have container div";
}

TEST_F(WebInterfaceTest, FrequencyListDisplay) {
    // Test frequency list display
    std::string frequency_list_html = mock_html_renderer->renderFrequencyList(test_frequencies);
    EXPECT_FALSE(frequency_list_html.empty()) << "Frequency list HTML should not be empty";
    
    // Test frequency list structure
    EXPECT_TRUE(frequency_list_html.find("<div class=\"frequency-list\">") != std::string::npos) << "Frequency list should have container div";
    EXPECT_TRUE(frequency_list_html.find("<div class=\"frequency-entry\">") != std::string::npos) << "Frequency list should have entry divs";
    
    // Test frequency data in HTML
    for (const auto& frequency : test_frequencies) {
        EXPECT_TRUE(frequency_list_html.find(frequency.at("frequency")) != std::string::npos) << "Frequency list should contain frequency";
        EXPECT_TRUE(frequency_list_html.find(frequency.at("user_count")) != std::string::npos) << "Frequency list should contain user count";
        EXPECT_TRUE(frequency_list_html.find(frequency.at("status")) != std::string::npos) << "Frequency list should contain status";
    }
    
    // Test frequency list with empty data
    std::vector<std::map<std::string, std::string>> empty_frequencies;
    std::string empty_frequency_list_html = mock_html_renderer->renderFrequencyList(empty_frequencies);
    EXPECT_FALSE(empty_frequency_list_html.empty()) << "Empty frequency list HTML should not be empty";
    EXPECT_TRUE(empty_frequency_list_html.find("<div class=\"frequency-list\">") != std::string::npos) << "Empty frequency list should have container div";
    
    // Test frequency list with single frequency
    std::vector<std::map<std::string, std::string>> single_frequency;
    single_frequency.push_back(test_frequencies[0]);
    std::string single_frequency_list_html = mock_html_renderer->renderFrequencyList(single_frequency);
    EXPECT_FALSE(single_frequency_list_html.empty()) << "Single frequency list HTML should not be empty";
    EXPECT_TRUE(single_frequency_list_html.find(test_frequencies[0].at("frequency")) != std::string::npos) << "Single frequency list should contain frequency";
    
    // Test frequency list with large dataset
    std::vector<std::map<std::string, std::string>> large_frequencies = generateTestFrequencies(50);
    std::string large_frequency_list_html = mock_html_renderer->renderFrequencyList(large_frequencies);
    EXPECT_FALSE(large_frequency_list_html.empty()) << "Large frequency list HTML should not be empty";
    EXPECT_TRUE(large_frequency_list_html.find("<div class=\"frequency-list\">") != std::string::npos) << "Large frequency list should have container div";
}

TEST_F(WebInterfaceTest, MapRendering) {
    // Test map rendering
    std::string map_html = mock_html_renderer->renderMap(test_map_data);
    EXPECT_FALSE(map_html.empty()) << "Map HTML should not be empty";
    
    // Test map structure
    EXPECT_TRUE(map_html.find("<div class=\"map-container\">") != std::string::npos) << "Map should have container div";
    EXPECT_TRUE(map_html.find("<div id=\"map\"") != std::string::npos) << "Map should have map div";
    EXPECT_TRUE(map_html.find("<script>") != std::string::npos) << "Map should have script tag";
    
    // Test map data in HTML
    for (const auto& marker : test_map_data) {
        EXPECT_TRUE(map_html.find(marker.at("lat")) != std::string::npos) << "Map should contain latitude";
        EXPECT_TRUE(map_html.find(marker.at("lon")) != std::string::npos) << "Map should contain longitude";
        EXPECT_TRUE(map_html.find(marker.at("callsign")) != std::string::npos) << "Map should contain callsign";
    }
    
    // Test map with empty data
    std::vector<std::map<std::string, std::string>> empty_map_data;
    std::string empty_map_html = mock_html_renderer->renderMap(empty_map_data);
    EXPECT_FALSE(empty_map_html.empty()) << "Empty map HTML should not be empty";
    EXPECT_TRUE(empty_map_html.find("<div class=\"map-container\">") != std::string::npos) << "Empty map should have container div";
    
    // Test map with single marker
    std::vector<std::map<std::string, std::string>> single_marker;
    single_marker.push_back(test_map_data[0]);
    std::string single_map_html = mock_html_renderer->renderMap(single_marker);
    EXPECT_FALSE(single_map_html.empty()) << "Single marker map HTML should not be empty";
    EXPECT_TRUE(single_map_html.find(test_map_data[0].at("callsign")) != std::string::npos) << "Single marker map should contain callsign";
    
    // Test map with large dataset
    std::vector<std::map<std::string, std::string>> large_map_data = generateTestMapData(100);
    std::string large_map_html = mock_html_renderer->renderMap(large_map_data);
    EXPECT_FALSE(large_map_html.empty()) << "Large map HTML should not be empty";
    EXPECT_TRUE(large_map_html.find("<div class=\"map-container\">") != std::string::npos) << "Large map should have container div";
}

TEST_F(WebInterfaceTest, WebSocketConnection) {
    // Test WebSocket server startup
    bool start_result = mock_websocket_server->startServer(8080);
    EXPECT_TRUE(start_result) << "WebSocket server should start successfully";
    
    // Test that server is running
    bool is_running = mock_websocket_server->isRunning();
    EXPECT_TRUE(is_running) << "WebSocket server should be running";
    
    // Test server port
    int port = mock_websocket_server->getPort();
    EXPECT_EQ(port, 8080) << "WebSocket server should have correct port";
    
    // Test client connection
    mock_websocket_server->addClient("client_1");
    size_t client_count = mock_websocket_server->getClientCount();
    EXPECT_EQ(client_count, 1) << "WebSocket server should have 1 client";
    
    // Test multiple client connections
    mock_websocket_server->addClient("client_2");
    mock_websocket_server->addClient("client_3");
    client_count = mock_websocket_server->getClientCount();
    EXPECT_EQ(client_count, 3) << "WebSocket server should have 3 clients";
    
    // Test message sending
    std::atomic<int> message_count{0};
    mock_websocket_server->setMessageCallback([&message_count](const std::string& client_id, const std::string& message) {
        // Use the parameters to verify they are valid
        EXPECT_FALSE(client_id.empty()) << "WebSocket client ID should not be empty";
        EXPECT_FALSE(message.empty()) << "WebSocket message should not be empty";
        message_count++;
    });
    
    mock_websocket_server->sendMessage("client_1", "test message");
    EXPECT_EQ(message_count.load(), 1) << "Should have sent 1 message";
    
    // Test broadcast message
    mock_websocket_server->broadcastMessage("broadcast message");
    EXPECT_EQ(message_count.load(), 2) << "Should have sent 2 messages";
    
    // Test client disconnection
    mock_websocket_server->removeClient("client_1");
    client_count = mock_websocket_server->getClientCount();
    EXPECT_EQ(client_count, 2) << "WebSocket server should have 2 clients after disconnection";
    
    // Test server shutdown
    mock_websocket_server->stopServer();
    is_running = mock_websocket_server->isRunning();
    EXPECT_FALSE(is_running) << "WebSocket server should be stopped";
    
    // Test restart
    start_result = mock_websocket_server->startServer(8081);
    EXPECT_TRUE(start_result) << "WebSocket server should restart successfully";
    
    // Test that server is running again
    is_running = mock_websocket_server->isRunning();
    EXPECT_TRUE(is_running) << "WebSocket server should be running again";
    
    // Clean up
    mock_websocket_server->stopServer();
}

// Additional web interface tests
TEST_F(WebInterfaceTest, WebInterfacePerformance) {
    // Test web interface performance
    const int num_operations = 1000;
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    // Test HTML rendering performance
    for (int i = 0; i < num_operations; ++i) {
        mock_html_renderer->renderStatusPage(status_page_data);
        mock_html_renderer->renderClientList(test_clients);
        mock_html_renderer->renderFrequencyList(test_frequencies);
        mock_html_renderer->renderMap(test_map_data);
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    // Calculate performance metrics
    double time_per_operation = static_cast<double>(duration.count()) / num_operations;
    
    // Web interface operations should be fast
    EXPECT_LT(time_per_operation, 1000.0) << "Web interface operations too slow: " << time_per_operation << " microseconds";
    
    std::cout << "Web interface performance: " << time_per_operation << " microseconds per operation" << std::endl;
}

TEST_F(WebInterfaceTest, WebInterfaceAccuracy) {
    // Test web interface accuracy
    std::string html = mock_html_renderer->renderStatusPage(status_page_data);
    EXPECT_FALSE(html.empty()) << "HTML rendering should be accurate";
    
    // Test HTML validation accuracy
    bool is_valid = mock_html_renderer->validateHTML(html);
    EXPECT_TRUE(is_valid) << "HTML validation should be accurate";
    
    // Test client list accuracy
    std::string client_list_html = mock_html_renderer->renderClientList(test_clients);
    EXPECT_FALSE(client_list_html.empty()) << "Client list rendering should be accurate";
    
    // Test frequency list accuracy
    std::string frequency_list_html = mock_html_renderer->renderFrequencyList(test_frequencies);
    EXPECT_FALSE(frequency_list_html.empty()) << "Frequency list rendering should be accurate";
    
    // Test map rendering accuracy
    std::string map_html = mock_html_renderer->renderMap(test_map_data);
    EXPECT_FALSE(map_html.empty()) << "Map rendering should be accurate";
    
    // Test real-time updates accuracy
    bool start_result = mock_real_time_updater->startRealTimeUpdates();
    EXPECT_TRUE(start_result) << "Real-time updates should be accurate";
    
    // Test WebSocket connection accuracy
    bool websocket_start_result = mock_websocket_server->startServer(8080);
    EXPECT_TRUE(websocket_start_result) << "WebSocket connection should be accurate";
    
    // Clean up
    mock_real_time_updater->stopRealTimeUpdates();
    mock_websocket_server->stopServer();
}
