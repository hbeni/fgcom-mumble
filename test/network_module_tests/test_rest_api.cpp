#include "test_network_module_main.cpp"

// 5.3 RESTful API Tests
TEST_F(RESTfulAPITest, GETEndpointResponses) {
    // Test GET endpoint responses
    int server_sock = createTCPSocket();
    int client_sock = createTCPSocket();
    
    ASSERT_GE(server_sock, 0) << "Failed to create server socket";
    ASSERT_GE(client_sock, 0) << "Failed to create client socket";
    
    ASSERT_TRUE(bindSocket(server_sock, test_rest_port)) << "Failed to bind server socket";
    ASSERT_EQ(listen(server_sock, 1), 0) << "Failed to listen on server socket";
    
    // Test GET /api/v1/status
    std::string get_request = generateRESTRequest("GET", test_endpoint_status);
    
    // Send GET request
    ssize_t sent = send(client_sock, get_request.c_str(), get_request.length(), 0);
    ASSERT_EQ(sent, static_cast<ssize_t>(get_request.length())) << "Failed to send GET request";
    
    // Receive response
    char buffer[1024];
    ssize_t received = recv(server_sock, buffer, sizeof(buffer) - 1, 0);
    ASSERT_GT(received, 0) << "Failed to receive GET response";
    
    buffer[received] = '\0';
    std::string response(buffer);
    
    // Test response format
    ASSERT_TRUE(response.find("HTTP/1.1") != std::string::npos) << "Response should contain HTTP version";
    ASSERT_TRUE(response.find("200 OK") != std::string::npos) << "Response should contain status code";
    ASSERT_TRUE(response.find("Content-Type: application/json") != std::string::npos) << "Response should contain content type";
    
    close(server_sock);
    close(client_sock);
}

TEST_F(RESTfulAPITest, POSTDataValidation) {
    // Test POST data validation
    int server_sock = createTCPSocket();
    int client_sock = createTCPSocket();
    
    ASSERT_GE(server_sock, 0) << "Failed to create server socket";
    ASSERT_GE(client_sock, 0) << "Failed to create client socket";
    
    ASSERT_TRUE(bindSocket(server_sock, test_rest_port)) << "Failed to bind server socket";
    ASSERT_EQ(listen(server_sock, 1), 0) << "Failed to listen on server socket";
    
    // Test POST with valid JSON
    std::string valid_json = "{\"name\":\"Test Radio\",\"frequency\":121.9,\"power\":25.0}";
    std::string post_request = generateRESTRequest("POST", test_endpoint_radios, valid_json);
    
    // Send POST request
    ssize_t sent = send(client_sock, post_request.c_str(), post_request.length(), 0);
    ASSERT_EQ(sent, static_cast<ssize_t>(post_request.length())) << "Failed to send POST request";
    
    // Receive response
    char buffer[1024];
    ssize_t received = recv(server_sock, buffer, sizeof(buffer) - 1, 0);
    ASSERT_GT(received, 0) << "Failed to receive POST response";
    
    buffer[received] = '\0';
    std::string response(buffer);
    
    // Test response format
    ASSERT_TRUE(response.find("HTTP/1.1") != std::string::npos) << "Response should contain HTTP version";
    ASSERT_TRUE(response.find("201 Created") != std::string::npos) << "Response should contain created status";
    
    // Test POST with invalid JSON
    std::string invalid_json = "{\"name\":\"Test Radio\",\"frequency\":121.9,\"power\":25.0"; // Missing closing brace
    std::string invalid_post_request = generateRESTRequest("POST", test_endpoint_radios, invalid_json);
    
    // Send invalid POST request
    sent = send(client_sock, invalid_post_request.c_str(), invalid_post_request.length(), 0);
    ASSERT_EQ(sent, static_cast<ssize_t>(invalid_post_request.length())) << "Failed to send invalid POST request";
    
    // Receive error response
    received = recv(server_sock, buffer, sizeof(buffer) - 1, 0);
    ASSERT_GT(received, 0) << "Failed to receive error response";
    
    buffer[received] = '\0';
    std::string error_response(buffer);
    
    // Test error response format
    ASSERT_TRUE(error_response.find("400 Bad Request") != std::string::npos) << "Response should contain bad request status";
    
    close(server_sock);
    close(client_sock);
}

TEST_F(RESTfulAPITest, PUTUpdateOperations) {
    // Test PUT update operations
    int server_sock = createTCPSocket();
    int client_sock = createTCPSocket();
    
    ASSERT_GE(server_sock, 0) << "Failed to create server socket";
    ASSERT_GE(client_sock, 0) << "Failed to create client socket";
    
    ASSERT_TRUE(bindSocket(server_sock, test_rest_port)) << "Failed to bind server socket";
    ASSERT_EQ(listen(server_sock, 1), 0) << "Failed to listen on server socket";
    
    // Test PUT with valid data
    std::string update_json = "{\"name\":\"Updated Radio\",\"frequency\":121.9,\"power\":50.0}";
    std::string put_request = generateRESTRequest("PUT", test_endpoint_radios + "/1", update_json);
    
    // Send PUT request
    ssize_t sent = send(client_sock, put_request.c_str(), put_request.length(), 0);
    ASSERT_EQ(sent, static_cast<ssize_t>(put_request.length())) << "Failed to send PUT request";
    
    // Receive response
    char buffer[1024];
    ssize_t received = recv(server_sock, buffer, sizeof(buffer) - 1, 0);
    ASSERT_GT(received, 0) << "Failed to receive PUT response";
    
    buffer[received] = '\0';
    std::string response(buffer);
    
    // Test response format
    ASSERT_TRUE(response.find("HTTP/1.1") != std::string::npos) << "Response should contain HTTP version";
    ASSERT_TRUE(response.find("200 OK") != std::string::npos) << "Response should contain success status";
    
    // Test PUT with non-existent resource
    std::string not_found_put_request = generateRESTRequest("PUT", test_endpoint_radios + "/999", update_json);
    
    // Send PUT request for non-existent resource
    sent = send(client_sock, not_found_put_request.c_str(), not_found_put_request.length(), 0);
    ASSERT_EQ(sent, static_cast<ssize_t>(not_found_put_request.length())) << "Failed to send PUT request for non-existent resource";
    
    // Receive error response
    received = recv(server_sock, buffer, sizeof(buffer) - 1, 0);
    ASSERT_GT(received, 0) << "Failed to receive error response";
    
    buffer[received] = '\0';
    std::string error_response(buffer);
    
    // Test error response format
    ASSERT_TRUE(error_response.find("404 Not Found") != std::string::npos) << "Response should contain not found status";
    
    close(server_sock);
    close(client_sock);
}

TEST_F(RESTfulAPITest, DELETEOperations) {
    // Test DELETE operations
    int server_sock = createTCPSocket();
    int client_sock = createTCPSocket();
    
    ASSERT_GE(server_sock, 0) << "Failed to create server socket";
    ASSERT_GE(client_sock, 0) << "Failed to create client socket";
    
    ASSERT_TRUE(bindSocket(server_sock, test_rest_port)) << "Failed to bind server socket";
    ASSERT_EQ(listen(server_sock, 1), 0) << "Failed to listen on server socket";
    
    // Test DELETE with existing resource
    std::string delete_request = generateRESTRequest("DELETE", test_endpoint_radios + "/1");
    
    // Send DELETE request
    ssize_t sent = send(client_sock, delete_request.c_str(), delete_request.length(), 0);
    ASSERT_EQ(sent, static_cast<ssize_t>(delete_request.length())) << "Failed to send DELETE request";
    
    // Receive response
    char buffer[1024];
    ssize_t received = recv(server_sock, buffer, sizeof(buffer) - 1, 0);
    ASSERT_GT(received, 0) << "Failed to receive DELETE response";
    
    buffer[received] = '\0';
    std::string response(buffer);
    
    // Test response format
    ASSERT_TRUE(response.find("HTTP/1.1") != std::string::npos) << "Response should contain HTTP version";
    ASSERT_TRUE(response.find("204 No Content") != std::string::npos) << "Response should contain no content status";
    
    // Test DELETE with non-existent resource
    std::string not_found_delete_request = generateRESTRequest("DELETE", test_endpoint_radios + "/999");
    
    // Send DELETE request for non-existent resource
    sent = send(client_sock, not_found_delete_request.c_str(), not_found_delete_request.length(), 0);
    ASSERT_EQ(sent, static_cast<ssize_t>(not_found_delete_request.length())) << "Failed to send DELETE request for non-existent resource";
    
    // Receive error response
    received = recv(server_sock, buffer, sizeof(buffer) - 1, 0);
    ASSERT_GT(received, 0) << "Failed to receive error response";
    
    buffer[received] = '\0';
    std::string error_response(buffer);
    
    // Test error response format
    ASSERT_TRUE(error_response.find("404 Not Found") != std::string::npos) << "Response should contain not found status";
    
    close(server_sock);
    close(client_sock);
}

TEST_F(RESTfulAPITest, AuthenticationAPIKeys) {
    // Test authentication with API keys
    int server_sock = createTCPSocket();
    int client_sock = createTCPSocket();
    
    ASSERT_GE(server_sock, 0) << "Failed to create server socket";
    ASSERT_GE(client_sock, 0) << "Failed to create client socket";
    
    ASSERT_TRUE(bindSocket(server_sock, test_rest_port)) << "Failed to bind server socket";
    ASSERT_EQ(listen(server_sock, 1), 0) << "Failed to listen on server socket";
    
    // Test request with valid API key
    std::string valid_request = "GET " + test_endpoint_status + " HTTP/1.1\r\n";
    valid_request += "Host: localhost\r\n";
    valid_request += "Authorization: Bearer " + test_api_key + "\r\n";
    valid_request += "\r\n";
    
    // Send request with valid API key
    ssize_t sent = send(client_sock, valid_request.c_str(), valid_request.length(), 0);
    ASSERT_EQ(sent, static_cast<ssize_t>(valid_request.length())) << "Failed to send request with valid API key";
    
    // Receive response
    char buffer[1024];
    ssize_t received = recv(server_sock, buffer, sizeof(buffer) - 1, 0);
    ASSERT_GT(received, 0) << "Failed to receive response";
    
    buffer[received] = '\0';
    std::string response(buffer);
    
    // Test response format
    ASSERT_TRUE(response.find("HTTP/1.1") != std::string::npos) << "Response should contain HTTP version";
    ASSERT_TRUE(response.find("200 OK") != std::string::npos) << "Response should contain success status";
    
    // Test request with invalid API key
    std::string invalid_request = "GET " + test_endpoint_status + " HTTP/1.1\r\n";
    invalid_request += "Host: localhost\r\n";
    invalid_request += "Authorization: Bearer invalid_key\r\n";
    invalid_request += "\r\n";
    
    // Send request with invalid API key
    sent = send(client_sock, invalid_request.c_str(), invalid_request.length(), 0);
    ASSERT_EQ(sent, static_cast<ssize_t>(invalid_request.length())) << "Failed to send request with invalid API key";
    
    // Receive error response
    received = recv(server_sock, buffer, sizeof(buffer) - 1, 0);
    ASSERT_GT(received, 0) << "Failed to receive error response";
    
    buffer[received] = '\0';
    std::string error_response(buffer);
    
    // Test error response format
    ASSERT_TRUE(error_response.find("401 Unauthorized") != std::string::npos) << "Response should contain unauthorized status";
    
    close(server_sock);
    close(client_sock);
}

TEST_F(RESTfulAPITest, RateLimiting) {
    // Test rate limiting
    int server_sock = createTCPSocket();
    int client_sock = createTCPSocket();
    
    ASSERT_GE(server_sock, 0) << "Failed to create server socket";
    ASSERT_GE(client_sock, 0) << "Failed to create client socket";
    
    ASSERT_TRUE(bindSocket(server_sock, test_rest_port)) << "Failed to bind server socket";
    ASSERT_EQ(listen(server_sock, 1), 0) << "Failed to listen on server socket";
    
    // Test rate limiting with multiple requests
    std::string request = generateRESTRequest("GET", test_endpoint_status);
    
    // Send multiple requests quickly
    for (int i = 0; i < 10; ++i) {
        ssize_t sent = send(client_sock, request.c_str(), request.length(), 0);
        ASSERT_EQ(sent, static_cast<ssize_t>(request.length())) << "Failed to send request " << i;
    }
    
    // Receive responses
    int success_count = 0;
    int rate_limited_count = 0;
    char buffer[1024];
    
    for (int i = 0; i < 10; ++i) {
        ssize_t received = recv(server_sock, buffer, sizeof(buffer) - 1, 0);
        if (received > 0) {
            buffer[received] = '\0';
            std::string response(buffer);
            
            if (response.find("200 OK") != std::string::npos) {
                success_count++;
            } else if (response.find("429 Too Many Requests") != std::string::npos) {
                rate_limited_count++;
            }
        }
    }
    
    // Should have some successful requests and some rate limited
    ASSERT_GT(success_count, 0) << "Should have some successful requests";
    ASSERT_GT(rate_limited_count, 0) << "Should have some rate limited requests";
    
    close(server_sock);
    close(client_sock);
}

TEST_F(RESTfulAPITest, ErrorResponseCodes) {
    // Test error response codes
    int server_sock = createTCPSocket();
    int client_sock = createTCPSocket();
    
    ASSERT_GE(server_sock, 0) << "Failed to create server socket";
    ASSERT_GE(client_sock, 0) << "Failed to create client socket";
    
    ASSERT_TRUE(bindSocket(server_sock, test_rest_port)) << "Failed to bind server socket";
    ASSERT_EQ(listen(server_sock, 1), 0) << "Failed to listen on server socket";
    
    // Test 400 Bad Request
    std::string bad_request = "GET " + test_endpoint_status + " HTTP/1.1\r\n";
    bad_request += "Host: localhost\r\n";
    bad_request += "Content-Length: 100\r\n"; // Invalid content length
    bad_request += "\r\n";
    
    ssize_t sent = send(client_sock, bad_request.c_str(), bad_request.length(), 0);
    ASSERT_EQ(sent, static_cast<ssize_t>(bad_request.length())) << "Failed to send bad request";
    
    char buffer[1024];
    ssize_t received = recv(server_sock, buffer, sizeof(buffer) - 1, 0);
    ASSERT_GT(received, 0) << "Failed to receive error response";
    
    buffer[received] = '\0';
    std::string response(buffer);
    
    ASSERT_TRUE(response.find("400 Bad Request") != std::string::npos) << "Response should contain bad request status";
    
    // Test 404 Not Found
    std::string not_found_request = generateRESTRequest("GET", "/api/v1/nonexistent");
    
    sent = send(client_sock, not_found_request.c_str(), not_found_request.length(), 0);
    ASSERT_EQ(sent, static_cast<ssize_t>(not_found_request.length())) << "Failed to send not found request";
    
    received = recv(server_sock, buffer, sizeof(buffer) - 1, 0);
    ASSERT_GT(received, 0) << "Failed to receive error response";
    
    buffer[received] = '\0';
    std::string not_found_response(buffer);
    
    ASSERT_TRUE(not_found_response.find("404 Not Found") != std::string::npos) << "Response should contain not found status";
    
    close(server_sock);
    close(client_sock);
}

TEST_F(RESTfulAPITest, JSONSchemaValidation) {
    // Test JSON schema validation
    int server_sock = createTCPSocket();
    int client_sock = createTCPSocket();
    
    ASSERT_GE(server_sock, 0) << "Failed to create server socket";
    ASSERT_GE(client_sock, 0) << "Failed to create client socket";
    
    ASSERT_TRUE(bindSocket(server_sock, test_rest_port)) << "Failed to bind server socket";
    ASSERT_EQ(listen(server_sock, 1), 0) << "Failed to listen on server socket";
    
    // Test valid JSON schema
    std::string valid_json = "{\"name\":\"Test Radio\",\"frequency\":121.9,\"power\":25.0}";
    std::string valid_request = generateRESTRequest("POST", test_endpoint_radios, valid_json);
    
    ssize_t sent = send(client_sock, valid_request.c_str(), valid_request.length(), 0);
    ASSERT_EQ(sent, static_cast<ssize_t>(valid_request.length())) << "Failed to send valid JSON request";
    
    char buffer[1024];
    ssize_t received = recv(server_sock, buffer, sizeof(buffer) - 1, 0);
    ASSERT_GT(received, 0) << "Failed to receive response";
    
    buffer[received] = '\0';
    std::string response(buffer);
    
    ASSERT_TRUE(response.find("201 Created") != std::string::npos) << "Response should contain created status";
    
    // Test invalid JSON schema
    std::string invalid_json = "{\"name\":\"Test Radio\",\"frequency\":\"invalid\",\"power\":25.0}"; // Invalid frequency type
    std::string invalid_request = generateRESTRequest("POST", test_endpoint_radios, invalid_json);
    
    sent = send(client_sock, invalid_request.c_str(), invalid_request.length(), 0);
    ASSERT_EQ(sent, static_cast<ssize_t>(invalid_request.length())) << "Failed to send invalid JSON request";
    
    received = recv(server_sock, buffer, sizeof(buffer) - 1, 0);
    ASSERT_GT(received, 0) << "Failed to receive error response";
    
    buffer[received] = '\0';
    std::string error_response(buffer);
    
    ASSERT_TRUE(error_response.find("400 Bad Request") != std::string::npos) << "Response should contain bad request status";
    
    close(server_sock);
    close(client_sock);
}

// Additional RESTful API tests
TEST_F(RESTfulAPITest, RESTfulAPIPerformance) {
    // Test RESTful API performance
    const int num_requests = 100;
    int server_sock = createTCPSocket();
    int client_sock = createTCPSocket();
    
    ASSERT_GE(server_sock, 0) << "Failed to create server socket";
    ASSERT_GE(client_sock, 0) << "Failed to create client socket";
    
    ASSERT_TRUE(bindSocket(server_sock, test_rest_port)) << "Failed to bind server socket";
    ASSERT_EQ(listen(server_sock, 1), 0) << "Failed to listen on server socket";
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    // Send requests
    for (int i = 0; i < num_requests; ++i) {
        std::string request = generateRESTRequest("GET", test_endpoint_status);
        ssize_t sent = send(client_sock, request.c_str(), request.length(), 0);
        ASSERT_EQ(sent, static_cast<ssize_t>(request.length())) << "Failed to send request " << i;
    }
    
    // Receive responses
    int received_count = 0;
    char buffer[1024];
    for (int i = 0; i < num_requests; ++i) {
        ssize_t received = recv(server_sock, buffer, sizeof(buffer) - 1, 0);
        if (received > 0) {
            received_count++;
        }
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    // Calculate performance metrics
    double time_per_request = static_cast<double>(duration.count()) / num_requests;
    double requests_per_second = 1000000.0 / time_per_request;
    
    // RESTful API should be fast
    EXPECT_LT(time_per_request, 1000.0) << "RESTful API request processing too slow: " << time_per_request << " microseconds";
    EXPECT_GT(requests_per_second, 1000.0) << "RESTful API request rate too low: " << requests_per_second << " requests/second";
    
    std::cout << "RESTful API performance: " << time_per_request << " microseconds per request" << std::endl;
    std::cout << "RESTful API rate: " << requests_per_second << " requests/second" << std::endl;
    
    close(server_sock);
    close(client_sock);
}

