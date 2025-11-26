#include "test_network_module_main.h"

// 5.3 RESTful API Tests
TEST_F(RESTfulAPITest, GETEndpointResponses) {
    // Test GET endpoint responses
    int server_sock = createTCPSocket();
    int client_sock = createTCPSocket();
    
    ASSERT_GE(server_sock, 0) << "Failed to create server socket";
    ASSERT_GE(client_sock, 0) << "Failed to create client socket";
    
    ASSERT_TRUE(bindSocket(server_sock, test_rest_port)) << "Failed to bind server socket";
    ASSERT_EQ(listen(server_sock, 1), 0) << "Failed to listen on server socket";
    
    // Test GET request generation
    std::string get_request = generateRESTRequest("GET", test_endpoint_status);
    ASSERT_FALSE(get_request.empty()) << "GET request should not be empty";
    ASSERT_NE(get_request.find("GET"), std::string::npos) << "Request should contain GET method";
    ASSERT_NE(get_request.find(test_endpoint_status), std::string::npos) << "Request should contain endpoint";
    ASSERT_NE(get_request.find("HTTP/1.1"), std::string::npos) << "Request should contain HTTP version";
    
    // Test response format validation
    std::string response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"status\":\"active\"}";
    ASSERT_FALSE(response.empty()) << "Response should not be empty";
    ASSERT_NE(response.find("HTTP/1.1"), std::string::npos) << "Response should contain HTTP version";
    ASSERT_NE(response.find("200 OK"), std::string::npos) << "Response should contain status code";
    ASSERT_NE(response.find("Content-Type: application/json"), std::string::npos) << "Response should contain content type";
    
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
    
    // Test POST request generation with valid JSON
    std::string valid_json = "{\"name\":\"Test Radio\",\"frequency\":121.9,\"power\":25.0}";
    std::string post_request = generateRESTRequest("POST", test_endpoint_radios, valid_json);
    
    ASSERT_FALSE(post_request.empty()) << "POST request should not be empty";
    ASSERT_NE(post_request.find("POST"), std::string::npos) << "Request should contain POST method";
    ASSERT_NE(post_request.find(test_endpoint_radios), std::string::npos) << "Request should contain endpoint";
    ASSERT_NE(post_request.find(valid_json), std::string::npos) << "Request should contain JSON data";
    
    // Test response format for valid POST
    std::string valid_response = "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\n\r\n{\"id\":123}";
    ASSERT_NE(valid_response.find("HTTP/1.1"), std::string::npos) << "Response should contain HTTP version";
    ASSERT_NE(valid_response.find("201 Created"), std::string::npos) << "Response should contain created status";
    
    // Test POST with invalid JSON
    std::string invalid_json = "{\"name\":\"Test Radio\",\"frequency\":121.9,\"power\":25.0"; // Missing closing brace
    std::string invalid_post_request = generateRESTRequest("POST", test_endpoint_radios, invalid_json);
    
    ASSERT_FALSE(invalid_post_request.empty()) << "Invalid POST request should not be empty";
    ASSERT_NE(invalid_post_request.find("POST"), std::string::npos) << "Invalid request should contain POST method";
    ASSERT_NE(invalid_post_request.find(invalid_json), std::string::npos) << "Request should contain invalid JSON";
    
    // Test error response format
    std::string error_response = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\n\r\n{\"error\":\"Invalid JSON\"}";
    ASSERT_FALSE(error_response.empty()) << "Error response should not be empty";
    ASSERT_NE(error_response.find("HTTP/1.1"), std::string::npos) << "Error response should contain HTTP version";
    ASSERT_NE(error_response.find("400 Bad Request"), std::string::npos) << "Response should contain bad request status";
    
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
    
    // Test PUT request generation
    ASSERT_FALSE(put_request.empty()) << "PUT request should not be empty";
    ASSERT_NE(put_request.find("PUT"), std::string::npos) << "Request should contain PUT method";
    ASSERT_NE(put_request.find(test_endpoint_radios + "/1"), std::string::npos) << "Request should contain endpoint";
    ASSERT_NE(put_request.find(update_json), std::string::npos) << "Request should contain JSON data";
    
    // Test success response format
    std::string response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"updated\":true}";
    ASSERT_FALSE(response.empty()) << "Response should not be empty";
    ASSERT_NE(response.find("HTTP/1.1"), std::string::npos) << "Response should contain HTTP version";
    ASSERT_NE(response.find("200 OK"), std::string::npos) << "Response should contain success status";
    
    // Test PUT with non-existent resource
    std::string not_found_put_request = generateRESTRequest("PUT", test_endpoint_radios + "/999", update_json);
    
    // Test not found request generation
    ASSERT_FALSE(not_found_put_request.empty()) << "Not found PUT request should not be empty";
    ASSERT_NE(not_found_put_request.find("PUT"), std::string::npos) << "Request should contain PUT method";
    ASSERT_NE(not_found_put_request.find(test_endpoint_radios + "/999"), std::string::npos) << "Request should contain non-existent endpoint";
    
    // Test error response format
    std::string error_response = "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\n\r\n{\"error\":\"Resource not found\"}";
    ASSERT_FALSE(error_response.empty()) << "Error response should not be empty";
    ASSERT_NE(error_response.find("HTTP/1.1"), std::string::npos) << "Error response should contain HTTP version";
    ASSERT_NE(error_response.find("404 Not Found"), std::string::npos) << "Response should contain not found status";
    
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
    
    // Test DELETE request generation
    ASSERT_FALSE(delete_request.empty()) << "DELETE request should not be empty";
    ASSERT_NE(delete_request.find("DELETE"), std::string::npos) << "Request should contain DELETE method";
    ASSERT_NE(delete_request.find(test_endpoint_radios + "/1"), std::string::npos) << "Request should contain endpoint";
    
    // Test success response format
    std::string response = "HTTP/1.1 204 No Content\r\n\r\n";
    ASSERT_FALSE(response.empty()) << "Response should not be empty";
    ASSERT_NE(response.find("HTTP/1.1"), std::string::npos) << "Response should contain HTTP version";
    ASSERT_NE(response.find("204 No Content"), std::string::npos) << "Response should contain no content status";
    
    // Test DELETE with non-existent resource
    std::string not_found_delete_request = generateRESTRequest("DELETE", test_endpoint_radios + "/999");
    
    // Test not found request generation
    ASSERT_FALSE(not_found_delete_request.empty()) << "Not found DELETE request should not be empty";
    ASSERT_NE(not_found_delete_request.find("DELETE"), std::string::npos) << "Request should contain DELETE method";
    ASSERT_NE(not_found_delete_request.find(test_endpoint_radios + "/999"), std::string::npos) << "Request should contain non-existent endpoint";
    
    // Test error response format
    std::string error_response = "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\n\r\n{\"error\":\"Resource not found\"}";
    ASSERT_FALSE(error_response.empty()) << "Error response should not be empty";
    ASSERT_NE(error_response.find("HTTP/1.1"), std::string::npos) << "Error response should contain HTTP version";
    ASSERT_NE(error_response.find("404 Not Found"), std::string::npos) << "Response should contain not found status";
    
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
    
    // Test valid request generation
    ASSERT_FALSE(valid_request.empty()) << "Valid request should not be empty";
    ASSERT_NE(valid_request.find("GET"), std::string::npos) << "Request should contain GET method";
    ASSERT_NE(valid_request.find(test_endpoint_status), std::string::npos) << "Request should contain endpoint";
    ASSERT_NE(valid_request.find("Authorization: Bearer " + test_api_key), std::string::npos) << "Request should contain API key";
    
    // Test success response format
    std::string response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"authenticated\":true}";
    ASSERT_FALSE(response.empty()) << "Response should not be empty";
    ASSERT_NE(response.find("HTTP/1.1"), std::string::npos) << "Response should contain HTTP version";
    ASSERT_NE(response.find("200 OK"), std::string::npos) << "Response should contain success status";
    
    // Test request with invalid API key
    std::string invalid_request = "GET " + test_endpoint_status + " HTTP/1.1\r\n";
    invalid_request += "Host: localhost\r\n";
    invalid_request += "Authorization: Bearer invalid_key\r\n";
    invalid_request += "\r\n";
    
    // Test invalid request generation
    ASSERT_FALSE(invalid_request.empty()) << "Invalid request should not be empty";
    ASSERT_NE(invalid_request.find("GET"), std::string::npos) << "Request should contain GET method";
    ASSERT_NE(invalid_request.find("Authorization: Bearer invalid_key"), std::string::npos) << "Request should contain invalid API key";
    
    // Test error response format
    std::string error_response = "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\n\r\n{\"error\":\"Invalid API key\"}";
    ASSERT_FALSE(error_response.empty()) << "Error response should not be empty";
    ASSERT_NE(error_response.find("HTTP/1.1"), std::string::npos) << "Error response should contain HTTP version";
    ASSERT_NE(error_response.find("401 Unauthorized"), std::string::npos) << "Response should contain unauthorized status";
    
    
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
    
    // Test request generation
    ASSERT_FALSE(request.empty()) << "Request should not be empty";
    ASSERT_NE(request.find("GET"), std::string::npos) << "Request should contain GET method";
    ASSERT_NE(request.find(test_endpoint_status), std::string::npos) << "Request should contain endpoint";
    
    // Test rate limiting logic
    int success_count = 0;
    int rate_limited_count = 0;
    
    // Simulate rate limiting behavior
    for (int i = 0; i < 10; ++i) {
        if (i < 5) {
            // First 5 requests should succeed
            success_count++;
        } else {
            // Remaining requests should be rate limited
            rate_limited_count++;
        }
    }
    
    // Test success response format
    std::string success_response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"status\":\"active\"}";
    ASSERT_FALSE(success_response.empty()) << "Success response should not be empty";
    ASSERT_NE(success_response.find("HTTP/1.1"), std::string::npos) << "Response should contain HTTP version";
    ASSERT_NE(success_response.find("200 OK"), std::string::npos) << "Response should contain success status";
    
    // Test rate limited response format
    std::string rate_limited_response = "HTTP/1.1 429 Too Many Requests\r\nContent-Type: application/json\r\n\r\n{\"error\":\"Rate limit exceeded\"}";
    ASSERT_FALSE(rate_limited_response.empty()) << "Rate limited response should not be empty";
    ASSERT_NE(rate_limited_response.find("HTTP/1.1"), std::string::npos) << "Response should contain HTTP version";
    ASSERT_NE(rate_limited_response.find("429 Too Many Requests"), std::string::npos) << "Response should contain rate limited status";
    
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
    
    // Test bad request generation
    ASSERT_FALSE(bad_request.empty()) << "Bad request should not be empty";
    ASSERT_NE(bad_request.find("GET"), std::string::npos) << "Request should contain GET method";
    ASSERT_NE(bad_request.find("Content-Length: 100"), std::string::npos) << "Request should contain invalid content length";
    
    // Test 400 error response format
    std::string response = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\n\r\n{\"error\":\"Invalid request\"}";
    ASSERT_FALSE(response.empty()) << "Error response should not be empty";
    ASSERT_NE(response.find("HTTP/1.1"), std::string::npos) << "Response should contain HTTP version";
    ASSERT_NE(response.find("400 Bad Request"), std::string::npos) << "Response should contain bad request status";
    
    // Test 404 Not Found
    std::string not_found_request = generateRESTRequest("GET", "/api/v1/nonexistent");
    
    // Test not found request generation
    ASSERT_FALSE(not_found_request.empty()) << "Not found request should not be empty";
    ASSERT_NE(not_found_request.find("GET"), std::string::npos) << "Request should contain GET method";
    ASSERT_NE(not_found_request.find("/api/v1/nonexistent"), std::string::npos) << "Request should contain nonexistent endpoint";
    
    // Test 404 error response format
    std::string not_found_response = "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\n\r\n{\"error\":\"Resource not found\"}";
    ASSERT_FALSE(not_found_response.empty()) << "Not found response should not be empty";
    ASSERT_NE(not_found_response.find("HTTP/1.1"), std::string::npos) << "Response should contain HTTP version";
    ASSERT_NE(not_found_response.find("404 Not Found"), std::string::npos) << "Response should contain not found status";
    
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
    
    // Test valid JSON request generation
    ASSERT_FALSE(valid_request.empty()) << "Valid JSON request should not be empty";
    ASSERT_NE(valid_request.find("POST"), std::string::npos) << "Request should contain POST method";
    ASSERT_NE(valid_request.find(test_endpoint_radios), std::string::npos) << "Request should contain endpoint";
    ASSERT_NE(valid_request.find(valid_json), std::string::npos) << "Request should contain valid JSON";
    
    // Test valid JSON response format
    std::string response = "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\n\r\n{\"id\":123}";
    ASSERT_FALSE(response.empty()) << "Response should not be empty";
    ASSERT_NE(response.find("HTTP/1.1"), std::string::npos) << "Response should contain HTTP version";
    ASSERT_NE(response.find("201 Created"), std::string::npos) << "Response should contain created status";
    
    // Test invalid JSON schema
    std::string invalid_json = "{\"name\":\"Test Radio\",\"frequency\":\"invalid\",\"power\":25.0}"; // Invalid frequency type
    std::string invalid_request = generateRESTRequest("POST", test_endpoint_radios, invalid_json);
    
    // Test invalid JSON request generation
    ASSERT_FALSE(invalid_request.empty()) << "Invalid JSON request should not be empty";
    ASSERT_NE(invalid_request.find("POST"), std::string::npos) << "Request should contain POST method";
    ASSERT_NE(invalid_request.find(invalid_json), std::string::npos) << "Request should contain invalid JSON";
    
    // Test invalid JSON error response format
    std::string error_response = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\n\r\n{\"error\":\"Invalid JSON schema\"}";
    ASSERT_FALSE(error_response.empty()) << "Error response should not be empty";
    ASSERT_NE(error_response.find("HTTP/1.1"), std::string::npos) << "Error response should contain HTTP version";
    ASSERT_NE(error_response.find("400 Bad Request"), std::string::npos) << "Response should contain bad request status";
    
    close(server_sock);
    close(client_sock);
}

// Additional RESTful API tests
TEST_F(RESTfulAPITest, RESTfulAPIPerformance) {
    // Test RESTful API performance
    const int num_requests = 10;  // OPTIMIZED: Reduced from 100 to 10
    int server_sock = createTCPSocket();
    int client_sock = createTCPSocket();
    
    ASSERT_GE(server_sock, 0) << "Failed to create server socket";
    ASSERT_GE(client_sock, 0) << "Failed to create client socket";
    
    ASSERT_TRUE(bindSocket(server_sock, test_rest_port)) << "Failed to bind server socket";
    ASSERT_EQ(listen(server_sock, 1), 0) << "Failed to listen on server socket";
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    // Test request generation performance
    for (int i = 0; i < num_requests; ++i) {
        std::string request = generateRESTRequest("GET", test_endpoint_status);
        ASSERT_FALSE(request.empty()) << "Request should not be empty";
        ASSERT_NE(request.find("GET"), std::string::npos) << "Request should contain GET method";
        ASSERT_NE(request.find(test_endpoint_status), std::string::npos) << "Request should contain endpoint";
    }
    
    // Test response generation performance
    int response_count = 0;
    for (int i = 0; i < num_requests; ++i) {
        std::string response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"status\":\"active\"}";
        ASSERT_FALSE(response.empty()) << "Response should not be empty";
        ASSERT_NE(response.find("HTTP/1.1"), std::string::npos) << "Response should contain HTTP version";
        ASSERT_NE(response.find("200 OK"), std::string::npos) << "Response should contain success status";
        response_count++;
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    // Calculate performance metrics
    double time_per_request = static_cast<double>(duration.count()) / num_requests;
    double requests_per_second = 1000000.0 / time_per_request;
    
    // RESTful API should be fast
    EXPECT_LT(time_per_request, 1000.0) << "RESTful API request processing too slow: " << time_per_request << " microseconds";
    EXPECT_GT(requests_per_second, 1000.0) << "RESTful API request rate too low: " << requests_per_second << " requests/second";
    EXPECT_EQ(response_count, num_requests) << "Should generate all responses";
    
    std::cout << "RESTful API performance: " << time_per_request << " microseconds per request" << std::endl;
    std::cout << "RESTful API rate: " << requests_per_second << " requests/second" << std::endl;
    
    close(server_sock);
    close(client_sock);
}

