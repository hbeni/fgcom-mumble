#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <thread>
#include <vector>
#include <chrono>
#include <memory>
#include <random>
#include <cmath>
#include <fstream>
#include <sstream>
#include <map>
#include <set>
#include <algorithm>
#include <numeric>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>

// Include the network modules
#include "../../client/mumble-plugin/lib/globalVars.h"
#include "../../client/mumble-plugin/lib/radio_model.h"
#include "../../client/mumble-plugin/lib/mumble/MumbleAPI_v_1_0_x.h"
#include "../../client/mumble-plugin/lib/mumble/MumblePlugin_v_1_0_x.h"
#include "../../client/mumble-plugin/lib/io_UDPClient.h"
#include "../../client/mumble-plugin/lib/io_plugin.h"


// Test fixtures and utilities
class Network_Module_Test : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize test parameters
        test_udp_port = 16661;
        test_websocket_port = 8080;
        test_rest_port = 8081;
        
        // Test packet sizes
        test_packet_size_small = 64;    // 64 bytes
        test_packet_size_medium = 512;  // 512 bytes
        test_packet_size_large = 1024; // 1024 bytes (max UDP packet size)
        
        // Test timeouts
        test_timeout_short = 100;  // 100ms
        test_timeout_medium = 1000; // 1s
        test_timeout_long = 5000;   // 5s
        
        // Test data
        test_message_simple = "LAT=40.7128,LON=-74.0060,ALT=100.5";
        test_message_complex = "LAT=40.7128,LON=-74.0060,ALT=100.5,COM1_FRQ=118.500,COM1_PTT=1,COM1_PWR=25.0,COM2_FRQ=121.900,COM2_PTT=0,COM2_PWR=25.0,VEHICLE_TYPE=aircraft,VEHICLE_NAME=Cessna_172,CALLSIGN=N123AB,PLAYER_ID=player_001";
        test_binary_data = std::vector<uint8_t>{0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x57, 0x6F, 0x72, 0x6C, 0x64};
        
        // Test API endpoints
        test_endpoint_radios = "/api/v1/radios";
        test_endpoint_vehicles = "/api/v1/vehicles";
        test_endpoint_status = "/api/v1/status";
        
        // Test authentication
        test_api_key = "test_api_key_12345";
        test_jwt_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0X3VzZXIiLCJpYXQiOjE1MTYyMzkwMjJ9.test_signature";
    }
    
    void TearDown() override {
        // Clean up after each test
    }
    
    // Test parameters
    int test_udp_port, test_websocket_port, test_rest_port;
    int test_packet_size_small, test_packet_size_medium, test_packet_size_large;
    int test_timeout_short, test_timeout_medium, test_timeout_long;
    std::string test_message_simple, test_message_complex;
    std::vector<uint8_t> test_binary_data;
    std::string test_endpoint_radios, test_endpoint_vehicles, test_endpoint_status;
    std::string test_api_key, test_jwt_token;
    
    // Helper functions for test data generation
    std::vector<uint8_t> generateRandomData(size_t size) {
        std::vector<uint8_t> data(size);
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 255);
        
        for (size_t i = 0; i < size; ++i) {
            data[i] = static_cast<uint8_t>(dis(gen));
        }
        return data;
    }
    
    std::string generateUDPMessage(const std::string& prefix = "LAT=40.7128,LON=-74.0060,ALT=100.5") {
        return prefix + "\n";
    }
    
    std::string generateWebSocketMessage(const std::string& type = "radio_transmission", const std::string& data = "{}") {
        return "{\"type\":\"" + type + "\",\"data\":" + data + "}";
    }
    
    std::string generateRESTRequest(const std::string& method = "GET", const std::string& endpoint = "/api/v1/status", const std::string& body = "") {
        std::string request = method + " " + endpoint + " HTTP/1.1\r\n";
        request += "Host: localhost\r\n";
        request += "Content-Type: application/json\r\n";
        if (!body.empty()) {
            request += "Content-Length: " + std::to_string(body.length()) + "\r\n";
        }
        request += "\r\n";
        if (!body.empty()) {
            request += body;
        }
        return request;
    }
    
    // Helper to create UDP socket
    int createUDPSocket() {
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) {
            return -1;
        }
        
        // Set socket to non-blocking
        int flags = fcntl(sock, F_GETFL, 0);
        fcntl(sock, F_SETFL, flags | O_NONBLOCK);
        
        return sock;
    }
    
    // Helper to create TCP socket
    int createTCPSocket() {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            return -1;
        }
        
        // Set socket to non-blocking
        int flags = fcntl(sock, F_GETFL, 0);
        fcntl(sock, F_SETFL, flags | O_NONBLOCK);
        
        return sock;
    }
    
    // Helper to bind socket to port
    bool bindSocket(int sock, int port) {
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(port);
        
        return bind(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0;
    }
    
    // Helper to send UDP packet
    bool sendUDPPacket(int sock, const std::string& message, const std::string& host = "127.0.0.1", int port = 16661) {
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        inet_pton(AF_INET, host.c_str(), &addr.sin_addr);
        
        ssize_t sent = sendto(sock, message.c_str(), message.length(), 0, (struct sockaddr*)&addr, sizeof(addr));
        return sent == static_cast<ssize_t>(message.length());
    }
    
    // Helper to receive UDP packet
    std::string receiveUDPPacket(int sock, int timeout_ms = 1000) {
        char buffer[1024];
        struct sockaddr_in addr;
        socklen_t addr_len = sizeof(addr);
        
        // Set timeout
        struct pollfd pfd;
        pfd.fd = sock;
        pfd.events = POLLIN;
        
        int result = poll(&pfd, 1, timeout_ms);
        if (result <= 0) {
            return "";
        }
        
        ssize_t received = recvfrom(sock, buffer, sizeof(buffer) - 1, 0, (struct sockaddr*)&addr, &addr_len);
        if (received <= 0) {
            return "";
        }
        
        buffer[received] = '\0';
        return std::string(buffer);
    }
    
    // Helper to measure execution time
    template<typename Func>
    auto measureTime(Func&& func) -> decltype(func()) {
        auto start = std::chrono::high_resolution_clock::now();
        auto result = func();
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        std::cout << "Execution time: " << duration.count() << " microseconds" << std::endl;
        return result;
    }
    
    // Helper to validate JSON
    bool isValidJSON(const std::string& json) {
        // Simple JSON validation (check for balanced braces and quotes)
        int brace_count = 0;
        int bracket_count = 0;
        bool in_string = false;
        bool escaped = false;
        
        for (char c : json) {
            if (escaped) {
                escaped = false;
                continue;
            }
            
            if (c == '\\') {
                escaped = true;
                continue;
            }
            
            if (c == '"' && !escaped) {
                in_string = !in_string;
                continue;
            }
            
            if (!in_string) {
                if (c == '{') brace_count++;
                else if (c == '}') brace_count--;
                else if (c == '[') bracket_count++;
                else if (c == ']') bracket_count--;
            }
        }
        
        return brace_count == 0 && bracket_count == 0 && !in_string;
    }
};

// Test suite for UDP protocol tests
class UDPProtocolTest : public Network_Module_Test {
protected:
    void SetUp() override {
        Network_Module_Test::SetUp();
    }
};

// Test suite for WebSocket tests
class WebSocketTest : public Network_Module_Test {
protected:
    void SetUp() override {
        Network_Module_Test::SetUp();
    }
};

// Test suite for RESTful API tests
class RESTfulAPITest : public Network_Module_Test {
protected:
    void SetUp() override {
        Network_Module_Test::SetUp();
    }
};


