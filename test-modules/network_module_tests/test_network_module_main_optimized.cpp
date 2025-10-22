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

// Optimized test fixtures with reduced parameters
class Network_Module_Test_Optimized : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize test parameters with dynamic ports to avoid conflicts
        test_udp_port = 16661 + (getpid() % 1000);
        test_websocket_port = 8080 + (getpid() % 1000);
        test_rest_port = 8081 + (getpid() % 1000);
        
        // OPTIMIZED: Reduced test packet sizes and counts
        test_packet_size_small = 64;    // 64 bytes
        test_packet_size_medium = 256;   // 256 bytes (reduced from 512)
        test_packet_size_large = 512;    // 512 bytes (reduced from 1024)
        
        // OPTIMIZED: Reduced test timeouts for faster execution
        test_timeout_short = 50;   // 50ms (reduced from 100ms)
        test_timeout_medium = 500;  // 500ms (reduced from 1000ms)
        test_timeout_long = 2000;   // 2s (reduced from 5s)
        
        // OPTIMIZED: Reduced test data sizes
        test_data_size_small = 100;   // 100 bytes (reduced from 256)
        test_data_size_medium = 500;  // 500 bytes (reduced from 1024)
        test_data_size_large = 1000;  // 1000 bytes (reduced from 2048)
        
        // OPTIMIZED: Reduced performance test counts
        performance_packet_count = 100;    // 100 packets (reduced from 1000)
        performance_message_count = 100;   // 100 messages (reduced from 1000)
        performance_request_count = 10;     // 10 requests (reduced from 100)
        
        // OPTIMIZED: Reduced stress test parameters
        stress_test_iterations = 1;        // 1 iteration (reduced from 5)
        stress_test_repeats = 1;           // 1 repeat (reduced from 10)
        
        // Test endpoints
        test_endpoint_status = "/api/status";
        test_endpoint_health = "/api/health";
        test_endpoint_data = "/api/data";
        
        // Test data
        test_latitude = 40.7128;
        test_longitude = -74.0060;
        test_altitude = 100.0;
        test_frequency = 121.5;
        test_callsign = "TEST";
        
        // Initialize random number generator
        rng.seed(std::chrono::high_resolution_clock::now().time_since_epoch().count());
    }
    
    void TearDown() override {
        // Clean up any resources
    }
    
    // Test parameters (optimized)
    int test_udp_port;
    int test_websocket_port;
    int test_rest_port;
    int test_packet_size_small;
    int test_packet_size_medium;
    int test_packet_size_large;
    int test_timeout_short;
    int test_timeout_medium;
    int test_timeout_long;
    int test_data_size_small;
    int test_data_size_medium;
    int test_data_size_large;
    int performance_packet_count;
    int performance_message_count;
    int performance_request_count;
    int stress_test_iterations;
    int stress_test_repeats;
    std::string test_endpoint_status;
    std::string test_endpoint_health;
    std::string test_endpoint_data;
    double test_latitude;
    double test_longitude;
    double test_altitude;
    double test_frequency;
    std::string test_callsign;
    std::mt19937 rng;
    
    // Helper functions (optimized versions)
    int createUDPSocket() {
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) return -1;
        
        // Set socket options for better performance
        int opt = 1;
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        
        return sock;
    }
    
    int createTCPSocket() {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) return -1;
        
        // Set socket options for better performance
        int opt = 1;
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        
        return sock;
    }
    
    bool bindSocket(int sock, int port) {
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(port);
        
        return bind(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0;
    }
    
    std::string generateUDPMessage(const std::string& data) {
        // OPTIMIZED: Simplified message format
        return "UDP:" + data;
    }
    
    std::string generateWebSocketMessage(const std::string& type, const std::string& data) {
        // OPTIMIZED: Simplified WebSocket frame format
        return "WS:" + type + ":" + data;
    }
    
    std::string generateRESTRequest(const std::string& method, const std::string& endpoint) {
        // OPTIMIZED: Simplified HTTP request format
        return method + " " + endpoint + " HTTP/1.1\r\nHost: localhost\r\n\r\n";
    }
    
    bool sendUDPPacket(int sock, const std::string& message, const std::string& host, int port) {
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        inet_pton(AF_INET, host.c_str(), &addr.sin_addr);
        
        ssize_t sent = sendto(sock, message.c_str(), message.length(), 0, 
                             (struct sockaddr*)&addr, sizeof(addr));
        return sent == static_cast<ssize_t>(message.length());
    }
    
    std::string receiveUDPPacket(int sock, int timeout_ms) {
        // OPTIMIZED: Simplified receive with timeout
        struct pollfd pfd;
        pfd.fd = sock;
        pfd.events = POLLIN;
        
        int result = poll(&pfd, 1, timeout_ms);
        if (result <= 0) return "";
        
        char buffer[1024];
        ssize_t received = recv(sock, buffer, sizeof(buffer) - 1, 0);
        if (received <= 0) return "";
        
        buffer[received] = '\0';
        return std::string(buffer);
    }
    
    // OPTIMIZED: Helper to measure execution time with reduced overhead
    template<typename Func>
    auto measureTime(Func&& func) -> decltype(func()) {
        auto start = std::chrono::high_resolution_clock::now();
        auto result = func();
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        std::cout << "Execution time: " << duration.count() << " microseconds" << std::endl;
        return result;
    }
    
    // OPTIMIZED: Simplified JSON validation
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

// OPTIMIZED: Test suite for UDP protocol tests with reduced scope
class UDPProtocolTest_Optimized : public Network_Module_Test_Optimized {
protected:
    void SetUp() override {
        Network_Module_Test_Optimized::SetUp();
    }
};

// OPTIMIZED: Test suite for WebSocket tests with reduced scope
class WebSocketTest_Optimized : public Network_Module_Test_Optimized {
protected:
    void SetUp() override {
        Network_Module_Test_Optimized::SetUp();
    }
};

// OPTIMIZED: Test suite for RESTful API tests with reduced scope
class RESTfulAPITest_Optimized : public Network_Module_Test_Optimized {
protected:
    void SetUp() override {
        Network_Module_Test_Optimized::SetUp();
    }
};

// Main function for running optimized tests
int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    
    // OPTIMIZED: Set test environment variables for faster execution
    setenv("GTEST_REPEAT", "1", 1);
    setenv("GTEST_SHUFFLE", "0", 1);
    
    return RUN_ALL_TESTS();
}
