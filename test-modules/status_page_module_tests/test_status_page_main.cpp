#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <chrono>
#include <thread>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <random>
#include <algorithm>
#include <numeric>
#include <cmath>
#include <queue>
#include <set>
#include <unordered_map>
#include <functional>
#include <fstream>
#include <sstream>
#include <regex>
#include <exception>
#include <stdexcept>
#include <limits>
#include <type_traits>

// Thread-safe mock classes for testing with proper error handling
class MockHTMLRenderer {
public:
    MockHTMLRenderer() = default;
    
    virtual ~MockHTMLRenderer() = default;
    
    // HTML rendering methods with proper validation and error handling
    virtual std::string renderStatusPage(const std::map<std::string, std::string>& data) {
        // Validate input data
        if (data.empty()) {
            throw std::invalid_argument("Data map cannot be empty");
        }
        
        // Check for required fields
        const std::vector<std::string> required_fields = {"user_count", "last_update", "map_content", "users_content", "frequencies_content"};
        for (const auto& field : required_fields) {
            if (data.find(field) == data.end()) {
                throw std::invalid_argument("Required field missing: " + field);
            }
        }
        
        try {
            std::ostringstream html;
            html << "<!DOCTYPE html>\n";
            html << "<html>\n";
            html << "<head>\n";
            html << "  <title>FGCom-mumble Status</title>\n";
            html << "  <meta charset=\"UTF-8\">\n";
            html << "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n";
            html << "</head>\n";
            html << "<body>\n";
            html << "  <div class=\"header\">\n";
            html << "    <h1>FGCom-mumble: live status page</h1>\n";
            html << "    <span class=\"userinfo\">Users: " << data.at("user_count") << "</span>\n";
            html << "    <span class=\"lastdbupdate\">Last DB update: " << data.at("last_update") << "</span>\n";
            html << "  </div>\n";
            html << "  <div class=\"body\">\n";
            html << "    <div class=\"map\">" << data.at("map_content") << "</div>\n";
            html << "    <div class=\"users\">" << data.at("users_content") << "</div>\n";
            html << "    <div class=\"frequencies\">" << data.at("frequencies_content") << "</div>\n";
            html << "  </div>\n";
            html << "</body>\n";
            html << "</html>\n";
            return html.str();
        } catch (const std::exception& e) {
            throw std::runtime_error("Failed to render status page: " + std::string(e.what()));
        }
    }
    
    virtual std::string renderClientList(const std::vector<std::map<std::string, std::string>>& clients) {
        std::ostringstream html;
        html << "<div class=\"client-list\">\n";
        for (const auto& client : clients) {
            html << "  <div class=\"client-entry\">\n";
            html << "    <span class=\"callsign\">" << client.at("callsign") << "</span>\n";
            html << "    <span class=\"position\">" << client.at("lat") << ", " << client.at("lon") << "</span>\n";
            html << "    <span class=\"altitude\">" << client.at("alt") << " ft</span>\n";
            html << "    <span class=\"frequency\">" << client.at("frequency") << "</span>\n";
            html << "  </div>\n";
        }
        html << "</div>\n";
        return html.str();
    }
    
    virtual std::string renderFrequencyList(const std::vector<std::map<std::string, std::string>>& frequencies) {
        std::ostringstream html;
        html << "<div class=\"frequency-list\">\n";
        for (const auto& freq : frequencies) {
            html << "  <div class=\"frequency-entry\">\n";
            html << "    <span class=\"frequency\">" << freq.at("frequency") << " MHz</span>\n";
            html << "    <span class=\"users\">" << freq.at("user_count") << " users</span>\n";
            html << "    <span class=\"status\">" << freq.at("status") << "</span>\n";
            html << "  </div>\n";
        }
        html << "</div>\n";
        return html.str();
    }
    
    virtual std::string renderMap(const std::vector<std::map<std::string, std::string>>& clients) {
        std::ostringstream html;
        html << "<div class=\"map-container\">\n";
        html << "  <div id=\"map\" style=\"width: 100%; height: 400px;\"></div>\n";
        html << "  <script>\n";
        html << "    var map = L.map('map').setView([0, 0], 2);\n";
        html << "    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png').addTo(map);\n";
        
        for (const auto& client : clients) {
            html << "    L.marker([" << client.at("lat") << ", " << client.at("lon") << "])";
            html << ".addTo(map).bindPopup('" << client.at("callsign") << "');\n";
        }
        
        html << "  </script>\n";
        html << "</div>\n";
        return html.str();
    }
    
    virtual bool validateHTML(const std::string& html) {
        // Basic HTML validation
        return html.find("<!DOCTYPE html>") != std::string::npos &&
               html.find("<html>") != std::string::npos &&
               html.find("</html>") != std::string::npos &&
               html.find("<head>") != std::string::npos &&
               html.find("<body>") != std::string::npos;
    }
};

class MockRealTimeUpdater {
public:
    MockRealTimeUpdater() = default;
    
    virtual ~MockRealTimeUpdater() = default;
    
    // Real-time update methods
    virtual bool startRealTimeUpdates() {
        std::lock_guard<std::mutex> lock(updater_mutex);
        is_running = true;
        update_thread = std::thread(&MockRealTimeUpdater::updateLoop, this);
        return true;
    }
    
    virtual void stopRealTimeUpdates() {
        std::lock_guard<std::mutex> lock(updater_mutex);
        is_running = false;
        if (update_thread.joinable()) {
            update_thread.join();
        }
    }
    
    virtual void setUpdateCallback(std::function<void(const std::string&)> callback) {
        std::lock_guard<std::mutex> lock(updater_mutex);
        update_callback = callback;
    }
    
    virtual bool isRunning() {
        std::lock_guard<std::mutex> lock(updater_mutex);
        return is_running;
    }
    
    virtual int getUpdateCount() {
        std::lock_guard<std::mutex> lock(updater_mutex);
        return update_count;
    }
    
    virtual void setUpdateInterval(int milliseconds) {
        std::lock_guard<std::mutex> lock(updater_mutex);
        update_interval_ms = milliseconds;
    }
    
protected:
    void updateLoop() {
        while (is_running) {
            std::this_thread::sleep_for(std::chrono::milliseconds(update_interval_ms));
            if (is_running && update_callback) {
                update_callback("real-time-update");
                update_count++;
            }
        }
    }
    
    std::atomic<bool> is_running{false};
    std::atomic<int> update_count{0};
    int update_interval_ms = 1000;
    std::thread update_thread;
    std::function<void(const std::string&)> update_callback;
    std::mutex updater_mutex;
};

class MockWebSocketServer {
public:
    MockWebSocketServer() = default;
    
    virtual ~MockWebSocketServer() = default;
    
    // WebSocket server methods
    virtual bool startServer(int port) {
        std::lock_guard<std::mutex> lock(server_mutex);
        server_port = port;
        is_running = true;
        return true;
    }
    
    virtual void stopServer() {
        std::lock_guard<std::mutex> lock(server_mutex);
        is_running = false;
    }
    
    virtual bool isRunning() {
        std::lock_guard<std::mutex> lock(server_mutex);
        return is_running;
    }
    
    virtual int getPort() {
        std::lock_guard<std::mutex> lock(server_mutex);
        return server_port;
    }
    
    virtual void setMessageCallback(std::function<void(const std::string&, const std::string&)> callback) {
        std::lock_guard<std::mutex> lock(server_mutex);
        message_callback = callback;
    }
    
    virtual void sendMessage(const std::string& client_id, const std::string& message) {
        std::lock_guard<std::mutex> lock(server_mutex);
        if (message_callback) {
            message_callback(client_id, message);
        }
    }
    
    virtual void broadcastMessage(const std::string& message) {
        std::lock_guard<std::mutex> lock(server_mutex);
        if (message_callback) {
            message_callback("broadcast", message);
        }
    }
    
    virtual size_t getClientCount() {
        std::lock_guard<std::mutex> lock(server_mutex);
        return connected_clients.size();
    }
    
    virtual void addClient(const std::string& client_id) {
        std::lock_guard<std::mutex> lock(server_mutex);
        connected_clients.insert(client_id);
    }
    
    virtual void removeClient(const std::string& client_id) {
        std::lock_guard<std::mutex> lock(server_mutex);
        connected_clients.erase(client_id);
    }
    
protected:
    std::atomic<bool> is_running{false};
    int server_port = 8080;
    std::set<std::string> connected_clients;
    std::function<void(const std::string&, const std::string&)> message_callback;
    std::mutex server_mutex;
};

class MockDataValidator {
public:
    MockDataValidator() = default;
    
    virtual ~MockDataValidator() = default;
    
    // Data validation methods
    virtual bool validateClientData(const std::map<std::string, std::string>& client_data) {
        // Check required fields
        if (client_data.find("callsign") == client_data.end()) return false;
        if (client_data.find("lat") == client_data.end()) return false;
        if (client_data.find("lon") == client_data.end()) return false;
        if (client_data.find("alt") == client_data.end()) return false;
        if (client_data.find("frequency") == client_data.end()) return false;
        
        // Validate latitude
        try {
            double lat = std::stod(client_data.at("lat"));
            if (lat < -90.0 || lat > 90.0) return false;
        } catch (...) {
            return false;
        }
        
        // Validate longitude
        try {
            double lon = std::stod(client_data.at("lon"));
            if (lon < -180.0 || lon > 180.0) return false;
        } catch (...) {
            return false;
        }
        
        // Validate altitude
        try {
            double alt = std::stod(client_data.at("alt"));
            if (alt < 0.0 || alt > 100000.0) return false;
        } catch (...) {
            return false;
        }
        
        // Validate frequency
        try {
            double freq = std::stod(client_data.at("frequency"));
            if (freq < 0.0 || freq > 10000.0) return false;
        } catch (...) {
            return false;
        }
        
        return true;
    }
    
    virtual bool validateFrequencyData(const std::map<std::string, std::string>& frequency_data) {
        // Check required fields
        if (frequency_data.find("frequency") == frequency_data.end()) return false;
        if (frequency_data.find("user_count") == frequency_data.end()) return false;
        if (frequency_data.find("status") == frequency_data.end()) return false;
        
        // Validate frequency
        try {
            double freq = std::stod(frequency_data.at("frequency"));
            if (freq < 0.0 || freq > 10000.0) return false;
        } catch (...) {
            return false;
        }
        
        // Validate user count
        try {
            int user_count = std::stoi(frequency_data.at("user_count"));
            if (user_count < 0 || user_count > 1000) return false;
        } catch (...) {
            return false;
        }
        
        return true;
    }
    
    virtual bool validatePositionData(double lat, double lon, double alt) {
        return lat >= -90.0 && lat <= 90.0 &&
               lon >= -180.0 && lon <= 180.0 &&
               alt >= 0.0 && alt <= 100000.0;
    }
    
    virtual bool validateFrequency(double frequency) {
        return frequency >= 0.0 && frequency <= 10000.0;
    }
    
    virtual bool validateConnectionState(const std::string& state) {
        return state == "connected" || state == "disconnected" || state == "connecting" || state == "error";
    }
    
    virtual bool validateUpdateFrequency(int frequency_hz) {
        return frequency_hz >= 1 && frequency_hz <= 100;
    }
};

// Test fixtures and utilities
class StatusPageModuleTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize test parameters
        test_clients = generateTestClients(10);
        test_frequencies = generateTestFrequencies(5);
        test_map_data = generateTestMapData(10);
        
        // Initialize mock objects
        mock_html_renderer = std::make_unique<MockHTMLRenderer>();
        mock_real_time_updater = std::make_unique<MockRealTimeUpdater>();
        mock_websocket_server = std::make_unique<MockWebSocketServer>();
        mock_data_validator = std::make_unique<MockDataValidator>();
        
        // Set up test data
        status_page_data["user_count"] = std::to_string(test_clients.size());
        status_page_data["last_update"] = "2024-01-01 12:00:00";
        status_page_data["map_content"] = mock_html_renderer->renderMap(test_map_data);
        status_page_data["users_content"] = mock_html_renderer->renderClientList(test_clients);
        status_page_data["frequencies_content"] = mock_html_renderer->renderFrequencyList(test_frequencies);
    }
    
    void TearDown() override {
        // Clean up mock objects
        mock_html_renderer.reset();
        mock_real_time_updater.reset();
        mock_websocket_server.reset();
        mock_data_validator.reset();
    }
    
    // Test parameters
    std::vector<std::map<std::string, std::string>> test_clients;
    std::vector<std::map<std::string, std::string>> test_frequencies;
    std::vector<std::map<std::string, std::string>> test_map_data;
    std::map<std::string, std::string> status_page_data;
    
    // Mock objects
    std::unique_ptr<MockHTMLRenderer> mock_html_renderer;
    std::unique_ptr<MockRealTimeUpdater> mock_real_time_updater;
    std::unique_ptr<MockWebSocketServer> mock_websocket_server;
    std::unique_ptr<MockDataValidator> mock_data_validator;
    
    // Helper functions
    std::vector<std::map<std::string, std::string>> generateTestClients(int count) {
        std::vector<std::map<std::string, std::string>> clients;
        for (int i = 0; i < count; ++i) {
            std::map<std::string, std::string> client;
            client["callsign"] = "TEST" + std::to_string(i);
            client["lat"] = std::to_string(40.0 + i * 0.1);
            client["lon"] = std::to_string(-74.0 + i * 0.1);
            client["alt"] = std::to_string(1000 + i * 100);
            client["frequency"] = std::to_string(144.0 + i * 0.1);
            clients.push_back(client);
        }
        return clients;
    }
    
    std::vector<std::map<std::string, std::string>> generateTestFrequencies(int count) {
        std::vector<std::map<std::string, std::string>> frequencies;
        for (int i = 0; i < count; ++i) {
            std::map<std::string, std::string> frequency;
            frequency["frequency"] = std::to_string(144.0 + i * 0.1);
            frequency["user_count"] = std::to_string(i + 1);
            frequency["status"] = "active";
            frequencies.push_back(frequency);
        }
        return frequencies;
    }
    
    std::vector<std::map<std::string, std::string>> generateTestMapData(int count) {
        std::vector<std::map<std::string, std::string>> map_data;
        for (int i = 0; i < count; ++i) {
            std::map<std::string, std::string> marker;
            marker["lat"] = std::to_string(40.0 + i * 0.1);
            marker["lon"] = std::to_string(-74.0 + i * 0.1);
            marker["callsign"] = "TEST" + std::to_string(i);
            map_data.push_back(marker);
        }
        return map_data;
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
};

// Test suite for web interface tests
class WebInterfaceTest : public StatusPageModuleTest {
protected:
    void SetUp() override {
        StatusPageModuleTest::SetUp();
    }
};

// Test suite for data accuracy tests
class DataAccuracyTest : public StatusPageModuleTest {
protected:
    void SetUp() override {
        StatusPageModuleTest::SetUp();
    }
};

// Main function moved to main.cpp to avoid multiple definitions
