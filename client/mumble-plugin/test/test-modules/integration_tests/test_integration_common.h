#ifndef TEST_INTEGRATION_COMMON_H
#define TEST_INTEGRATION_COMMON_H

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
#include <future>
#include <array>

// Thread-safe mock classes for integration testing
class MockClient {
public:
    MockClient(const std::string& id) : client_id(id), connected(false), transmitting(false) {
        // Validate client ID
        if (id.empty()) {
            throw std::invalid_argument("Client ID cannot be empty");
        }
    }
    
    virtual ~MockClient() = default;
    
    // Client connection methods with proper error handling
    virtual bool connect(const std::string& server_address, int port) {
        // Validate inputs
        if (server_address.empty()) {
            throw std::invalid_argument("Server address cannot be empty");
        }
        if (port <= 0 || port > 65535) {
            throw std::out_of_range("Port must be between 1 and 65535");
        }
        
        std::lock_guard<std::mutex> lock(client_mutex);
        try {
            connected = true;
            server_addr = server_address;
            server_port = port;
            return true;
        } catch (const std::exception& e) {
            connected = false;
            throw std::runtime_error("Failed to connect: " + std::string(e.what()));
        }
    }
    
    virtual void disconnect() {
        std::lock_guard<std::mutex> lock(client_mutex);
        try {
            connected = false;
            transmitting = false;
            // Clear any pending operations
            audio_callback = nullptr;
        } catch (const std::exception& e) {
            // Log but don't throw during disconnect
            std::cerr << "Warning: Exception during disconnect: " << e.what() << std::endl;
        }
    }
    
    virtual bool isConnected() {
        std::lock_guard<std::mutex> lock(client_mutex);
        return connected;
    }
    
    // Audio transmission methods
    virtual bool startTransmission(const std::string& frequency) {
        std::lock_guard<std::mutex> lock(client_mutex);
        if (!connected) return false;
        transmitting = true;
        current_frequency = frequency;
        return true;
    }
    
    virtual void stopTransmission() {
        std::lock_guard<std::mutex> lock(client_mutex);
        transmitting = false;
    }
    
    virtual bool isTransmitting() {
        std::lock_guard<std::mutex> lock(client_mutex);
        return transmitting;
    }
    
    virtual std::string getCurrentFrequency() {
        std::lock_guard<std::mutex> lock(client_mutex);
        return current_frequency;
    }
    
    // Audio reception methods
    virtual void setAudioCallback(std::function<void(const std::vector<float>&)> callback) {
        std::lock_guard<std::mutex> lock(client_mutex);
        audio_callback = callback;
    }
    
    virtual void receiveAudio(const std::vector<float>& audio_data) {
        std::lock_guard<std::mutex> lock(client_mutex);
        if (audio_callback) {
            audio_callback(audio_data);
        }
    }
    
    // Position and status methods
    virtual void setPosition(double lat, double lon, double alt) {
        std::lock_guard<std::mutex> lock(client_mutex);
        latitude = lat;
        longitude = lon;
        altitude = alt;
    }
    
    virtual std::tuple<double, double, double> getPosition() {
        std::lock_guard<std::mutex> lock(client_mutex);
        return std::make_tuple(latitude, longitude, altitude);
    }
    
    virtual std::string getClientId() {
        return client_id;
    }
    
protected:
    std::string client_id;
    std::atomic<bool> connected{false};
    std::atomic<bool> transmitting{false};
    std::string server_addr;
    int server_port = 0;
    std::string current_frequency;
    double latitude = 0.0;
    double longitude = 0.0;
    double altitude = 0.0;
    std::function<void(const std::vector<float>&)> audio_callback;
    std::mutex client_mutex;
};

class MockServer {
public:
    MockServer() = default;
    
    virtual ~MockServer() = default;
    
    // Server management methods
    virtual bool startServer(int port) {
        std::lock_guard<std::mutex> lock(server_mutex);
        server_port = port;
        is_running = true;
        return true;
    }
    
    virtual void stopServer() {
        std::lock_guard<std::mutex> lock(server_mutex);
        is_running = false;
        connected_clients.clear();
    }
    
    virtual bool isRunning() {
        std::lock_guard<std::mutex> lock(server_mutex);
        return is_running;
    }
    
    virtual int getPort() {
        std::lock_guard<std::mutex> lock(server_mutex);
        return server_port;
    }
    
    // Client connection methods
    virtual bool addClient(std::shared_ptr<MockClient> client) {
        std::lock_guard<std::mutex> lock(server_mutex);
        if (!is_running) return false;
        connected_clients[client->getClientId()] = client;
        return true;
    }
    
    virtual void removeClient(const std::string& client_id) {
        std::lock_guard<std::mutex> lock(server_mutex);
        connected_clients.erase(client_id);
    }
    
    virtual size_t getClientCount() {
        std::lock_guard<std::mutex> lock(server_mutex);
        return connected_clients.size();
    }
    
    virtual std::vector<std::string> getConnectedClients() {
        std::lock_guard<std::mutex> lock(server_mutex);
        std::vector<std::string> clients;
        for (const auto& pair : connected_clients) {
            clients.push_back(pair.first);
        }
        return clients;
    }
    
    // Audio routing methods
    virtual void routeAudio(const std::string& from_client_id, const std::vector<float>& audio_data) {
        std::lock_guard<std::mutex> lock(server_mutex);
        if (!is_running) return;
        
        auto from_client = connected_clients.find(from_client_id);
        if (from_client == connected_clients.end()) return;
        
        // Route audio to all other clients on the same frequency
        std::string frequency = from_client->second->getCurrentFrequency();
        for (const auto& pair : connected_clients) {
            if (pair.first != from_client_id && pair.second->getCurrentFrequency() == frequency) {
                pair.second->receiveAudio(audio_data);
            }
        }
    }
    
    // Propagation calculation methods
    virtual double calculatePropagation(const std::string& from_client_id, const std::string& to_client_id) {
        std::lock_guard<std::mutex> lock(server_mutex);
        auto from_client = connected_clients.find(from_client_id);
        auto to_client = connected_clients.find(to_client_id);
        
        if (from_client == connected_clients.end() || to_client == connected_clients.end()) {
            return 0.0;
        }
        
        // Simple distance-based propagation calculation
        auto from_pos = from_client->second->getPosition();
        auto to_pos = to_client->second->getPosition();
        
        double lat1 = std::get<0>(from_pos);
        double lon1 = std::get<1>(from_pos);
        double alt1 = std::get<2>(from_pos);
        double lat2 = std::get<0>(to_pos);
        double lon2 = std::get<1>(to_pos);
        double alt2 = std::get<2>(to_pos);
        
        // Calculate distance
        double distance = calculateDistance(lat1, lon1, lat2, lon2);
        
        // Simple propagation model (line of sight)
        double horizon_distance = calculateHorizonDistance(alt1, alt2);
        
        if (distance <= horizon_distance) {
            return 1.0; // Full signal
        } else {
            return 0.0; // No signal
        }
    }
    
    // ATIS playback methods
    virtual void startATISPlayback(const std::string& frequency) {
        std::lock_guard<std::mutex> lock(server_mutex);
        atis_frequencies.insert(frequency);
    }
    
    virtual void stopATISPlayback(const std::string& frequency) {
        std::lock_guard<std::mutex> lock(server_mutex);
        atis_frequencies.erase(frequency);
    }
    
    virtual bool isATISActive(const std::string& frequency) {
        std::lock_guard<std::mutex> lock(server_mutex);
        return atis_frequencies.find(frequency) != atis_frequencies.end();
    }
    
    // RDF detection methods
    virtual void startRDFDetection(const std::string& frequency) {
        std::lock_guard<std::mutex> lock(server_mutex);
        rdf_frequencies.insert(frequency);
    }
    
    virtual void stopRDFDetection(const std::string& frequency) {
        std::lock_guard<std::mutex> lock(server_mutex);
        rdf_frequencies.erase(frequency);
    }
    
    virtual bool isRDFActive(const std::string& frequency) {
        std::lock_guard<std::mutex> lock(server_mutex);
        return rdf_frequencies.find(frequency) != rdf_frequencies.end();
    }
    
protected:
    double calculateDistance(double lat1, double lon1, double lat2, double lon2) {
        // Simple distance calculation (not accurate for large distances)
        double dx = (lon2 - lon1) * 111320.0 * cos(lat1 * M_PI / 180.0);
        double dy = (lat2 - lat1) * 111320.0;
        return sqrt(dx * dx + dy * dy);
    }
    
    double calculateHorizonDistance(double alt1, double alt2) {
        // Simple horizon distance calculation
        double horizon1 = sqrt(2 * 6371000 * alt1);
        double horizon2 = sqrt(2 * 6371000 * alt2);
        return horizon1 + horizon2;
    }
    
    std::atomic<bool> is_running{false};
    int server_port = 8080;
    std::map<std::string, std::shared_ptr<MockClient>> connected_clients;
    std::set<std::string> atis_frequencies;
    std::set<std::string> rdf_frequencies;
    std::mutex server_mutex;
};

class MockPropagationCalculator {
public:
    MockPropagationCalculator() = default;
    
    virtual ~MockPropagationCalculator() = default;
    
    // Propagation calculation methods
    virtual double calculateSignalStrength(double distance, double frequency, double altitude1, double altitude2) {
        // Simple propagation model
        double free_space_loss = 20 * log10(distance) + 20 * log10(frequency) + 32.45;
        double height_gain = 20 * log10(altitude1 + altitude2);
        return -free_space_loss + height_gain;
    }
    
    virtual double calculatePathLoss(double distance, double frequency) {
        // Free space path loss
        return 20 * log10(distance) + 20 * log10(frequency) + 32.45;
    }
    
    virtual double calculateFresnelZone(double distance, double frequency) {
        // First Fresnel zone radius
        double wavelength = 300.0 / frequency; // Speed of light / frequency
        return sqrt(wavelength * distance / 2.0);
    }
    
    virtual bool isLineOfSight(double distance, double altitude1, double altitude2) {
        // Simple line of sight check
        double horizon_distance = calculateHorizonDistance(altitude1, altitude2);
        return distance <= horizon_distance;
    }
    
    virtual double calculateAtmosphericAttenuation(double distance, double frequency) {
        // Simple atmospheric attenuation model
        return 0.1 * distance * (frequency / 1000.0);
    }
    
    virtual double calculateGroundReflection(double distance, double frequency, double altitude) {
        // Simple ground reflection model
        double reflection_coefficient = 0.5;
        double phase_shift = 2 * M_PI * distance / (300.0 / frequency);
        return reflection_coefficient * cos(phase_shift);
    }
    
protected:
    double calculateHorizonDistance(double alt1, double alt2) {
        // Simple horizon distance calculation
        double horizon1 = sqrt(2 * 6371000 * alt1);
        double horizon2 = sqrt(2 * 6371000 * alt2);
        return horizon1 + horizon2;
    }
};

// Test fixtures and utilities
class IntegrationTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize test parameters
        test_frequencies = {"121.5", "243.0", "118.0", "137.0", "144.0", "430.0"};
        test_positions = {
            {40.0, -74.0, 1000.0},  // New York
            {34.0, -118.0, 2000.0}, // Los Angeles
            {51.0, -0.0, 1500.0},   // London
            {48.0, 2.0, 1200.0},    // Paris
            {35.0, 139.0, 1800.0}   // Tokyo
        };
        
        // Initialize mock objects
        mock_server = std::make_unique<MockServer>();
        mock_propagation_calculator = std::make_unique<MockPropagationCalculator>();
        
        // Create test clients
        for (int i = 0; i < 10; ++i) {
            auto client = std::make_shared<MockClient>("client_" + std::to_string(i));
            test_clients.push_back(client);
        }
    }
    
    void TearDown() override {
        // Clean up mock objects
        mock_server.reset();
        mock_propagation_calculator.reset();
        test_clients.clear();
    }
    
    // Test parameters
    std::vector<std::string> test_frequencies;
    std::vector<std::tuple<double, double, double>> test_positions;
    std::vector<std::shared_ptr<MockClient>> test_clients;
    
    // Mock objects
    std::unique_ptr<MockServer> mock_server;
    std::unique_ptr<MockPropagationCalculator> mock_propagation_calculator;
    
    // Helper functions
    std::vector<float> generateTestAudio(int samples) {
        std::vector<float> audio_data;
        audio_data.reserve(samples);
        for (int i = 0; i < samples; ++i) {
            audio_data.push_back(static_cast<float>(sin(2 * M_PI * 440 * i / 44100.0))); // 440 Hz tone
        }
        return audio_data;
    }
    
    void setupTestClients() {
        for (size_t i = 0; i < test_clients.size() && i < test_positions.size(); ++i) {
            auto pos = test_positions[i];
            test_clients[i]->setPosition(std::get<0>(pos), std::get<1>(pos), std::get<2>(pos));
            mock_server->addClient(test_clients[i]);
        }
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

// Test suite for end-to-end tests
class EndToEndTest : public IntegrationTest {
protected:
    void SetUp() override {
        IntegrationTest::SetUp();
    }
};

// Test suite for multi-client tests
class MultiClientTest : public IntegrationTest {
protected:
    void SetUp() override {
        IntegrationTest::SetUp();
    }
};

// Test suite for stress tests
class StressTest : public IntegrationTest {
protected:
    void SetUp() override {
        IntegrationTest::SetUp();
    }
};

#endif // TEST_INTEGRATION_COMMON_H
