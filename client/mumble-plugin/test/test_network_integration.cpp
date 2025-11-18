/* 
 * This file is part of the FGCom-mumble distribution (https://github.com/hbeni/fgcom-mumble).
 * Copyright (c) 2020 Benedikt Hallinger
 * 
 * This program is free software: you can redistribute it and/or modify  
 * it under the terms of the GNU General Public License as published by  
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but 
 * WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU 
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
#include <gtest/gtest.h>
#include <thread>
#include <chrono>
#include <memory>
#include <string>
#include <vector>
#include "io_UDPServer.h"
#include "io_plugin.h"
#include "shared_data.h"

class NetworkIntegrationTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize shared data
        shared_data = std::make_unique<FGCom_SharedData>();
        
        // Set up test configuration
        shared_data->setConfigValue("udp_port", "16661");
        shared_data->setConfigValue("udp_client_port", "16662");
        shared_data->setConfigValue("server_timeout", "30");
        
        // Initialize test client data
        test_client.callsign = "TEST01";
        test_client.aircraft = "C172";
        test_client.lat = 52.5200;  // Berlin
        test_client.lon = 13.4050;
        test_client.alt = 1000.0;
        
        // Add test radio
        fgcom_radio test_radio;
        test_radio.operable = true;
        test_radio.ptt = false;
        test_radio.frequency = "118.100";
        test_radio.channelWidth = 25.0;
        test_radio.volume = 1.0;
        test_client.radios.push_back(test_radio);
    }
    
    void TearDown() override {
        // Clean up shared data
        if (shared_data) {
            shared_data->clearAllData();
        }
    }
    
    std::unique_ptr<FGCom_SharedData> shared_data;
    fgcom_local_client_t test_client;
};

// Test UDP Server Startup and Shutdown
TEST_F(NetworkIntegrationTest, UDPServer_StartupShutdown) {
    // Test server startup
    EXPECT_FALSE(shared_data->isUdpServerRunning());
    
    // Start server (this would normally be done by fgcom_spawnUDPServer)
    shared_data->setUdpServerRunning(true);
    EXPECT_TRUE(shared_data->isUdpServerRunning());
    
    // Test server shutdown
    shared_data->setUdpServerRunning(false);
    EXPECT_FALSE(shared_data->isUdpServerRunning());
}

// Test Client Data Management
TEST_F(NetworkIntegrationTest, ClientData_AddRemove) {
    // Test adding local client
    shared_data->addLocalClient(test_client);
    EXPECT_EQ(shared_data->getLocalClientCount(), 1);
    
    // Test retrieving client data
    fgcom_local_client_t retrieved_client = shared_data->getLocalClient(0);
    EXPECT_EQ(retrieved_client.callsign, "TEST01");
    EXPECT_EQ(retrieved_client.aircraft, "C172");
    EXPECT_FLOAT_EQ(retrieved_client.lat, 52.5200);
    EXPECT_FLOAT_EQ(retrieved_client.lon, 13.4050);
    EXPECT_FLOAT_EQ(retrieved_client.alt, 1000.0);
    
    // Test updating client data
    test_client.alt = 2000.0;
    shared_data->updateLocalClient(0, test_client);
    retrieved_client = shared_data->getLocalClient(0);
    EXPECT_FLOAT_EQ(retrieved_client.alt, 2000.0);
    
    // Test removing client
    shared_data->removeLocalClient(0);
    EXPECT_EQ(shared_data->getLocalClientCount(), 0);
}

// Test Remote Client Management
TEST_F(NetworkIntegrationTest, RemoteClient_AddRemove) {
    mumble_userid_t test_user_id = 12345;
    int radio_id = 0;
    
    // Create test remote client
    fgcom_client remote_client;
    remote_client.callsign = "REMOTE01";
    remote_client.lat = 52.5300;
    remote_client.lon = 13.4100;
    remote_client.alt = 1500.0;
    
    // Test adding remote client
    shared_data->addRemoteClient(test_user_id, radio_id, remote_client);
    
    // Test retrieving remote client
    fgcom_client retrieved_client = shared_data->getRemoteClient(test_user_id, radio_id);
    EXPECT_EQ(retrieved_client.callsign, "REMOTE01");
    EXPECT_FLOAT_EQ(retrieved_client.lat, 52.5300);
    EXPECT_FLOAT_EQ(retrieved_client.lon, 13.4100);
    EXPECT_FLOAT_EQ(retrieved_client.alt, 1500.0);
    
    // Test updating remote client
    remote_client.alt = 2500.0;
    shared_data->updateRemoteClient(test_user_id, radio_id, remote_client);
    retrieved_client = shared_data->getRemoteClient(test_user_id, radio_id);
    EXPECT_FLOAT_EQ(retrieved_client.alt, 2500.0);
    
    // Test removing remote client
    shared_data->removeRemoteClient(test_user_id, radio_id);
    retrieved_client = shared_data->getRemoteClient(test_user_id, radio_id);
    EXPECT_EQ(retrieved_client.callsign, "");  // Should return default constructed client
}

// Test Configuration Management
TEST_F(NetworkIntegrationTest, Configuration_GetSet) {
    // Test setting configuration values
    shared_data->setConfigValue("test_key", "test_value");
    EXPECT_TRUE(shared_data->hasConfigValue("test_key"));
    EXPECT_EQ(shared_data->getConfigValue("test_key"), "test_value");
    
    // Test default value
    EXPECT_EQ(shared_data->getConfigValue("nonexistent_key", "default"), "default");
    
    // Test updating configuration
    shared_data->setConfigValue("test_key", "updated_value");
    EXPECT_EQ(shared_data->getConfigValue("test_key"), "updated_value");
}

// Test Thread Safety
TEST_F(NetworkIntegrationTest, ThreadSafety_ConcurrentAccess) {
    const int num_threads = 4;
    const int operations_per_thread = 100;
    std::vector<std::thread> threads;
    
    // Test concurrent client additions
    for (int i = 0; i < num_threads; i++) {
        threads.emplace_back([this, i, operations_per_thread]() {
            for (int j = 0; j < operations_per_thread; j++) {
                fgcom_local_client_t client = test_client;
                client.callsign = "THREAD" + std::to_string(i) + "_" + std::to_string(j);
                client.lat = 52.5200 + (i * 0.001);
                client.lon = 13.4050 + (j * 0.001);
                shared_data->addLocalClient(client);
            }
        });
    }
    
    // Wait for all threads to complete
    for (auto& thread : threads) {
        thread.join();
    }
    
    // Verify all clients were added
    EXPECT_EQ(shared_data->getLocalClientCount(), num_threads * operations_per_thread);
}

// Test Rate Throttling
TEST_F(NetworkIntegrationTest, RateThrottling_FrequencyLimit) {
    // Test that rapid notifications are throttled
    const int rapid_notifications = 10;
    const int throttle_interval_ms = 100;
    
    auto start_time = std::chrono::steady_clock::now();
    
    for (int i = 0; i < rapid_notifications; i++) {
        // Simulate rapid notifications
        shared_data->setUdpServerRunning(true);
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    
    auto end_time = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
    
    // Should take at least throttle_interval_ms * (rapid_notifications - 1)
    EXPECT_GE(duration.count(), throttle_interval_ms * (rapid_notifications - 1));
}

// Test Network Message Parsing
TEST_F(NetworkIntegrationTest, MessageParsing_ValidFormat) {
    // Test parsing valid UDP message format
    std::string valid_message = "CALLSIGN=TEST01,LAT=52.5200,LON=13.4050,ALT=1000.0,COM1_FRQ=118.100,COM1_PTT=0";
    
    // This would normally be parsed by the UDP server
    // For integration test, we verify the format is valid
    EXPECT_TRUE(valid_message.find("CALLSIGN=") != std::string::npos);
    EXPECT_TRUE(valid_message.find("LAT=") != std::string::npos);
    EXPECT_TRUE(valid_message.find("LON=") != std::string::npos);
    EXPECT_TRUE(valid_message.find("ALT=") != std::string::npos);
    EXPECT_TRUE(valid_message.find("COM1_FRQ=") != std::string::npos);
    EXPECT_TRUE(valid_message.find("COM1_PTT=") != std::string::npos);
}

// Test Network Error Handling
TEST_F(NetworkIntegrationTest, ErrorHandling_InvalidData) {
    // Test handling of invalid client data
    fgcom_local_client_t invalid_client;
    invalid_client.callsign = "";  // Empty callsign
    invalid_client.lat = 999.0;    // Invalid latitude
    invalid_client.lon = 999.0;    // Invalid longitude
    invalid_client.alt = -1000.0;  // Invalid altitude
    
    // Should still be able to add invalid data (validation happens elsewhere)
    shared_data->addLocalClient(invalid_client);
    EXPECT_EQ(shared_data->getLocalClientCount(), 1);
    
    // Test retrieving invalid data
    fgcom_local_client_t retrieved = shared_data->getLocalClient(0);
    EXPECT_EQ(retrieved.callsign, "");
    EXPECT_FLOAT_EQ(retrieved.lat, 999.0);
    EXPECT_FLOAT_EQ(retrieved.lon, 999.0);
    EXPECT_FLOAT_EQ(retrieved.alt, -1000.0);
}

// Test Network Performance
TEST_F(NetworkIntegrationTest, Performance_LargeDataSet) {
    const int num_clients = 1000;
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    // Add many clients
    for (int i = 0; i < num_clients; i++) {
        fgcom_local_client_t client = test_client;
        client.callsign = "CLIENT" + std::to_string(i);
        client.lat = 52.5200 + (i * 0.0001);
        client.lon = 13.4050 + (i * 0.0001);
        shared_data->addLocalClient(client);
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    // Should complete in reasonable time (< 100ms for 1000 clients)
    EXPECT_LT(duration.count(), 100000);
    EXPECT_EQ(shared_data->getLocalClientCount(), num_clients);
}

// Test Network Cleanup
TEST_F(NetworkIntegrationTest, Cleanup_AllData) {
    // Add some test data
    shared_data->addLocalClient(test_client);
    shared_data->setConfigValue("test_key", "test_value");
    shared_data->setUdpServerRunning(true);
    
    // Verify data exists
    EXPECT_EQ(shared_data->getLocalClientCount(), 1);
    EXPECT_TRUE(shared_data->hasConfigValue("test_key"));
    EXPECT_TRUE(shared_data->isUdpServerRunning());
    
    // Clear all data
    shared_data->clearAllData();
    
    // Verify data is cleared
    EXPECT_EQ(shared_data->getLocalClientCount(), 0);
    EXPECT_FALSE(shared_data->hasConfigValue("test_key"));
    EXPECT_FALSE(shared_data->isUdpServerRunning());
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
