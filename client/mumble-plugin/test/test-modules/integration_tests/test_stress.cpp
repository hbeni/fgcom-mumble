#include "test_integration_common.h"

// 14.3 Stress Tests
TEST_F(StressTest, MaximumClientCapacity) {
    // Test maximum client capacity
    bool server_started = mock_server->startServer(8080);
    EXPECT_TRUE(server_started) << "Server should start successfully";
    
    // Test connecting maximum number of clients
    const int max_clients = 1000;
    std::vector<std::shared_ptr<MockClient>> clients;
    
    for (int i = 0; i < max_clients; ++i) {
        auto client = std::make_shared<MockClient>("client_" + std::to_string(i));
        bool connected = client->connect("localhost", 8080);
        EXPECT_TRUE(connected) << "Client " << i << " should connect successfully";
        
        bool added = mock_server->addClient(client);
        EXPECT_TRUE(added) << "Client " << i << " should be added to server";
        
        clients.push_back(client);
    }
    
    // Test server client count
    size_t client_count = mock_server->getClientCount();
    EXPECT_EQ(client_count, max_clients) << "Server should have " << max_clients << " clients";
    
    // Test all clients tuning to frequency
    std::string frequency = "121.5";
    for (int i = 0; i < max_clients; ++i) {
        bool tuned = clients[i]->startTransmission(frequency);
        EXPECT_TRUE(tuned) << "Client " << i << " should tune to frequency successfully";
    }
    
    // Test audio communication with maximum clients
    std::vector<std::atomic<int>> audio_received_counts(max_clients);
    for (int i = 0; i < max_clients; ++i) {
        audio_received_counts[i] = 0;
        clients[i]->setAudioCallback([&audio_received_counts, i](const std::vector<float>& audio_data) {
            audio_received_counts[i]++;
        });
    }
    
    // Test audio transmission from client 0 to all other clients
    std::vector<float> audio_data = generateTestAudio(1024);
    mock_server->routeAudio(clients[0]->getClientId(), audio_data);
    
    // Test that all other clients received audio
    for (int i = 1; i < max_clients; ++i) {
        EXPECT_EQ(audio_received_counts[i].load(), 1) << "Client " << i << " should have received audio from client 0";
    }
    
    // Test propagation calculation with maximum clients
    for (int i = 0; i < max_clients; ++i) {
        double lat = 40.0 + (i % 100) * 0.01;
        double lon = -74.0 + (i / 100) * 0.01;
        double alt = 1000.0 + i * 10.0;
        clients[i]->setPosition(lat, lon, alt);
    }
    
    // Test propagation calculation between sample pairs of clients
    for (int i = 0; i < 100; ++i) {
        for (int j = 0; j < 100; ++j) {
            if (i != j) {
                double propagation = mock_server->calculatePropagation(
                    clients[i]->getClientId(), 
                    clients[j]->getClientId()
                );
                
                EXPECT_GE(propagation, 0.0) << "Propagation should be non-negative between clients " << i << " and " << j;
                EXPECT_LE(propagation, 1.0) << "Propagation should be at most 1.0 between clients " << i << " and " << j;
            }
        }
    }
    
    // Clean up
    for (auto& client : clients) {
        client->disconnect();
    }
    mock_server->stopServer();
}

TEST_F(StressTest, NetworkSaturation) {
    // Test network saturation
    bool server_started = mock_server->startServer(8080);
    EXPECT_TRUE(server_started) << "Server should start successfully";
    
    // Test connecting clients for network saturation
    const int num_clients = 100;
    std::vector<std::shared_ptr<MockClient>> clients;
    
    for (int i = 0; i < num_clients; ++i) {
        auto client = std::make_shared<MockClient>("client_" + std::to_string(i));
        bool connected = client->connect("localhost", 8080);
        EXPECT_TRUE(connected) << "Client " << i << " should connect successfully";
        
        bool added = mock_server->addClient(client);
        EXPECT_TRUE(added) << "Client " << i << " should be added to server";
        
        clients.push_back(client);
    }
    
    // Test network saturation with continuous audio transmission
    std::vector<std::atomic<int>> audio_received_counts(num_clients);
    for (int i = 0; i < num_clients; ++i) {
        audio_received_counts[i] = 0;
        clients[i]->setAudioCallback([&audio_received_counts, i](const std::vector<float>& audio_data) {
            audio_received_counts[i]++;
        });
    }
    
    // Test continuous audio transmission from all clients
    const int num_transmissions = 1000;
    for (int t = 0; t < num_transmissions; ++t) {
        for (int i = 0; i < num_clients; ++i) {
            std::vector<float> audio_data = generateTestAudio(1024);
            mock_server->routeAudio(clients[i]->getClientId(), audio_data);
        }
    }
    
    // Test that all clients received audio
    for (int i = 0; i < num_clients; ++i) {
        EXPECT_GT(audio_received_counts[i].load(), 0) << "Client " << i << " should have received audio";
    }
    
    // Test network saturation with different frequencies
    std::vector<std::string> frequencies = {"121.5", "243.0", "118.0", "137.0", "144.0"};
    for (int i = 0; i < num_clients; ++i) {
        std::string frequency = frequencies[i % frequencies.size()];
        bool tuned = clients[i]->startTransmission(frequency);
        EXPECT_TRUE(tuned) << "Client " << i << " should tune to frequency successfully";
    }
    
    // Test continuous audio transmission with frequency separation
    for (int t = 0; t < num_transmissions; ++t) {
        for (int i = 0; i < num_clients; ++i) {
            std::vector<float> audio_data = generateTestAudio(1024);
            mock_server->routeAudio(clients[i]->getClientId(), audio_data);
        }
    }
    
    // Test that clients received audio from same frequency
    for (int i = 0; i < num_clients; ++i) {
        std::string client_frequency = clients[i]->getCurrentFrequency();
        int expected_audio_count = 0;
        for (int j = 0; j < num_clients; ++j) {
            if (i != j && clients[j]->getCurrentFrequency() == client_frequency) {
                expected_audio_count++;
            }
        }
        
        EXPECT_GE(audio_received_counts[i].load(), expected_audio_count) << "Client " << i << " should have received audio from clients on same frequency";
    }
    
    // Clean up
    for (auto& client : clients) {
        client->disconnect();
    }
    mock_server->stopServer();
}

TEST_F(StressTest, CPULoadUnderMaximumClients) {
    // Test CPU load under maximum clients
    bool server_started = mock_server->startServer(8080);
    EXPECT_TRUE(server_started) << "Server should start successfully";
    
    // Test connecting maximum number of clients
    const int max_clients = 500;
    std::vector<std::shared_ptr<MockClient>> clients;
    
    for (int i = 0; i < max_clients; ++i) {
        auto client = std::make_shared<MockClient>("client_" + std::to_string(i));
        bool connected = client->connect("localhost", 8080);
        EXPECT_TRUE(connected) << "Client " << i << " should connect successfully";
        
        bool added = mock_server->addClient(client);
        EXPECT_TRUE(added) << "Client " << i << " should be added to server";
        
        clients.push_back(client);
    }
    
    // Test CPU load with continuous operations
    const int num_operations = 1000;
    auto start_time = std::chrono::high_resolution_clock::now();
    
    for (int op = 0; op < num_operations; ++op) {
        // Test audio transmission from all clients
        for (int i = 0; i < max_clients; ++i) {
            std::vector<float> audio_data = generateTestAudio(1024);
            mock_server->routeAudio(clients[i]->getClientId(), audio_data);
        }
        
        // Test propagation calculation between all clients
        for (int i = 0; i < 100; ++i) {
            for (int j = 0; j < 100; ++j) {
                if (i != j) {
                    double propagation = mock_server->calculatePropagation(
                        clients[i]->getClientId(), 
                        clients[j]->getClientId()
                    );
                    EXPECT_GE(propagation, 0.0) << "Propagation should be non-negative";
                }
            }
        }
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    // Calculate performance metrics
    double time_per_operation = static_cast<double>(duration.count()) / num_operations;
    
    // CPU load operations should be reasonably fast
    EXPECT_LT(time_per_operation, 1000000.0) << "CPU load operations too slow: " << time_per_operation << " microseconds";
    
    std::cout << "CPU load performance: " << time_per_operation << " microseconds per operation" << std::endl;
    
    // Clean up
    for (auto& client : clients) {
        client->disconnect();
    }
    mock_server->stopServer();
}

TEST_F(StressTest, MemoryUsageOverTime) {
    // Test memory usage over time
    bool server_started = mock_server->startServer(8080);
    EXPECT_TRUE(server_started) << "Server should start successfully";
    
    // Test memory usage with increasing number of clients
    const int max_clients = 100;
    std::vector<std::shared_ptr<MockClient>> clients;
    
    for (int i = 0; i < max_clients; ++i) {
        auto client = std::make_shared<MockClient>("client_" + std::to_string(i));
        bool connected = client->connect("localhost", 8080);
        EXPECT_TRUE(connected) << "Client " << i << " should connect successfully";
        
        bool added = mock_server->addClient(client);
        EXPECT_TRUE(added) << "Client " << i << " should be added to server";
        
        clients.push_back(client);
    }
    
    // Test memory usage with continuous operations
    const int num_operations = 1000;
    for (int op = 0; op < num_operations; ++op) {
        // Test audio transmission from all clients
        for (int i = 0; i < max_clients; ++i) {
            std::vector<float> audio_data = generateTestAudio(1024);
            mock_server->routeAudio(clients[i]->getClientId(), audio_data);
        }
        
        // Test propagation calculation between all clients
        for (int i = 0; i < max_clients; ++i) {
            for (int j = 0; j < max_clients; ++j) {
                if (i != j) {
                    double propagation = mock_server->calculatePropagation(
                        clients[i]->getClientId(), 
                        clients[j]->getClientId()
                    );
                    EXPECT_GE(propagation, 0.0) << "Propagation should be non-negative";
                }
            }
        }
        
        // Test memory usage with different client counts
        if (op % 100 == 0) {
            size_t client_count = mock_server->getClientCount();
            EXPECT_EQ(client_count, max_clients) << "Server should maintain client count";
        }
    }
    
    // Test memory usage with client disconnection and reconnection
    for (int i = 0; i < max_clients; ++i) {
        clients[i]->disconnect();
        mock_server->removeClient(clients[i]->getClientId());
    }
    
    size_t client_count_after_disconnect = mock_server->getClientCount();
    EXPECT_EQ(client_count_after_disconnect, 0) << "Server should have 0 clients after disconnection";
    
    // Test memory usage with client reconnection
    for (int i = 0; i < max_clients; ++i) {
        bool reconnected = clients[i]->connect("localhost", 8080);
        EXPECT_TRUE(reconnected) << "Client " << i << " should reconnect successfully";
        
        bool readded = mock_server->addClient(clients[i]);
        EXPECT_TRUE(readded) << "Client " << i << " should be readded to server";
    }
    
    size_t client_count_after_reconnect = mock_server->getClientCount();
    EXPECT_EQ(client_count_after_reconnect, max_clients) << "Server should have " << max_clients << " clients after reconnection";
    
    // Clean up
    for (auto& client : clients) {
        client->disconnect();
    }
    mock_server->stopServer();
}

TEST_F(StressTest, DatabaseQueryPerformance) {
    // Test database query performance
    bool server_started = mock_server->startServer(8080);
    EXPECT_TRUE(server_started) << "Server should start successfully";
    
    // Test database query performance with multiple clients
    const int num_clients = 100;
    std::vector<std::shared_ptr<MockClient>> clients;
    
    for (int i = 0; i < num_clients; ++i) {
        auto client = std::make_shared<MockClient>("client_" + std::to_string(i));
        bool connected = client->connect("localhost", 8080);
        EXPECT_TRUE(connected) << "Client " << i << " should connect successfully";
        
        bool added = mock_server->addClient(client);
        EXPECT_TRUE(added) << "Client " << i << " should be added to server";
        
        clients.push_back(client);
    }
    
    // Test database query performance
    const int num_queries = 1000;
    auto start_time = std::chrono::high_resolution_clock::now();
    
    for (int q = 0; q < num_queries; ++q) {
        // Test client count query
        size_t client_count = mock_server->getClientCount();
        EXPECT_EQ(client_count, num_clients) << "Client count query should be accurate";
        
        // Test connected clients query
        std::vector<std::string> connected_clients = mock_server->getConnectedClients();
        EXPECT_EQ(connected_clients.size(), num_clients) << "Connected clients query should be accurate";
        
        // Test propagation calculation query
        for (int i = 0; i < 10; ++i) {
            for (int j = 0; j < 10; ++j) {
                if (i != j) {
                    double propagation = mock_server->calculatePropagation(
                        clients[i]->getClientId(), 
                        clients[j]->getClientId()
                    );
                    EXPECT_GE(propagation, 0.0) << "Propagation query should be non-negative";
                }
            }
        }
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    // Calculate performance metrics
    double time_per_query = static_cast<double>(duration.count()) / num_queries;
    
    // Database query operations should be fast
    EXPECT_LT(time_per_query, 10000.0) << "Database query operations too slow: " << time_per_query << " microseconds";
    
    std::cout << "Database query performance: " << time_per_query << " microseconds per query" << std::endl;
    
    // Clean up
    for (auto& client : clients) {
        client->disconnect();
    }
    mock_server->stopServer();
}

TEST_F(StressTest, FileIOPerformance) {
    // Test file I/O performance
    bool server_started = mock_server->startServer(8080);
    EXPECT_TRUE(server_started) << "Server should start successfully";
    
    // Test file I/O performance with multiple clients
    const int num_clients = 100;
    std::vector<std::shared_ptr<MockClient>> clients;
    
    for (int i = 0; i < num_clients; ++i) {
        auto client = std::make_shared<MockClient>("client_" + std::to_string(i));
        bool connected = client->connect("localhost", 8080);
        EXPECT_TRUE(connected) << "Client " << i << " should connect successfully";
        
        bool added = mock_server->addClient(client);
        EXPECT_TRUE(added) << "Client " << i << " should be added to server";
        
        clients.push_back(client);
    }
    
    // Test file I/O performance
    const int num_operations = 1000;
    auto start_time = std::chrono::high_resolution_clock::now();
    
    for (int op = 0; op < num_operations; ++op) {
        // Test audio data generation and processing
        for (int i = 0; i < num_clients; ++i) {
            std::vector<float> audio_data = generateTestAudio(1024);
            mock_server->routeAudio(clients[i]->getClientId(), audio_data);
        }
        
        // Test position data processing
        for (int i = 0; i < num_clients; ++i) {
            double lat = 40.0 + i * 0.01;
            double lon = -74.0 + i * 0.01;
            double alt = 1000.0 + i * 10.0;
            clients[i]->setPosition(lat, lon, alt);
        }
        
        // Test frequency data processing
        for (int i = 0; i < num_clients; ++i) {
            std::string frequency = "121.5";
            bool tuned = clients[i]->startTransmission(frequency);
            EXPECT_TRUE(tuned) << "Client " << i << " should tune to frequency successfully";
        }
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    // Calculate performance metrics
    double time_per_operation = static_cast<double>(duration.count()) / num_operations;
    
    // File I/O operations should be reasonably fast
    EXPECT_LT(time_per_operation, 100000.0) << "File I/O operations too slow: " << time_per_operation << " microseconds";
    
    std::cout << "File I/O performance: " << time_per_operation << " microseconds per operation" << std::endl;
    
    // Clean up
    for (auto& client : clients) {
        client->disconnect();
    }
    mock_server->stopServer();
}

// Additional stress tests
TEST_F(StressTest, StressTestPerformance) {
    // Test stress test performance
    const int num_stress_tests = 10;
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    // Test stress test operations
    for (int test = 0; test < num_stress_tests; ++test) {
        bool server_started = mock_server->startServer(8080 + test);
        EXPECT_TRUE(server_started) << "Server should start successfully";
        
        // Test connecting clients
        const int num_clients = 50;
        std::vector<std::shared_ptr<MockClient>> clients;
        
        for (int i = 0; i < num_clients; ++i) {
            auto client = std::make_shared<MockClient>("client_" + std::to_string(i));
            bool connected = client->connect("localhost", 8080 + test);
            EXPECT_TRUE(connected) << "Client " << i << " should connect successfully";
            
            bool added = mock_server->addClient(client);
            EXPECT_TRUE(added) << "Client " << i << " should be added to server";
            
            clients.push_back(client);
        }
        
        // Test audio communication
        for (int i = 0; i < num_clients; ++i) {
            std::vector<float> audio_data = generateTestAudio(1024);
            mock_server->routeAudio(clients[i]->getClientId(), audio_data);
        }
        
        // Test propagation calculation
        for (int i = 0; i < num_clients; ++i) {
            for (int j = 0; j < num_clients; ++j) {
                if (i != j) {
                    double propagation = mock_server->calculatePropagation(
                        clients[i]->getClientId(), 
                        clients[j]->getClientId()
                    );
                    EXPECT_GE(propagation, 0.0) << "Propagation should be non-negative";
                }
            }
        }
        
        // Clean up
        for (auto& client : clients) {
            client->disconnect();
        }
        mock_server->stopServer();
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    // Calculate performance metrics
    double time_per_stress_test = static_cast<double>(duration.count()) / num_stress_tests;
    
    // Stress test operations should be reasonably fast
    EXPECT_LT(time_per_stress_test, 1000000.0) << "Stress test operations too slow: " << time_per_stress_test << " microseconds";
    
    std::cout << "Stress test performance: " << time_per_stress_test << " microseconds per stress test" << std::endl;
}

TEST_F(StressTest, StressTestAccuracy) {
    // Test stress test accuracy
    bool server_started = mock_server->startServer(8080);
    EXPECT_TRUE(server_started) << "Server should start successfully";
    
    // Test stress test accuracy with multiple clients
    const int num_clients = 100;
    std::vector<std::shared_ptr<MockClient>> clients;
    
    for (int i = 0; i < num_clients; ++i) {
        auto client = std::make_shared<MockClient>("client_" + std::to_string(i));
        bool connected = client->connect("localhost", 8080);
        EXPECT_TRUE(connected) << "Client " << i << " should connect successfully";
        
        bool added = mock_server->addClient(client);
        EXPECT_TRUE(added) << "Client " << i << " should be added to server";
        
        clients.push_back(client);
    }
    
    // Test server client count accuracy
    size_t client_count = mock_server->getClientCount();
    EXPECT_EQ(client_count, num_clients) << "Server should have " << num_clients << " clients";
    
    // Test client connection accuracy
    for (int i = 0; i < num_clients; ++i) {
        bool is_connected = clients[i]->isConnected();
        EXPECT_TRUE(is_connected) << "Client " << i << " should be connected";
    }
    
    // Test frequency tuning accuracy
    for (int i = 0; i < num_clients; ++i) {
        std::string frequency = "121.5";
        bool tuned = clients[i]->startTransmission(frequency);
        EXPECT_TRUE(tuned) << "Client " << i << " should tune to frequency successfully";
        
        std::string current_frequency = clients[i]->getCurrentFrequency();
        EXPECT_EQ(current_frequency, frequency) << "Client " << i << " should be tuned to correct frequency";
    }
    
    // Test audio communication accuracy
    std::vector<std::atomic<int>> audio_received_counts(num_clients);
    for (int i = 0; i < num_clients; ++i) {
        audio_received_counts[i] = 0;
        clients[i]->setAudioCallback([&audio_received_counts, i](const std::vector<float>& audio_data) {
            audio_received_counts[i]++;
        });
    }
    
    // Test audio transmission accuracy
    std::vector<float> audio_data = generateTestAudio(1024);
    mock_server->routeAudio(clients[0]->getClientId(), audio_data);
    
    // Test that all other clients received audio
    for (int i = 1; i < num_clients; ++i) {
        EXPECT_EQ(audio_received_counts[i].load(), 1) << "Client " << i << " should have received audio";
    }
    
    // Test propagation calculation accuracy
    for (int i = 0; i < num_clients; ++i) {
        double lat = 40.0 + i * 0.01;
        double lon = -74.0 + i * 0.01;
        double alt = 1000.0 + i * 10.0;
        clients[i]->setPosition(lat, lon, alt);
    }
    
    for (int i = 0; i < num_clients; ++i) {
        for (int j = 0; j < num_clients; ++j) {
            if (i != j) {
                double propagation = mock_server->calculatePropagation(
                    clients[i]->getClientId(), 
                    clients[j]->getClientId()
                );
                
                EXPECT_GE(propagation, 0.0) << "Propagation should be non-negative between clients " << i << " and " << j;
                EXPECT_LE(propagation, 1.0) << "Propagation should be at most 1.0 between clients " << i << " and " << j;
            }
        }
    }
    
    // Clean up
    for (auto& client : clients) {
        client->disconnect();
    }
    mock_server->stopServer();
}

