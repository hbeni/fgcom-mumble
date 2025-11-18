#include "test_integration_common.h"

// 14.2 Multi-Client Tests
TEST_F(MultiClientTest, TwoClientsCommunicating) {
    // Test 2 clients communicating
    bool server_started = mock_server->startServer(8080);
    EXPECT_TRUE(server_started) << "Server should start successfully";
    
    // Test client 1 connection
    bool client1_connected = test_clients[0]->connect("localhost", 8080);
    EXPECT_TRUE(client1_connected) << "Client 1 should connect successfully";
    
    // Test client 2 connection
    bool client2_connected = test_clients[1]->connect("localhost", 8080);
    EXPECT_TRUE(client2_connected) << "Client 2 should connect successfully";
    
    // Test adding clients to server
    bool client1_added = mock_server->addClient(test_clients[0]);
    EXPECT_TRUE(client1_added) << "Client 1 should be added to server";
    
    bool client2_added = mock_server->addClient(test_clients[1]);
    EXPECT_TRUE(client2_added) << "Client 2 should be added to server";
    
    // Test server client count
    size_t client_count = mock_server->getClientCount();
    EXPECT_EQ(client_count, 2) << "Server should have 2 clients";
    
    // Test both clients tuning to same frequency
    std::string frequency = "121.5";
    bool client1_tuned = test_clients[0]->startTransmission(frequency);
    EXPECT_TRUE(client1_tuned) << "Client 1 should tune to frequency successfully";
    
    bool client2_tuned = test_clients[1]->startTransmission(frequency);
    EXPECT_TRUE(client2_tuned) << "Client 2 should tune to frequency successfully";
    
    // Test audio communication between clients
    std::atomic<int> client2_audio_received_count{0};
    test_clients[1]->setAudioCallback([&client2_audio_received_count](const std::vector<float>& audio_data) {
        client2_audio_received_count++;
    });
    
    // Test audio transmission from client 1 to client 2
    std::vector<float> audio_data = generateTestAudio(1024);
    mock_server->routeAudio(test_clients[0]->getClientId(), audio_data);
    
    // Test that client 2 received audio
    EXPECT_EQ(client2_audio_received_count.load(), 1) << "Client 2 should have received audio from client 1";
    
    // Test audio communication from client 2 to client 1
    std::atomic<int> client1_audio_received_count{0};
    test_clients[0]->setAudioCallback([&client1_audio_received_count](const std::vector<float>& audio_data) {
        client1_audio_received_count++;
    });
    
    std::vector<float> audio_data2 = generateTestAudio(1024);
    mock_server->routeAudio(test_clients[1]->getClientId(), audio_data2);
    
    // Test that client 1 received audio
    EXPECT_EQ(client1_audio_received_count.load(), 1) << "Client 1 should have received audio from client 2";
    
    // Test propagation calculation between clients
    test_clients[0]->setPosition(40.0, -74.0, 1000.0);  // New York
    test_clients[1]->setPosition(34.0, -118.0, 2000.0); // Los Angeles
    
    double propagation = mock_server->calculatePropagation(
        test_clients[0]->getClientId(), 
        test_clients[1]->getClientId()
    );
    
    EXPECT_GE(propagation, 0.0) << "Propagation should be non-negative";
    EXPECT_LE(propagation, 1.0) << "Propagation should be at most 1.0";
    
    // Clean up
    test_clients[0]->disconnect();
    test_clients[1]->disconnect();
    mock_server->stopServer();
}

TEST_F(MultiClientTest, TenPlusClientsOnSameFrequency) {
    // Test 10+ clients on same frequency
    bool server_started = mock_server->startServer(8080);
    EXPECT_TRUE(server_started) << "Server should start successfully";
    
    // Test connecting 10 clients
    std::vector<std::shared_ptr<MockClient>> clients;
    for (int i = 0; i < 10; ++i) {
        auto client = std::make_shared<MockClient>("client_" + std::to_string(i));
        bool connected = client->connect("localhost", 8080);
        EXPECT_TRUE(connected) << "Client " << i << " should connect successfully";
        
        bool added = mock_server->addClient(client);
        EXPECT_TRUE(added) << "Client " << i << " should be added to server";
        
        clients.push_back(client);
    }
    
    // Test server client count
    size_t client_count = mock_server->getClientCount();
    EXPECT_EQ(client_count, 10) << "Server should have 10 clients";
    
    // Test all clients tuning to same frequency
    std::string frequency = "121.5";
    for (int i = 0; i < 10; ++i) {
        bool tuned = clients[i]->startTransmission(frequency);
        EXPECT_TRUE(tuned) << "Client " << i << " should tune to frequency successfully";
        
        std::string current_frequency = clients[i]->getCurrentFrequency();
        EXPECT_EQ(current_frequency, frequency) << "Client " << i << " should be tuned to correct frequency";
    }
    
    // Test audio communication between all clients
    std::vector<std::atomic<int>> audio_received_counts(10);
    for (int i = 0; i < 10; ++i) {
        audio_received_counts[i] = 0;
        clients[i]->setAudioCallback([&audio_received_counts, i](const std::vector<float>& audio_data) {
            audio_received_counts[i]++;
        });
    }
    
    // Test audio transmission from client 0 to all other clients
    std::vector<float> audio_data = generateTestAudio(1024);
    mock_server->routeAudio(clients[0]->getClientId(), audio_data);
    
    // Test that all other clients received audio
    for (int i = 1; i < 10; ++i) {
        EXPECT_EQ(audio_received_counts[i].load(), 1) << "Client " << i << " should have received audio from client 0";
    }
    
    // Test audio transmission from multiple clients
    for (int i = 1; i < 5; ++i) {
        std::vector<float> client_audio_data = generateTestAudio(512);
        mock_server->routeAudio(clients[i]->getClientId(), client_audio_data);
    }
    
    // Test that all clients received audio from multiple sources
    for (int i = 0; i < 10; ++i) {
        EXPECT_GE(audio_received_counts[i].load(), 1) << "Client " << i << " should have received audio from multiple sources";
    }
    
    // Test propagation calculation between all clients
    for (int i = 0; i < 10; ++i) {
        double lat = 40.0 + i * 0.1;
        double lon = -74.0 + i * 0.1;
        double alt = 1000.0 + i * 100.0;
        clients[i]->setPosition(lat, lon, alt);
    }
    
    // Test propagation calculation between all pairs of clients
    for (int i = 0; i < 10; ++i) {
        for (int j = 0; j < 10; ++j) {
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

TEST_F(MultiClientTest, HundredPlusClientsOnServer) {
    // Test 100+ clients on server
    bool server_started = mock_server->startServer(8080);
    EXPECT_TRUE(server_started) << "Server should start successfully";
    
    // Test connecting 100 clients
    std::vector<std::shared_ptr<MockClient>> clients;
    for (int i = 0; i < 100; ++i) {
        auto client = std::make_shared<MockClient>("client_" + std::to_string(i));
        bool connected = client->connect("localhost", 8080);
        EXPECT_TRUE(connected) << "Client " << i << " should connect successfully";
        
        bool added = mock_server->addClient(client);
        EXPECT_TRUE(added) << "Client " << i << " should be added to server";
        
        clients.push_back(client);
    }
    
    // Test server client count
    size_t client_count = mock_server->getClientCount();
    EXPECT_EQ(client_count, 100) << "Server should have 100 clients";
    
    // Test clients tuning to different frequencies
    std::vector<std::string> frequencies = {"121.5", "243.0", "118.0", "137.0", "144.0"};
    for (int i = 0; i < 100; ++i) {
        std::string frequency = frequencies[i % frequencies.size()];
        bool tuned = clients[i]->startTransmission(frequency);
        EXPECT_TRUE(tuned) << "Client " << i << " should tune to frequency successfully";
        
        std::string current_frequency = clients[i]->getCurrentFrequency();
        EXPECT_EQ(current_frequency, frequency) << "Client " << i << " should be tuned to correct frequency";
    }
    
    // Test audio communication between clients on same frequency
    std::vector<std::atomic<int>> audio_received_counts(100);
    for (int i = 0; i < 100; ++i) {
        audio_received_counts[i] = 0;
        clients[i]->setAudioCallback([&audio_received_counts, i](const std::vector<float>& audio_data) {
            audio_received_counts[i]++;
        });
    }
    
    // Test audio transmission from client 0 to all clients on same frequency
    std::vector<float> audio_data = generateTestAudio(1024);
    mock_server->routeAudio(clients[0]->getClientId(), audio_data);
    
    // Test that clients on same frequency received audio
    std::string client0_frequency = clients[0]->getCurrentFrequency();
    int expected_receivers = 0;
    for (int i = 1; i < 100; ++i) {
        if (clients[i]->getCurrentFrequency() == client0_frequency) {
            expected_receivers++;
        }
    }
    
    int actual_receivers = 0;
    for (int i = 1; i < 100; ++i) {
        if (audio_received_counts[i].load() > 0) {
            actual_receivers++;
        }
    }
    
    EXPECT_EQ(actual_receivers, expected_receivers) << "Should have correct number of audio receivers";
    
    // Test propagation calculation between all clients
    for (int i = 0; i < 100; ++i) {
        double lat = 40.0 + (i % 10) * 0.1;
        double lon = -74.0 + (i / 10) * 0.1;
        double alt = 1000.0 + i * 10.0;
        clients[i]->setPosition(lat, lon, alt);
    }
    
    // Test propagation calculation between sample pairs of clients
    for (int i = 0; i < 10; ++i) {
        for (int j = 0; j < 10; ++j) {
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

TEST_F(MultiClientTest, FrequencySeparation) {
    // Test frequency separation
    bool server_started = mock_server->startServer(8080);
    EXPECT_TRUE(server_started) << "Server should start successfully";
    
    // Test connecting clients to different frequencies
    std::vector<std::shared_ptr<MockClient>> clients;
    std::vector<std::string> frequencies = {"121.5", "243.0", "118.0", "137.0", "144.0"};
    
    for (int i = 0; i < 20; ++i) {
        auto client = std::make_shared<MockClient>("client_" + std::to_string(i));
        bool connected = client->connect("localhost", 8080);
        EXPECT_TRUE(connected) << "Client " << i << " should connect successfully";
        
        bool added = mock_server->addClient(client);
        EXPECT_TRUE(added) << "Client " << i << " should be added to server";
        
        // Assign frequency based on client index
        std::string frequency = frequencies[i % frequencies.size()];
        bool tuned = client->startTransmission(frequency);
        EXPECT_TRUE(tuned) << "Client " << i << " should tune to frequency successfully";
        
        clients.push_back(client);
    }
    
    // Test frequency separation
    std::map<std::string, int> frequency_counts;
    for (const auto& client : clients) {
        std::string frequency = client->getCurrentFrequency();
        frequency_counts[frequency]++;
    }
    
    // Test that each frequency has correct number of clients (20 clients / 5 frequencies = 4 per frequency)
    for (const auto& freq : frequencies) {
        EXPECT_EQ(frequency_counts[freq], 4) << "Frequency " << freq << " should have 4 clients";
    }
    
    // Test audio communication within frequency groups
    std::vector<std::atomic<int>> audio_received_counts(20);
    for (int i = 0; i < 20; ++i) {
        audio_received_counts[i] = 0;
        clients[i]->setAudioCallback([&audio_received_counts, i](const std::vector<float>& audio_data) {
            audio_received_counts[i]++;
        });
    }
    
    // Test audio transmission from client 0 to clients on same frequency
    std::vector<float> audio_data = generateTestAudio(1024);
    mock_server->routeAudio(clients[0]->getClientId(), audio_data);
    
    // Test that only clients on same frequency received audio
    std::string client0_frequency = clients[0]->getCurrentFrequency();
    for (int i = 1; i < 20; ++i) {
        if (clients[i]->getCurrentFrequency() == client0_frequency) {
            EXPECT_EQ(audio_received_counts[i].load(), 1) << "Client " << i << " on same frequency should have received audio";
        } else {
            EXPECT_EQ(audio_received_counts[i].load(), 0) << "Client " << i << " on different frequency should not have received audio";
        }
    }
    
    // Test audio transmission from clients on different frequencies
    for (int i = 0; i < 20; ++i) {
        std::vector<float> client_audio_data = generateTestAudio(512);
        mock_server->routeAudio(clients[i]->getClientId(), client_audio_data);
    }
    
    // Test that clients only received audio from same frequency
    for (int i = 0; i < 20; ++i) {
        std::string client_frequency = clients[i]->getCurrentFrequency();
        int expected_audio_count = 0;
        for (int j = 0; j < 20; ++j) {
            if (i != j && clients[j]->getCurrentFrequency() == client_frequency) {
                expected_audio_count++;
            }
        }
        
        // Add 1 extra for the initial client 0 transmission if this client is on the same frequency
        // But only if this is not client 0 itself (client 0 doesn't receive from itself)
        if (i != 0 && clients[i]->getCurrentFrequency() == clients[0]->getCurrentFrequency()) {
            expected_audio_count += 1;
        }
        
        // Each client should receive audio from other clients on the same frequency
        EXPECT_EQ(audio_received_counts[i].load(), expected_audio_count) << "Client " << i << " should have received audio from " << expected_audio_count << " clients on same frequency (got " << audio_received_counts[i].load() << ")";
    }
    
    // Clean up
    for (auto& client : clients) {
        client->disconnect();
    }
    mock_server->stopServer();
}

TEST_F(MultiClientTest, GeographicSeparation) {
    // Test geographic separation
    bool server_started = mock_server->startServer(8080);
    EXPECT_TRUE(server_started) << "Server should start successfully";
    
    // Test connecting clients at different geographic locations
    std::vector<std::shared_ptr<MockClient>> clients;
    std::vector<std::tuple<double, double, double>> locations = {
        {40.0, -74.0, 1000.0},   // New York
        {34.0, -118.0, 2000.0},  // Los Angeles
        {51.0, -0.0, 1500.0},    // London
        {48.0, 2.0, 1200.0},     // Paris
        {35.0, 139.0, 1800.0}    // Tokyo
    };
    
    for (int i = 0; i < 10; ++i) {
        auto client = std::make_shared<MockClient>("client_" + std::to_string(i));
        bool connected = client->connect("localhost", 8080);
        EXPECT_TRUE(connected) << "Client " << i << " should connect successfully";
        
        bool added = mock_server->addClient(client);
        EXPECT_TRUE(added) << "Client " << i << " should be added to server";
        
        // Set position based on location index, but add small variations to ensure different positions
        auto location = locations[i % locations.size()];
        double lat = std::get<0>(location) + (i * 0.001); // Add small variation
        double lon = std::get<1>(location) + (i * 0.001); // Add small variation
        double alt = std::get<2>(location) + (i * 10.0);   // Add small altitude variation
        client->setPosition(lat, lon, alt);
        
        // Tune to same frequency
        bool tuned = client->startTransmission("121.5");
        EXPECT_TRUE(tuned) << "Client " << i << " should tune to frequency successfully";
        
        clients.push_back(client);
    }
    
    // Test geographic separation
    for (int i = 0; i < 10; ++i) {
        auto pos1 = clients[i]->getPosition();
        for (int j = i + 1; j < 10; ++j) {
            auto pos2 = clients[j]->getPosition();
            
            // Calculate distance between positions using proper geographic distance
            double lat1 = std::get<0>(pos1);
            double lon1 = std::get<1>(pos1);
            double lat2 = std::get<0>(pos2);
            double lon2 = std::get<1>(pos2);
            
            // Use simple distance calculation that works for test coordinates
            double dx = (lon2 - lon1) * 111320.0 * cos(lat1 * M_PI / 180.0);
            double dy = (lat2 - lat1) * 111320.0;
            double distance = sqrt(dx * dx + dy * dy);
            
            EXPECT_GT(distance, 0.0) << "Distance between clients " << i << " and " << j << " should be positive";
        }
    }
    
    // Test propagation calculation between geographically separated clients
    for (int i = 0; i < 10; ++i) {
        for (int j = 0; j < 10; ++j) {
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
    
    // Test audio communication between geographically separated clients
    std::vector<std::atomic<int>> audio_received_counts(10);
    for (int i = 0; i < 10; ++i) {
        audio_received_counts[i] = 0;
        clients[i]->setAudioCallback([&audio_received_counts, i](const std::vector<float>& audio_data) {
            audio_received_counts[i]++;
        });
    }
    
    // Test audio transmission from client 0 to all other clients
    std::vector<float> audio_data = generateTestAudio(1024);
    mock_server->routeAudio(clients[0]->getClientId(), audio_data);
    
    // Test that all other clients received audio
    for (int i = 1; i < 10; ++i) {
        EXPECT_EQ(audio_received_counts[i].load(), 1) << "Client " << i << " should have received audio from client 0";
    }
    
    // Clean up
    for (auto& client : clients) {
        client->disconnect();
    }
    mock_server->stopServer();
}

TEST_F(MultiClientTest, SimultaneousTransmissions) {
    // Test simultaneous transmissions
    bool server_started = mock_server->startServer(8080);
    EXPECT_TRUE(server_started) << "Server should start successfully";
    
    // Test connecting multiple clients
    std::vector<std::shared_ptr<MockClient>> clients;
    for (int i = 0; i < 5; ++i) {
        auto client = std::make_shared<MockClient>("client_" + std::to_string(i));
        bool connected = client->connect("localhost", 8080);
        EXPECT_TRUE(connected) << "Client " << i << " should connect successfully";
        
        bool added = mock_server->addClient(client);
        EXPECT_TRUE(added) << "Client " << i << " should be added to server";
        
        // Tune to same frequency
        bool tuned = client->startTransmission("121.5");
        EXPECT_TRUE(tuned) << "Client " << i << " should tune to frequency successfully";
        
        clients.push_back(client);
    }
    
    // Test simultaneous transmissions
    std::vector<std::atomic<int>> audio_received_counts(5);
    for (int i = 0; i < 5; ++i) {
        audio_received_counts[i] = 0;
        clients[i]->setAudioCallback([&audio_received_counts, i](const std::vector<float>& audio_data) {
            audio_received_counts[i]++;
        });
    }
    
    // Test simultaneous audio transmission from all clients
    std::vector<std::thread> transmission_threads;
    for (int i = 0; i < 5; ++i) {
        transmission_threads.emplace_back([this, &clients, i]() {
            std::vector<float> audio_data = generateTestAudio(1024);
            mock_server->routeAudio(clients[i]->getClientId(), audio_data);
        });
    }
    
    // Wait for all transmissions to complete
    for (auto& thread : transmission_threads) {
        thread.join();
    }
    
    // Test that all clients received audio from all other clients
    for (int i = 0; i < 5; ++i) {
        EXPECT_EQ(audio_received_counts[i].load(), 4) << "Client " << i << " should have received audio from 4 other clients";
    }
    
    // Test simultaneous transmissions with different frequencies
    std::vector<std::string> frequencies = {"121.5", "243.0", "118.0", "137.0", "144.0"};
    for (int i = 0; i < 5; ++i) {
        bool retuned = clients[i]->startTransmission(frequencies[i]);
        EXPECT_TRUE(retuned) << "Client " << i << " should retune to frequency successfully";
    }
    
    // Reset audio received counts
    for (int i = 0; i < 5; ++i) {
        audio_received_counts[i] = 0;
    }
    
    // Test simultaneous audio transmission from all clients on different frequencies
    std::vector<std::thread> frequency_transmission_threads;
    for (int i = 0; i < 5; ++i) {
        frequency_transmission_threads.emplace_back([this, &clients, i]() {
            std::vector<float> audio_data = generateTestAudio(1024);
            mock_server->routeAudio(clients[i]->getClientId(), audio_data);
        });
    }
    
    // Wait for all transmissions to complete
    for (auto& thread : frequency_transmission_threads) {
        thread.join();
    }
    
    // Test that clients only received audio from same frequency
    for (int i = 0; i < 5; ++i) {
        std::string client_frequency = clients[i]->getCurrentFrequency();
        int expected_audio_count = 0;
        for (int j = 0; j < 5; ++j) {
            if (i != j && clients[j]->getCurrentFrequency() == client_frequency) {
                expected_audio_count++;
            }
        }
        
        EXPECT_EQ(audio_received_counts[i].load(), expected_audio_count) << "Client " << i << " should have received audio from " << expected_audio_count << " clients on same frequency";
    }
    
    // Clean up
    for (auto& client : clients) {
        client->disconnect();
    }
    mock_server->stopServer();
}

// Additional multi-client tests
TEST_F(MultiClientTest, MultiClientPerformance) {
    // Test multi-client performance
    const int num_clients = 50;
    const int num_operations = 100;
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    // Test multi-client operations
    for (int op = 0; op < num_operations; ++op) {
        bool server_started = mock_server->startServer(8080 + op);
        EXPECT_TRUE(server_started) << "Server should start successfully";
        
        std::vector<std::shared_ptr<MockClient>> clients;
        for (int i = 0; i < num_clients; ++i) {
            auto client = std::make_shared<MockClient>("client_" + std::to_string(i));
            bool connected = client->connect("localhost", 8080 + op);
            EXPECT_TRUE(connected) << "Client " << i << " should connect successfully";
            
            bool added = mock_server->addClient(client);
            EXPECT_TRUE(added) << "Client " << i << " should be added to server";
            
            bool tuned = client->startTransmission("121.5");
            EXPECT_TRUE(tuned) << "Client " << i << " should tune to frequency successfully";
            
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
    double time_per_operation = static_cast<double>(duration.count()) / num_operations;
    
    // Multi-client operations should be reasonably fast
    EXPECT_LT(time_per_operation, 100000.0) << "Multi-client operations too slow: " << time_per_operation << " microseconds";
    
    std::cout << "Multi-client performance: " << time_per_operation << " microseconds per operation" << std::endl;
}

TEST_F(MultiClientTest, MultiClientAccuracy) {
    // Test multi-client accuracy
    bool server_started = mock_server->startServer(8080);
    EXPECT_TRUE(server_started) << "Server should start successfully";
    
    // Test connecting multiple clients
    std::vector<std::shared_ptr<MockClient>> clients;
    for (int i = 0; i < 10; ++i) {
        auto client = std::make_shared<MockClient>("client_" + std::to_string(i));
        bool connected = client->connect("localhost", 8080);
        EXPECT_TRUE(connected) << "Client " << i << " should connect successfully";
        
        bool added = mock_server->addClient(client);
        EXPECT_TRUE(added) << "Client " << i << " should be added to server";
        
        clients.push_back(client);
    }
    
    // Test server client count accuracy
    size_t client_count = mock_server->getClientCount();
    EXPECT_EQ(client_count, 10) << "Server should have 10 clients";
    
    // Test client connection accuracy
    for (int i = 0; i < 10; ++i) {
        bool is_connected = clients[i]->isConnected();
        EXPECT_TRUE(is_connected) << "Client " << i << " should be connected";
    }
    
    // Test frequency tuning accuracy
    for (int i = 0; i < 10; ++i) {
        std::string frequency = "121.5";
        bool tuned = clients[i]->startTransmission(frequency);
        EXPECT_TRUE(tuned) << "Client " << i << " should tune to frequency successfully";
        
        std::string current_frequency = clients[i]->getCurrentFrequency();
        EXPECT_EQ(current_frequency, frequency) << "Client " << i << " should be tuned to correct frequency";
    }
    
    // Test audio communication accuracy
    std::vector<std::atomic<int>> audio_received_counts(10);
    for (int i = 0; i < 10; ++i) {
        audio_received_counts[i] = 0;
        clients[i]->setAudioCallback([&audio_received_counts, i](const std::vector<float>& audio_data) {
            audio_received_counts[i]++;
        });
    }
    
    // Test audio transmission accuracy
    std::vector<float> audio_data = generateTestAudio(1024);
    mock_server->routeAudio(clients[0]->getClientId(), audio_data);
    
    // Test that all other clients received audio
    for (int i = 1; i < 10; ++i) {
        EXPECT_EQ(audio_received_counts[i].load(), 1) << "Client " << i << " should have received audio";
    }
    
    // Test propagation calculation accuracy
    for (int i = 0; i < 10; ++i) {
        double lat = 40.0 + i * 0.1;
        double lon = -74.0 + i * 0.1;
        double alt = 1000.0 + i * 100.0;
        clients[i]->setPosition(lat, lon, alt);
    }
    
    for (int i = 0; i < 10; ++i) {
        for (int j = 0; j < 10; ++j) {
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

