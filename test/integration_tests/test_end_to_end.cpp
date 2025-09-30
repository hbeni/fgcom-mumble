#include "test_integration_common.h"

// 14.1 End-to-End Tests
TEST_F(EndToEndTest, ClientConnectsToServer) {
    // Test client connection to server
    bool server_started = mock_server->startServer(8080);
    EXPECT_TRUE(server_started) << "Server should start successfully";
    
    // Test client connection
    bool client_connected = test_clients[0]->connect("localhost", 8080);
    EXPECT_TRUE(client_connected) << "Client should connect successfully";
    
    // Test that client is connected
    bool is_connected = test_clients[0]->isConnected();
    EXPECT_TRUE(is_connected) << "Client should be connected";
    
    // Test server client count
    size_t client_count = mock_server->getClientCount();
    EXPECT_EQ(client_count, 0) << "Server should have 0 clients before adding";
    
    // Test adding client to server
    bool client_added = mock_server->addClient(test_clients[0]);
    EXPECT_TRUE(client_added) << "Client should be added to server";
    
    // Test server client count after adding
    client_count = mock_server->getClientCount();
    EXPECT_EQ(client_count, 1) << "Server should have 1 client after adding";
    
    // Test client disconnection
    test_clients[0]->disconnect();
    is_connected = test_clients[0]->isConnected();
    EXPECT_FALSE(is_connected) << "Client should be disconnected";
    
    // Test removing client from server
    mock_server->removeClient(test_clients[0]->getClientId());
    client_count = mock_server->getClientCount();
    EXPECT_EQ(client_count, 0) << "Server should have 0 clients after removal";
    
    // Clean up
    mock_server->stopServer();
}

TEST_F(EndToEndTest, TunesToFrequency) {
    // Test client tuning to frequency
    bool server_started = mock_server->startServer(8080);
    EXPECT_TRUE(server_started) << "Server should start successfully";
    
    // Test client connection
    bool client_connected = test_clients[0]->connect("localhost", 8080);
    EXPECT_TRUE(client_connected) << "Client should connect successfully";
    
    // Test adding client to server
    bool client_added = mock_server->addClient(test_clients[0]);
    EXPECT_TRUE(client_added) << "Client should be added to server";
    
    // Test tuning to frequency
    std::string frequency = "121.5";
    bool tuned = test_clients[0]->startTransmission(frequency);
    EXPECT_TRUE(tuned) << "Client should tune to frequency successfully";
    
    // Test that client is tuned to frequency
    std::string current_frequency = test_clients[0]->getCurrentFrequency();
    EXPECT_EQ(current_frequency, frequency) << "Client should be tuned to correct frequency";
    
    // Test tuning to different frequency
    std::string new_frequency = "243.0";
    bool retuned = test_clients[0]->startTransmission(new_frequency);
    EXPECT_TRUE(retuned) << "Client should retune to new frequency successfully";
    
    // Test that client is tuned to new frequency
    current_frequency = test_clients[0]->getCurrentFrequency();
    EXPECT_EQ(current_frequency, new_frequency) << "Client should be tuned to new frequency";
    
    // Test stopping transmission
    test_clients[0]->stopTransmission();
    bool is_transmitting = test_clients[0]->isTransmitting();
    EXPECT_FALSE(is_transmitting) << "Client should not be transmitting";
    
    // Clean up
    test_clients[0]->disconnect();
    mock_server->stopServer();
}

TEST_F(EndToEndTest, TransmitsAudio) {
    // Test audio transmission
    bool server_started = mock_server->startServer(8080);
    EXPECT_TRUE(server_started) << "Server should start successfully";
    
    // Test client connection
    bool client_connected = test_clients[0]->connect("localhost", 8080);
    EXPECT_TRUE(client_connected) << "Client should connect successfully";
    
    // Test adding client to server
    bool client_added = mock_server->addClient(test_clients[0]);
    EXPECT_TRUE(client_added) << "Client should be added to server";
    
    // Test tuning to frequency
    std::string frequency = "121.5";
    bool tuned = test_clients[0]->startTransmission(frequency);
    EXPECT_TRUE(tuned) << "Client should tune to frequency successfully";
    
    // Test audio transmission
    std::vector<float> audio_data = generateTestAudio(1024);
    mock_server->routeAudio(test_clients[0]->getClientId(), audio_data);
    
    // Test that client is transmitting
    bool is_transmitting = test_clients[0]->isTransmitting();
    EXPECT_TRUE(is_transmitting) << "Client should be transmitting";
    
    // Test audio transmission with different frequencies
    for (const auto& freq : test_frequencies) {
        bool tuned_to_freq = test_clients[0]->startTransmission(freq);
        EXPECT_TRUE(tuned_to_freq) << "Client should tune to frequency " << freq;
        
        std::vector<float> freq_audio_data = generateTestAudio(512);
        mock_server->routeAudio(test_clients[0]->getClientId(), freq_audio_data);
        
        std::string current_frequency = test_clients[0]->getCurrentFrequency();
        EXPECT_EQ(current_frequency, freq) << "Client should be tuned to " << freq;
    }
    
    // Test stopping transmission
    test_clients[0]->stopTransmission();
    is_transmitting = test_clients[0]->isTransmitting();
    EXPECT_FALSE(is_transmitting) << "Client should not be transmitting";
    
    // Clean up
    test_clients[0]->disconnect();
    mock_server->stopServer();
}

TEST_F(EndToEndTest, ReceivesAudio) {
    // Test audio reception
    bool server_started = mock_server->startServer(8080);
    EXPECT_TRUE(server_started) << "Server should start successfully";
    
    // Test client connection
    bool client_connected = test_clients[0]->connect("localhost", 8080);
    EXPECT_TRUE(client_connected) << "Client should connect successfully";
    
    // Test adding client to server
    bool client_added = mock_server->addClient(test_clients[0]);
    EXPECT_TRUE(client_added) << "Client should be added to server";
    
    // Test audio reception callback
    std::atomic<int> audio_received_count{0};
    test_clients[0]->setAudioCallback([&audio_received_count](const std::vector<float>& audio_data) {
        audio_received_count++;
    });
    
    // Test tuning to frequency
    std::string frequency = "121.5";
    bool tuned = test_clients[0]->startTransmission(frequency);
    EXPECT_TRUE(tuned) << "Client should tune to frequency successfully";
    
    // Test audio reception
    std::vector<float> audio_data = generateTestAudio(1024);
    test_clients[0]->receiveAudio(audio_data);
    
    // Test that audio was received
    EXPECT_EQ(audio_received_count.load(), 1) << "Client should have received audio";
    
    // Test audio reception with different frequencies
    for (const auto& freq : test_frequencies) {
        bool tuned_to_freq = test_clients[0]->startTransmission(freq);
        EXPECT_TRUE(tuned_to_freq) << "Client should tune to frequency " << freq;
        
        std::vector<float> freq_audio_data = generateTestAudio(512);
        test_clients[0]->receiveAudio(freq_audio_data);
        
        std::string current_frequency = test_clients[0]->getCurrentFrequency();
        EXPECT_EQ(current_frequency, freq) << "Client should be tuned to " << freq;
    }
    
    // Test audio reception with multiple clients
    // First ensure client 1 is on the frequency
    bool client1_tuned = test_clients[0]->startTransmission(frequency);
    EXPECT_TRUE(client1_tuned) << "Client 1 should tune to frequency successfully";
    
    auto client2 = std::make_shared<MockClient>("client_2");
    bool client2_connected = client2->connect("localhost", 8080);
    EXPECT_TRUE(client2_connected) << "Client 2 should connect successfully";
    
    bool client2_added = mock_server->addClient(client2);
    EXPECT_TRUE(client2_added) << "Client 2 should be added to server";
    
    bool client2_tuned = client2->startTransmission(frequency);
    EXPECT_TRUE(client2_tuned) << "Client 2 should tune to frequency successfully";
    
    std::atomic<int> client2_audio_received_count{0};
    client2->setAudioCallback([&client2_audio_received_count](const std::vector<float>& audio_data) {
        client2_audio_received_count++;
    });
    
    // Test audio routing between clients
    std::vector<float> routing_audio_data = generateTestAudio(1024);
    mock_server->routeAudio(test_clients[0]->getClientId(), routing_audio_data);
    
    // Test that audio was routed to client 2
    EXPECT_EQ(client2_audio_received_count.load(), 1) << "Client 2 should have received audio";
    
    // Clean up
    test_clients[0]->disconnect();
    client2->disconnect();
    mock_server->stopServer();
}

TEST_F(EndToEndTest, PropagationCalculatedCorrectly) {
    // Test propagation calculation
    bool server_started = mock_server->startServer(8080);
    EXPECT_TRUE(server_started) << "Server should start successfully";
    
    // Test client connections
    bool client1_connected = test_clients[0]->connect("localhost", 8080);
    EXPECT_TRUE(client1_connected) << "Client 1 should connect successfully";
    
    bool client2_connected = test_clients[1]->connect("localhost", 8080);
    EXPECT_TRUE(client2_connected) << "Client 2 should connect successfully";
    
    // Test adding clients to server
    bool client1_added = mock_server->addClient(test_clients[0]);
    EXPECT_TRUE(client1_added) << "Client 1 should be added to server";
    
    bool client2_added = mock_server->addClient(test_clients[1]);
    EXPECT_TRUE(client2_added) << "Client 2 should be added to server";
    
    // Test setting client positions
    test_clients[0]->setPosition(40.0, -74.0, 1000.0);  // New York
    test_clients[1]->setPosition(34.0, -118.0, 2000.0); // Los Angeles
    
    // Test propagation calculation
    double propagation = mock_server->calculatePropagation(
        test_clients[0]->getClientId(), 
        test_clients[1]->getClientId()
    );
    
    EXPECT_GE(propagation, 0.0) << "Propagation should be non-negative";
    EXPECT_LE(propagation, 1.0) << "Propagation should be at most 1.0";
    
    // Test propagation calculation with different positions
    test_clients[0]->setPosition(51.0, -0.0, 1500.0);   // London
    test_clients[1]->setPosition(48.0, 2.0, 1200.0);    // Paris
    
    double propagation2 = mock_server->calculatePropagation(
        test_clients[0]->getClientId(), 
        test_clients[1]->getClientId()
    );
    
    EXPECT_GE(propagation2, 0.0) << "Propagation 2 should be non-negative";
    EXPECT_LE(propagation2, 1.0) << "Propagation 2 should be at most 1.0";
    
    // Test propagation calculation with same position
    test_clients[0]->setPosition(40.0, -74.0, 1000.0);
    test_clients[1]->setPosition(40.0, -74.0, 1000.0);
    
    double propagation3 = mock_server->calculatePropagation(
        test_clients[0]->getClientId(), 
        test_clients[1]->getClientId()
    );
    
    EXPECT_GE(propagation3, 0.0) << "Propagation 3 should be non-negative";
    EXPECT_LE(propagation3, 1.0) << "Propagation 3 should be at most 1.0";
    
    // Test propagation calculation with different altitudes
    test_clients[0]->setPosition(40.0, -74.0, 1000.0);
    test_clients[1]->setPosition(40.0, -74.0, 10000.0);
    
    double propagation4 = mock_server->calculatePropagation(
        test_clients[0]->getClientId(), 
        test_clients[1]->getClientId()
    );
    
    EXPECT_GE(propagation4, 0.0) << "Propagation 4 should be non-negative";
    EXPECT_LE(propagation4, 1.0) << "Propagation 4 should be at most 1.0";
    
    // Clean up
    test_clients[0]->disconnect();
    test_clients[1]->disconnect();
    mock_server->stopServer();
}

TEST_F(EndToEndTest, ATISPlaybackWorks) {
    // Test ATIS playback
    bool server_started = mock_server->startServer(8080);
    EXPECT_TRUE(server_started) << "Server should start successfully";
    
    // Test client connection
    bool client_connected = test_clients[0]->connect("localhost", 8080);
    EXPECT_TRUE(client_connected) << "Client should connect successfully";
    
    // Test adding client to server
    bool client_added = mock_server->addClient(test_clients[0]);
    EXPECT_TRUE(client_added) << "Client should be added to server";
    
    // Test ATIS playback start
    std::string atis_frequency = "121.5";
    mock_server->startATISPlayback(atis_frequency);
    
    // Test that ATIS is active
    bool atis_active = mock_server->isATISActive(atis_frequency);
    EXPECT_TRUE(atis_active) << "ATIS should be active";
    
    // Test ATIS playback with different frequencies
    for (const auto& freq : test_frequencies) {
        mock_server->startATISPlayback(freq);
        bool atis_active_freq = mock_server->isATISActive(freq);
        EXPECT_TRUE(atis_active_freq) << "ATIS should be active for frequency " << freq;
    }
    
    // Test ATIS playback stop
    mock_server->stopATISPlayback(atis_frequency);
    bool atis_inactive = mock_server->isATISActive(atis_frequency);
    EXPECT_FALSE(atis_inactive) << "ATIS should be inactive";
    
    // Test ATIS playback with multiple frequencies
    std::vector<std::string> atis_frequencies = {"121.5", "243.0", "118.0"};
    for (const auto& freq : atis_frequencies) {
        mock_server->startATISPlayback(freq);
        bool atis_active_freq = mock_server->isATISActive(freq);
        EXPECT_TRUE(atis_active_freq) << "ATIS should be active for frequency " << freq;
    }
    
    // Test stopping all ATIS playback
    for (const auto& freq : atis_frequencies) {
        mock_server->stopATISPlayback(freq);
        bool atis_inactive_freq = mock_server->isATISActive(freq);
        EXPECT_FALSE(atis_inactive_freq) << "ATIS should be inactive for frequency " << freq;
    }
    
    // Clean up
    test_clients[0]->disconnect();
    mock_server->stopServer();
}

TEST_F(EndToEndTest, RDFDetectionWorks) {
    // Test RDF detection
    bool server_started = mock_server->startServer(8080);
    EXPECT_TRUE(server_started) << "Server should start successfully";
    
    // Test client connection
    bool client_connected = test_clients[0]->connect("localhost", 8080);
    EXPECT_TRUE(client_connected) << "Client should connect successfully";
    
    // Test adding client to server
    bool client_added = mock_server->addClient(test_clients[0]);
    EXPECT_TRUE(client_added) << "Client should be added to server";
    
    // Test RDF detection start
    std::string rdf_frequency = "121.5";
    mock_server->startRDFDetection(rdf_frequency);
    
    // Test that RDF is active
    bool rdf_active = mock_server->isRDFActive(rdf_frequency);
    EXPECT_TRUE(rdf_active) << "RDF should be active";
    
    // Test RDF detection with different frequencies
    for (const auto& freq : test_frequencies) {
        mock_server->startRDFDetection(freq);
        bool rdf_active_freq = mock_server->isRDFActive(freq);
        EXPECT_TRUE(rdf_active_freq) << "RDF should be active for frequency " << freq;
    }
    
    // Test RDF detection stop
    mock_server->stopRDFDetection(rdf_frequency);
    bool rdf_inactive = mock_server->isRDFActive(rdf_frequency);
    EXPECT_FALSE(rdf_inactive) << "RDF should be inactive";
    
    // Test RDF detection with multiple frequencies
    std::vector<std::string> rdf_frequencies = {"121.5", "243.0", "118.0"};
    for (const auto& freq : rdf_frequencies) {
        mock_server->startRDFDetection(freq);
        bool rdf_active_freq = mock_server->isRDFActive(freq);
        EXPECT_TRUE(rdf_active_freq) << "RDF should be active for frequency " << freq;
    }
    
    // Test stopping all RDF detection
    for (const auto& freq : rdf_frequencies) {
        mock_server->stopRDFDetection(freq);
        bool rdf_inactive_freq = mock_server->isRDFActive(freq);
        EXPECT_FALSE(rdf_inactive_freq) << "RDF should be inactive for frequency " << freq;
    }
    
    // Clean up
    test_clients[0]->disconnect();
    mock_server->stopServer();
}

// Additional end-to-end tests
TEST_F(EndToEndTest, EndToEndPerformance) {
    // Test end-to-end performance
    const int num_operations = 100;
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    // Test end-to-end operations
    for (int i = 0; i < num_operations; ++i) {
        bool server_started = mock_server->startServer(8080 + i);
        EXPECT_TRUE(server_started) << "Server should start successfully";
        
        bool client_connected = test_clients[0]->connect("localhost", 8080 + i);
        EXPECT_TRUE(client_connected) << "Client should connect successfully";
        
        bool client_added = mock_server->addClient(test_clients[0]);
        EXPECT_TRUE(client_added) << "Client should be added to server";
        
        bool tuned = test_clients[0]->startTransmission("121.5");
        EXPECT_TRUE(tuned) << "Client should tune to frequency successfully";
        
        std::vector<float> audio_data = generateTestAudio(1024);
        mock_server->routeAudio(test_clients[0]->getClientId(), audio_data);
        
        double propagation = mock_server->calculatePropagation(
            test_clients[0]->getClientId(), 
            test_clients[0]->getClientId()
        );
        EXPECT_GE(propagation, 0.0) << "Propagation should be non-negative";
        
        test_clients[0]->disconnect();
        mock_server->stopServer();
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    // Calculate performance metrics
    double time_per_operation = static_cast<double>(duration.count()) / num_operations;
    
    // End-to-end operations should be reasonably fast
    EXPECT_LT(time_per_operation, 10000.0) << "End-to-end operations too slow: " << time_per_operation << " microseconds";
    
    std::cout << "End-to-end performance: " << time_per_operation << " microseconds per operation" << std::endl;
}

TEST_F(EndToEndTest, EndToEndAccuracy) {
    // Test end-to-end accuracy
    bool server_started = mock_server->startServer(8080);
    EXPECT_TRUE(server_started) << "Server should start successfully";
    
    // Test client connection accuracy
    bool client_connected = test_clients[0]->connect("localhost", 8080);
    EXPECT_TRUE(client_connected) << "Client connection should be accurate";
    
    // Test client status accuracy
    bool is_connected = test_clients[0]->isConnected();
    EXPECT_TRUE(is_connected) << "Client connection status should be accurate";
    
    // Test frequency tuning accuracy
    std::string frequency = "121.5";
    bool tuned = test_clients[0]->startTransmission(frequency);
    EXPECT_TRUE(tuned) << "Frequency tuning should be accurate";
    
    std::string current_frequency = test_clients[0]->getCurrentFrequency();
    EXPECT_EQ(current_frequency, frequency) << "Current frequency should be accurate";
    
    // Test audio transmission accuracy
    std::vector<float> audio_data = generateTestAudio(1024);
    mock_server->routeAudio(test_clients[0]->getClientId(), audio_data);
    
    bool is_transmitting = test_clients[0]->isTransmitting();
    EXPECT_TRUE(is_transmitting) << "Audio transmission status should be accurate";
    
    // Test propagation calculation accuracy
    test_clients[0]->setPosition(40.0, -74.0, 1000.0);
    double propagation = mock_server->calculatePropagation(
        test_clients[0]->getClientId(), 
        test_clients[0]->getClientId()
    );
    EXPECT_GE(propagation, 0.0) << "Propagation calculation should be accurate";
    EXPECT_LE(propagation, 1.0) << "Propagation calculation should be accurate";
    
    // Test ATIS playback accuracy
    mock_server->startATISPlayback(frequency);
    bool atis_active = mock_server->isATISActive(frequency);
    EXPECT_TRUE(atis_active) << "ATIS playback status should be accurate";
    
    // Test RDF detection accuracy
    mock_server->startRDFDetection(frequency);
    bool rdf_active = mock_server->isRDFActive(frequency);
    EXPECT_TRUE(rdf_active) << "RDF detection status should be accurate";
    
    // Clean up
    test_clients[0]->disconnect();
    mock_server->stopServer();
}

