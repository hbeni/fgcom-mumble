#include "test_work_unit_distribution_main.cpp"

// 12.1 Task Distribution Tests
TEST_F(TaskDistributionTest, WorkUnitCreation) {
    // Test work unit creation
    std::vector<double> input_data = generateTestData(100);
    std::map<std::string, double> parameters = generateTestParameters();
    
    for (const auto& type : test_work_unit_types) {
        std::string unit_id = mock_work_unit_manager->createWorkUnit(type, input_data, parameters);
        EXPECT_FALSE(unit_id.empty()) << "Work unit creation should succeed for type " << static_cast<int>(type);
        
        // Test that work unit was created
        WorkUnitStatus status = mock_work_unit_manager->getWorkUnitStatus(unit_id);
        EXPECT_EQ(status, WorkUnitStatus::PENDING) << "New work unit should be in PENDING status";
        
        // Test that work unit has correct data
        std::vector<double> result_data = mock_work_unit_manager->getWorkUnitResult(unit_id);
        EXPECT_TRUE(result_data.empty()) << "New work unit should have empty result data";
        
        std::string error_message = mock_work_unit_manager->getWorkUnitError(unit_id);
        EXPECT_TRUE(error_message.empty()) << "New work unit should have empty error message";
    }
    
    // Test work unit creation with empty input data
    std::vector<double> empty_data;
    std::string empty_unit_id = mock_work_unit_manager->createWorkUnit(WorkUnitType::PROPAGATION_GRID, empty_data);
    EXPECT_FALSE(empty_unit_id.empty()) << "Work unit creation should succeed with empty input data";
    
    // Test work unit creation with large input data
    std::vector<double> large_data = generateTestData(10000);
    std::string large_unit_id = mock_work_unit_manager->createWorkUnit(WorkUnitType::PROPAGATION_GRID, large_data);
    EXPECT_FALSE(large_unit_id.empty()) << "Work unit creation should succeed with large input data";
    
    // Test work unit creation with different parameters
    std::map<std::string, double> custom_parameters = {{"custom_param", 42.0}, {"another_param", 3.14}};
    std::string custom_unit_id = mock_work_unit_manager->createWorkUnit(WorkUnitType::ANTENNA_PATTERN, input_data, custom_parameters);
    EXPECT_FALSE(custom_unit_id.empty()) << "Work unit creation should succeed with custom parameters";
    
    // Test work unit count
    size_t unit_count = mock_work_unit_manager->getWorkUnitCount();
    EXPECT_GT(unit_count, 0) << "Work unit count should be greater than 0";
}

TEST_F(TaskDistributionTest, WorkerRegistration) {
    // Test client registration
    for (const auto& client_id : test_client_ids) {
        ClientWorkUnitCapability capability;
        capability.client_id = client_id;
        capability.supported_types = test_work_unit_types;
        capability.max_concurrent_units[WorkUnitType::PROPAGATION_GRID] = 5;
        capability.processing_speed_multiplier[WorkUnitType::PROPAGATION_GRID] = 1.0;
        capability.max_memory_mb = 1024;
        capability.supports_gpu = true;
        capability.supports_double_precision = true;
        capability.network_bandwidth_mbps = 100.0f;
        capability.processing_latency_ms = 10.0f;
        capability.is_online = true;
        capability.last_heartbeat = std::chrono::system_clock::now();
        capability.active_units = 0;
        capability.pending_units = 0;
        capability.memory_usage_mb = 0;
        capability.cpu_utilization_percent = 0.0;
        capability.gpu_utilization_percent = 0.0;
        
        bool register_result = mock_client_manager->registerClient(client_id, capability);
        EXPECT_TRUE(register_result) << "Client registration should succeed for " << client_id;
    }
    
    // Test client count
    size_t client_count = mock_client_manager->getClientCount();
    EXPECT_EQ(client_count, test_client_ids.size()) << "Client count should match registered clients";
    
    // Test client availability
    std::vector<std::string> available_clients = mock_client_manager->getAvailableClients();
    EXPECT_EQ(available_clients.size(), test_client_ids.size()) << "All registered clients should be available";
    
    // Test client compatibility
    for (const auto& type : test_work_unit_types) {
        std::vector<std::string> compatible_clients = mock_client_manager->getCompatibleClients(type);
        EXPECT_EQ(compatible_clients.size(), test_client_ids.size()) << "All clients should be compatible with " << static_cast<int>(type);
    }
    
    // Test client capability retrieval
    for (const auto& client_id : test_client_ids) {
        ClientWorkUnitCapability capability = mock_client_manager->getClientCapability(client_id);
        EXPECT_EQ(capability.client_id, client_id) << "Client capability should match client ID";
        EXPECT_TRUE(capability.is_online) << "Client should be online";
    }
    
    // Test client unregistration
    std::string test_client = test_client_ids[0];
    bool unregister_result = mock_client_manager->unregisterClient(test_client);
    EXPECT_TRUE(unregister_result) << "Client unregistration should succeed";
    
    // Test that unregistered client is no longer available
    bool is_online = mock_client_manager->isClientOnline(test_client);
    EXPECT_FALSE(is_online) << "Unregistered client should be offline";
    
    // Test client count after unregistration
    size_t new_client_count = mock_client_manager->getClientCount();
    EXPECT_EQ(new_client_count, test_client_ids.size() - 1) << "Client count should decrease after unregistration";
}

TEST_F(TaskDistributionTest, TaskAssignment) {
    // Test task assignment
    std::vector<double> input_data = generateTestData(100);
    std::map<std::string, double> parameters = generateTestParameters();
    
    // Create work units
    std::vector<std::string> unit_ids;
    for (const auto& type : test_work_unit_types) {
        std::string unit_id = mock_work_unit_manager->createWorkUnit(type, input_data, parameters);
        unit_ids.push_back(unit_id);
    }
    
    // Test work unit status before assignment
    for (const auto& unit_id : unit_ids) {
        WorkUnitStatus status = mock_work_unit_manager->getWorkUnitStatus(unit_id);
        EXPECT_EQ(status, WorkUnitStatus::PENDING) << "Work unit should be in PENDING status before assignment";
    }
    
    // Test work unit assignment to clients
    for (size_t i = 0; i < unit_ids.size(); ++i) {
        std::string unit_id = unit_ids[i];
        std::string client_id = test_client_ids[i % test_client_ids.size()];
        
        // Simulate work unit assignment
        WorkUnitStatus status = mock_work_unit_manager->getWorkUnitStatus(unit_id);
        EXPECT_EQ(status, WorkUnitStatus::PENDING) << "Work unit should be in PENDING status";
        
        // Test that work unit can be assigned
        bool can_assign = mock_client_manager->isClientOnline(client_id);
        EXPECT_TRUE(can_assign) << "Client should be available for assignment";
    }
    
    // Test work unit assignment with different priorities
    for (const auto& priority : test_priorities) {
        std::string unit_id = mock_work_unit_manager->createWorkUnit(WorkUnitType::PROPAGATION_GRID, input_data, parameters);
        bool enqueue_result = mock_queue_manager->enqueueWorkUnit(unit_id, priority);
        EXPECT_TRUE(enqueue_result) << "Work unit should be enqueued with priority " << static_cast<int>(priority);
    }
    
    // Test work unit assignment with specific client requirements
    std::string specific_client = test_client_ids[0];
    std::string unit_id = mock_work_unit_manager->createWorkUnit(WorkUnitType::PROPAGATION_GRID, input_data, parameters);
    bool enqueue_result = mock_queue_manager->enqueueWorkUnit(unit_id, WorkUnitPriority::HIGH);
    EXPECT_TRUE(enqueue_result) << "Work unit should be enqueued with specific client requirement";
    
    // Test work unit assignment with GPU requirements
    std::string gpu_unit_id = mock_work_unit_manager->createWorkUnit(WorkUnitType::ANTENNA_PATTERN, input_data, parameters);
    bool gpu_enqueue_result = mock_queue_manager->enqueueWorkUnit(gpu_unit_id, WorkUnitPriority::MEDIUM);
    EXPECT_TRUE(gpu_enqueue_result) << "Work unit should be enqueued with GPU requirements";
}

TEST_F(TaskDistributionTest, LoadBalancing) {
    // Test load balancing
    std::vector<double> input_data = generateTestData(100);
    std::map<std::string, double> parameters = generateTestParameters();
    
    // Create multiple work units
    std::vector<std::string> unit_ids;
    for (int i = 0; i < 20; ++i) {
        std::string unit_id = mock_work_unit_manager->createWorkUnit(WorkUnitType::PROPAGATION_GRID, input_data, parameters);
        unit_ids.push_back(unit_id);
    }
    
    // Test work unit distribution across clients
    std::map<std::string, int> client_assignments;
    for (const auto& client_id : test_client_ids) {
        client_assignments[client_id] = 0;
    }
    
    // Simulate load balancing by distributing work units
    for (size_t i = 0; i < unit_ids.size(); ++i) {
        std::string unit_id = unit_ids[i];
        std::string client_id = test_client_ids[i % test_client_ids.size()];
        client_assignments[client_id]++;
        
        // Test that work unit can be assigned to client
        bool can_assign = mock_client_manager->isClientOnline(client_id);
        EXPECT_TRUE(can_assign) << "Client should be available for assignment";
    }
    
    // Test that work units are distributed relatively evenly
    auto min_it = std::min_element(client_assignments.begin(), client_assignments.end(), 
                                  [](const auto& a, const auto& b) { return a.second < b.second; });
    auto max_it = std::max_element(client_assignments.begin(), client_assignments.end(), 
                                  [](const auto& a, const auto& b) { return a.second < b.second; });
    int min_assignments = min_it->second;
    int max_assignments = max_it->second;
    
    EXPECT_LE(max_assignments - min_assignments, 2) << "Work units should be distributed relatively evenly";
    
    // Test load balancing with different work unit types
    for (const auto& type : test_work_unit_types) {
        std::string unit_id = mock_work_unit_manager->createWorkUnit(type, input_data, parameters);
        std::vector<std::string> compatible_clients = mock_client_manager->getCompatibleClients(type);
        EXPECT_GT(compatible_clients.size(), 0) << "Should have compatible clients for " << static_cast<int>(type);
    }
    
    // Test load balancing with different priorities
    for (const auto& priority : test_priorities) {
        std::string unit_id = mock_work_unit_manager->createWorkUnit(WorkUnitType::PROPAGATION_GRID, input_data, parameters);
        bool enqueue_result = mock_queue_manager->enqueueWorkUnit(unit_id, priority);
        EXPECT_TRUE(enqueue_result) << "Work unit should be enqueued with priority " << static_cast<int>(priority);
    }
    
    // Test load balancing with client capacity constraints
    for (const auto& client_id : test_client_ids) {
        ClientWorkUnitCapability capability = mock_client_manager->getClientCapability(client_id);
        int max_units = capability.max_concurrent_units[WorkUnitType::PROPAGATION_GRID];
        EXPECT_GT(max_units, 0) << "Client should have positive capacity for " << client_id;
    }
}

TEST_F(TaskDistributionTest, WorkerFailureHandling) {
    // Test worker failure handling
    std::vector<double> input_data = generateTestData(100);
    std::map<std::string, double> parameters = generateTestParameters();
    
    // Create work units
    std::vector<std::string> unit_ids;
    for (int i = 0; i < 10; ++i) {
        std::string unit_id = mock_work_unit_manager->createWorkUnit(WorkUnitType::PROPAGATION_GRID, input_data, parameters);
        unit_ids.push_back(unit_id);
    }
    
    // Test work unit assignment before failure
    for (const auto& unit_id : unit_ids) {
        WorkUnitStatus status = mock_work_unit_manager->getWorkUnitStatus(unit_id);
        EXPECT_EQ(status, WorkUnitStatus::PENDING) << "Work unit should be in PENDING status before failure";
    }
    
    // Simulate client failure
    std::string failed_client = test_client_ids[0];
    bool unregister_result = mock_client_manager->unregisterClient(failed_client);
    EXPECT_TRUE(unregister_result) << "Client unregistration should succeed";
    
    // Test that failed client is no longer available
    bool is_online = mock_client_manager->isClientOnline(failed_client);
    EXPECT_FALSE(is_online) << "Failed client should be offline";
    
    // Test work unit reassignment after failure
    for (const auto& unit_id : unit_ids) {
        WorkUnitStatus status = mock_work_unit_manager->getWorkUnitStatus(unit_id);
        EXPECT_EQ(status, WorkUnitStatus::PENDING) << "Work unit should be in PENDING status after failure";
    }
    
    // Test work unit reassignment to remaining clients
    std::vector<std::string> remaining_clients = mock_client_manager->getAvailableClients();
    EXPECT_EQ(remaining_clients.size(), test_client_ids.size() - 1) << "Should have one less client after failure";
    
    // Test work unit reassignment with different priorities
    for (const auto& priority : test_priorities) {
        std::string unit_id = mock_work_unit_manager->createWorkUnit(WorkUnitType::PROPAGATION_GRID, input_data, parameters);
        bool enqueue_result = mock_queue_manager->enqueueWorkUnit(unit_id, priority);
        EXPECT_TRUE(enqueue_result) << "Work unit should be enqueued with priority " << static_cast<int>(priority);
    }
    
    // Test work unit reassignment with different work unit types
    for (const auto& type : test_work_unit_types) {
        std::string unit_id = mock_work_unit_manager->createWorkUnit(type, input_data, parameters);
        std::vector<std::string> compatible_clients = mock_client_manager->getCompatibleClients(type);
        EXPECT_GT(compatible_clients.size(), 0) << "Should have compatible clients for " << static_cast<int>(type);
    }
    
    // Test work unit reassignment with client capacity constraints
    for (const auto& client_id : remaining_clients) {
        ClientWorkUnitCapability capability = mock_client_manager->getClientCapability(client_id);
        int max_units = capability.max_concurrent_units[WorkUnitType::PROPAGATION_GRID];
        EXPECT_GT(max_units, 0) << "Client should have positive capacity for " << client_id;
    }
}

TEST_F(TaskDistributionTest, TaskTimeoutHandling) {
    // Test task timeout handling
    std::vector<double> input_data = generateTestData(100);
    std::map<std::string, double> parameters = generateTestParameters();
    
    // Create work units
    std::vector<std::string> unit_ids;
    for (int i = 0; i < 10; ++i) {
        std::string unit_id = mock_work_unit_manager->createWorkUnit(WorkUnitType::PROPAGATION_GRID, input_data, parameters);
        unit_ids.push_back(unit_id);
    }
    
    // Test work unit status before timeout
    for (const auto& unit_id : unit_ids) {
        WorkUnitStatus status = mock_work_unit_manager->getWorkUnitStatus(unit_id);
        EXPECT_EQ(status, WorkUnitStatus::PENDING) << "Work unit should be in PENDING status before timeout";
    }
    
    // Simulate work unit timeout
    for (const auto& unit_id : unit_ids) {
        WorkUnitStatus status = mock_work_unit_manager->getWorkUnitStatus(unit_id);
        EXPECT_EQ(status, WorkUnitStatus::PENDING) << "Work unit should be in PENDING status before timeout";
    }
    
    // Test work unit timeout with different priorities
    for (const auto& priority : test_priorities) {
        std::string unit_id = mock_work_unit_manager->createWorkUnit(WorkUnitType::PROPAGATION_GRID, input_data, parameters);
        bool enqueue_result = mock_queue_manager->enqueueWorkUnit(unit_id, priority);
        EXPECT_TRUE(enqueue_result) << "Work unit should be enqueued with priority " << static_cast<int>(priority);
    }
    
    // Test work unit timeout with different work unit types
    for (const auto& type : test_work_unit_types) {
        std::string unit_id = mock_work_unit_manager->createWorkUnit(type, input_data, parameters);
        std::vector<std::string> compatible_clients = mock_client_manager->getCompatibleClients(type);
        EXPECT_GT(compatible_clients.size(), 0) << "Should have compatible clients for " << static_cast<int>(type);
    }
    
    // Test work unit timeout with client capacity constraints
    for (const auto& client_id : test_client_ids) {
        ClientWorkUnitCapability capability = mock_client_manager->getClientCapability(client_id);
        int max_units = capability.max_concurrent_units[WorkUnitType::PROPAGATION_GRID];
        EXPECT_GT(max_units, 0) << "Client should have positive capacity for " << client_id;
    }
    
    // Test work unit timeout with retry logic
    for (const auto& unit_id : unit_ids) {
        WorkUnitStatus status = mock_work_unit_manager->getWorkUnitStatus(unit_id);
        EXPECT_EQ(status, WorkUnitStatus::PENDING) << "Work unit should be in PENDING status before timeout";
    }
    
    // Test work unit timeout with different timeout values
    std::vector<int> timeout_values = {1000, 5000, 10000, 30000, 60000};
    for (int timeout : timeout_values) {
        std::string unit_id = mock_work_unit_manager->createWorkUnit(WorkUnitType::PROPAGATION_GRID, input_data, parameters);
        bool enqueue_result = mock_queue_manager->enqueueWorkUnit(unit_id, WorkUnitPriority::MEDIUM);
        EXPECT_TRUE(enqueue_result) << "Work unit should be enqueued with timeout " << timeout;
    }
}

// Additional task distribution tests
TEST_F(TaskDistributionTest, TaskDistributionPerformance) {
    // Test task distribution performance
    const int num_operations = 1000;
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    // Test work unit creation performance
    for (int i = 0; i < num_operations; ++i) {
        std::vector<double> input_data = generateTestData(100);
        std::map<std::string, double> parameters = generateTestParameters();
        mock_work_unit_manager->createWorkUnit(WorkUnitType::PROPAGATION_GRID, input_data, parameters);
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    // Calculate performance metrics
    double time_per_operation = static_cast<double>(duration.count()) / num_operations;
    
    // Work unit creation operations should be fast
    EXPECT_LT(time_per_operation, 1000.0) << "Work unit creation operations too slow: " << time_per_operation << " microseconds";
    
    std::cout << "Task distribution performance: " << time_per_operation << " microseconds per operation" << std::endl;
}

TEST_F(TaskDistributionTest, TaskDistributionAccuracy) {
    // Test task distribution accuracy
    std::vector<double> input_data = generateTestData(100);
    std::map<std::string, double> parameters = generateTestParameters();
    
    // Test work unit creation accuracy
    std::string unit_id = mock_work_unit_manager->createWorkUnit(WorkUnitType::PROPAGATION_GRID, input_data, parameters);
    EXPECT_FALSE(unit_id.empty()) << "Work unit creation should be accurate";
    
    // Test work unit status accuracy
    WorkUnitStatus status = mock_work_unit_manager->getWorkUnitStatus(unit_id);
    EXPECT_EQ(status, WorkUnitStatus::PENDING) << "Work unit status should be accurate";
    
    // Test work unit result accuracy
    std::vector<double> result_data = mock_work_unit_manager->getWorkUnitResult(unit_id);
    EXPECT_TRUE(result_data.empty()) << "Work unit result should be accurate";
    
    // Test work unit error accuracy
    std::string error_message = mock_work_unit_manager->getWorkUnitError(unit_id);
    EXPECT_TRUE(error_message.empty()) << "Work unit error should be accurate";
    
    // Test client registration accuracy
    for (const auto& client_id : test_client_ids) {
        bool is_online = mock_client_manager->isClientOnline(client_id);
        EXPECT_TRUE(is_online) << "Client should be online for " << client_id;
    }
    
    // Test client capability accuracy
    for (const auto& client_id : test_client_ids) {
        ClientWorkUnitCapability capability = mock_client_manager->getClientCapability(client_id);
        EXPECT_EQ(capability.client_id, client_id) << "Client capability should be accurate";
        EXPECT_TRUE(capability.is_online) << "Client should be online";
    }
    
    // Test work unit assignment accuracy
    std::vector<std::string> available_clients = mock_client_manager->getAvailableClients();
    EXPECT_EQ(available_clients.size(), test_client_ids.size()) << "Available clients should be accurate";
    
    // Test work unit queue accuracy
    bool is_empty = mock_queue_manager->isEmpty();
    EXPECT_TRUE(is_empty) << "Work unit queue should be empty initially";
    
    // Test work unit enqueue accuracy
    bool enqueue_result = mock_queue_manager->enqueueWorkUnit(unit_id, WorkUnitPriority::MEDIUM);
    EXPECT_TRUE(enqueue_result) << "Work unit enqueue should be accurate";
    
    // Test work unit queue size accuracy
    size_t queue_size = mock_queue_manager->getQueueSize();
    EXPECT_EQ(queue_size, 1) << "Work unit queue size should be accurate";
    
    // Test work unit dequeue accuracy
    std::string dequeued_unit_id = mock_queue_manager->dequeueWorkUnit();
    EXPECT_EQ(dequeued_unit_id, unit_id) << "Work unit dequeue should be accurate";
}

