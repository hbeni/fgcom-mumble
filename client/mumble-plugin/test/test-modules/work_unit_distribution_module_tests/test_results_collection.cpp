#include "test_work_unit_distribution_main.cpp"

// 12.2 Results Collection Tests
TEST_F(ResultsCollectionTest, ResultValidation) {
    // Test result validation
    std::string work_unit_id = "test_unit_1";
    std::string client_id = "test_client_1";
    std::vector<double> result_data = {1.0, 2.0, 3.0, 4.0, 5.0};
    std::vector<double> expected_result = {1.0, 2.0, 3.0, 4.0, 5.0};
    
    // Test result validation with exact match
    bool validation_result = mock_result_aggregator->validateResult(work_unit_id, expected_result);
    EXPECT_FALSE(validation_result) << "Result validation should fail for non-existent work unit";
    
    // Add partial result
    bool add_result = mock_result_aggregator->addPartialResult(work_unit_id, client_id, result_data);
    EXPECT_TRUE(add_result) << "Partial result addition should succeed";
    
    // Test result validation with exact match
    validation_result = mock_result_aggregator->validateResult(work_unit_id, expected_result);
    EXPECT_TRUE(validation_result) << "Result validation should succeed for exact match";
    
    // Test result validation with tolerance
    std::vector<double> tolerance_result = {1.01, 2.01, 3.01, 4.01, 5.01};
    validation_result = mock_result_aggregator->validateResult(work_unit_id, tolerance_result);
    EXPECT_TRUE(validation_result) << "Result validation should succeed within tolerance";
    
    // Test result validation with large tolerance
    std::vector<double> large_tolerance_result = {1.1, 2.1, 3.1, 4.1, 5.1};
    validation_result = mock_result_aggregator->validateResult(work_unit_id, large_tolerance_result);
    EXPECT_FALSE(validation_result) << "Result validation should fail for large tolerance";
    
    // Test result validation with different size
    std::vector<double> different_size_result = {1.0, 2.0, 3.0};
    validation_result = mock_result_aggregator->validateResult(work_unit_id, different_size_result);
    EXPECT_FALSE(validation_result) << "Result validation should fail for different size";
    
    // Test result validation with empty result
    std::vector<double> empty_result;
    validation_result = mock_result_aggregator->validateResult(work_unit_id, empty_result);
    EXPECT_FALSE(validation_result) << "Result validation should fail for empty result";
    
    // Test result validation with negative values
    std::vector<double> negative_result = {-1.0, -2.0, -3.0, -4.0, -5.0};
    validation_result = mock_result_aggregator->validateResult(work_unit_id, negative_result);
    EXPECT_FALSE(validation_result) << "Result validation should fail for negative values";
    
    // Test result validation with zero values
    std::vector<double> zero_result = {0.0, 0.0, 0.0, 0.0, 0.0};
    validation_result = mock_result_aggregator->validateResult(work_unit_id, zero_result);
    EXPECT_FALSE(validation_result) << "Result validation should fail for zero values";
    
    // Test result validation with very large values
    std::vector<double> large_result = {1000000.0, 2000000.0, 3000000.0, 4000000.0, 5000000.0};
    validation_result = mock_result_aggregator->validateResult(work_unit_id, large_result);
    EXPECT_FALSE(validation_result) << "Result validation should fail for very large values";
}

TEST_F(ResultsCollectionTest, ResultAggregation) {
    // Test result aggregation
    std::string work_unit_id = "test_unit_2";
    std::vector<std::string> client_ids = {"client_1", "client_2", "client_3"};
    std::vector<std::vector<double>> result_data_sets = {
        {1.0, 2.0, 3.0},
        {4.0, 5.0, 6.0},
        {7.0, 8.0, 9.0}
    };
    
    // Test adding partial results
    for (size_t i = 0; i < client_ids.size(); ++i) {
        bool add_result = mock_result_aggregator->addPartialResult(work_unit_id, client_ids[i], result_data_sets[i]);
        EXPECT_TRUE(add_result) << "Partial result addition should succeed for " << client_ids[i];
    }
    
    // Test aggregated result retrieval
    std::vector<double> aggregated_result = mock_result_aggregator->getAggregatedResult(work_unit_id);
    EXPECT_FALSE(aggregated_result.empty()) << "Aggregated result should not be empty";
    
    // Test result completeness
    bool is_complete = mock_result_aggregator->isResultComplete(work_unit_id);
    EXPECT_TRUE(is_complete) << "Result should be complete";
    
    // Test contributing clients
    std::vector<std::string> contributing_clients = mock_result_aggregator->getContributingClients(work_unit_id);
    EXPECT_EQ(contributing_clients.size(), client_ids.size()) << "Contributing clients count should match";
    
    // Test result confidence
    double confidence = mock_result_aggregator->calculateResultConfidence(work_unit_id);
    EXPECT_GE(confidence, 0.0) << "Result confidence should be non-negative";
    EXPECT_LE(confidence, 1.0) << "Result confidence should be at most 1.0";
    
    // Test result aggregation with different work unit types
    for (const auto& type : test_work_unit_types) {
        std::string type_unit_id = "test_unit_" + std::to_string(static_cast<int>(type));
        std::vector<double> type_result_data = generateTestData(10);
        
        bool add_result = mock_result_aggregator->addPartialResult(type_unit_id, "test_client", type_result_data);
        EXPECT_TRUE(add_result) << "Partial result addition should succeed for " << static_cast<int>(type);
        
        std::vector<double> type_aggregated_result = mock_result_aggregator->getAggregatedResult(type_unit_id);
        EXPECT_FALSE(type_aggregated_result.empty()) << "Aggregated result should not be empty for " << static_cast<int>(type);
    }
    
    // Test result aggregation with different client counts
    std::vector<int> client_counts = {1, 2, 3, 5, 10};
    for (int count : client_counts) {
        std::string count_unit_id = "test_unit_count_" + std::to_string(count);
        std::vector<double> count_result_data = generateTestData(10);
        
        for (int i = 0; i < count; ++i) {
            std::string client_id = "client_" + std::to_string(i);
            bool add_result = mock_result_aggregator->addPartialResult(count_unit_id, client_id, count_result_data);
            EXPECT_TRUE(add_result) << "Partial result addition should succeed for client " << i;
        }
        
        double count_confidence = mock_result_aggregator->calculateResultConfidence(count_unit_id);
        EXPECT_GE(count_confidence, 0.0) << "Result confidence should be non-negative for count " << count;
        EXPECT_LE(count_confidence, 1.0) << "Result confidence should be at most 1.0 for count " << count;
    }
}

TEST_F(ResultsCollectionTest, PartialResultHandling) {
    // Test partial result handling
    std::string work_unit_id = "test_unit_3";
    std::vector<std::string> client_ids = {"client_1", "client_2", "client_3", "client_4", "client_5"};
    std::vector<std::vector<double>> result_data_sets = {
        {1.0, 2.0, 3.0},
        {4.0, 5.0, 6.0},
        {7.0, 8.0, 9.0},
        {10.0, 11.0, 12.0},
        {13.0, 14.0, 15.0}
    };
    
    // Test adding partial results one by one
    for (size_t i = 0; i < client_ids.size(); ++i) {
        bool add_result = mock_result_aggregator->addPartialResult(work_unit_id, client_ids[i], result_data_sets[i]);
        EXPECT_TRUE(add_result) << "Partial result addition should succeed for " << client_ids[i];
        
        // Test result completeness after each addition
        bool is_complete = mock_result_aggregator->isResultComplete(work_unit_id);
        EXPECT_TRUE(is_complete) << "Result should be complete after addition " << i;
        
        // Test contributing clients after each addition
        std::vector<std::string> contributing_clients = mock_result_aggregator->getContributingClients(work_unit_id);
        EXPECT_EQ(contributing_clients.size(), i + 1) << "Contributing clients count should match after addition " << i;
        
        // Test result confidence after each addition
        double confidence = mock_result_aggregator->calculateResultConfidence(work_unit_id);
        EXPECT_GE(confidence, 0.0) << "Result confidence should be non-negative after addition " << i;
        EXPECT_LE(confidence, 1.0) << "Result confidence should be at most 1.0 after addition " << i;
    }
    
    // Test partial result handling with different data sizes
    std::vector<size_t> data_sizes = {1, 5, 10, 50, 100, 1000};
    for (size_t size : data_sizes) {
        std::string size_unit_id = "test_unit_size_" + std::to_string(size);
        std::vector<double> size_result_data = generateTestData(size);
        
        bool add_result = mock_result_aggregator->addPartialResult(size_unit_id, "test_client", size_result_data);
        EXPECT_TRUE(add_result) << "Partial result addition should succeed for size " << size;
        
        std::vector<double> size_aggregated_result = mock_result_aggregator->getAggregatedResult(size_unit_id);
        EXPECT_EQ(size_aggregated_result.size(), size) << "Aggregated result size should match for size " << size;
    }
    
    // Test partial result handling with different client types
    std::vector<std::string> client_types = {"fast_client", "slow_client", "gpu_client", "cpu_client", "memory_client"};
    for (const auto& client_type : client_types) {
        std::string type_unit_id = "test_unit_type_" + client_type;
        std::vector<double> type_result_data = generateTestData(10);
        
        bool add_result = mock_result_aggregator->addPartialResult(type_unit_id, client_type, type_result_data);
        EXPECT_TRUE(add_result) << "Partial result addition should succeed for " << client_type;
        
        std::vector<double> type_aggregated_result = mock_result_aggregator->getAggregatedResult(type_unit_id);
        EXPECT_FALSE(type_aggregated_result.empty()) << "Aggregated result should not be empty for " << client_type;
    }
    
    // Test partial result handling with duplicate clients
    std::string duplicate_unit_id = "test_unit_duplicate";
    std::vector<double> duplicate_result_data = generateTestData(10);
    
    bool add_result_1 = mock_result_aggregator->addPartialResult(duplicate_unit_id, "duplicate_client", duplicate_result_data);
    EXPECT_TRUE(add_result_1) << "First partial result addition should succeed";
    
    bool add_result_2 = mock_result_aggregator->addPartialResult(duplicate_unit_id, "duplicate_client", duplicate_result_data);
    EXPECT_TRUE(add_result_2) << "Second partial result addition should succeed";
    
    std::vector<std::string> duplicate_contributing_clients = mock_result_aggregator->getContributingClients(duplicate_unit_id);
    EXPECT_EQ(duplicate_contributing_clients.size(), 2) << "Contributing clients count should be 2 for duplicate client";
}

TEST_F(ResultsCollectionTest, ResultStorage) {
    // Test result storage
    std::string work_unit_id = "test_unit_4";
    std::string client_id = "test_client_4";
    std::vector<double> result_data = generateTestData(100);
    
    // Test result storage
    bool add_result = mock_result_aggregator->addPartialResult(work_unit_id, client_id, result_data);
    EXPECT_TRUE(add_result) << "Result storage should succeed";
    
    // Test result retrieval
    std::vector<double> stored_result = mock_result_aggregator->getAggregatedResult(work_unit_id);
    EXPECT_EQ(stored_result.size(), result_data.size()) << "Stored result size should match";
    
    // Test result storage with different data types
    std::vector<std::vector<double>> different_data_types = {
        {1.0, 2.0, 3.0},  // Small data
        generateTestData(1000),  // Medium data
        generateTestData(10000), // Large data
        {0.0, 0.0, 0.0},  // Zero data
        {-1.0, -2.0, -3.0} // Negative data
    };
    
    for (size_t i = 0; i < different_data_types.size(); ++i) {
        std::string type_unit_id = "test_unit_type_" + std::to_string(i);
        std::vector<double> type_result_data = different_data_types[i];
        
        bool add_type_result = mock_result_aggregator->addPartialResult(type_unit_id, "test_client", type_result_data);
        EXPECT_TRUE(add_type_result) << "Result storage should succeed for type " << i;
        
        std::vector<double> type_stored_result = mock_result_aggregator->getAggregatedResult(type_unit_id);
        EXPECT_EQ(type_stored_result.size(), type_result_data.size()) << "Stored result size should match for type " << i;
    }
    
    // Test result storage with different work unit types
    for (const auto& type : test_work_unit_types) {
        std::string type_unit_id = "test_unit_storage_" + std::to_string(static_cast<int>(type));
        std::vector<double> type_result_data = generateTestData(50);
        
        bool add_type_result = mock_result_aggregator->addPartialResult(type_unit_id, "test_client", type_result_data);
        EXPECT_TRUE(add_type_result) << "Result storage should succeed for " << static_cast<int>(type);
        
        std::vector<double> type_stored_result = mock_result_aggregator->getAggregatedResult(type_unit_id);
        EXPECT_FALSE(type_stored_result.empty()) << "Stored result should not be empty for " << static_cast<int>(type);
    }
    
    // Test result storage with different client types
    std::vector<std::string> client_types = {"fast_client", "slow_client", "gpu_client", "cpu_client", "memory_client"};
    for (const auto& client_type : client_types) {
        std::string type_unit_id = "test_unit_client_" + client_type;
        std::vector<double> type_result_data = generateTestData(25);
        
        bool add_type_result = mock_result_aggregator->addPartialResult(type_unit_id, client_type, type_result_data);
        EXPECT_TRUE(add_type_result) << "Result storage should succeed for " << client_type;
        
        std::vector<double> type_stored_result = mock_result_aggregator->getAggregatedResult(type_unit_id);
        EXPECT_FALSE(type_stored_result.empty()) << "Stored result should not be empty for " << client_type;
    }
    
    // Test result storage with different priorities
    for (const auto& priority : test_priorities) {
        std::string priority_unit_id = "test_unit_priority_" + std::to_string(static_cast<int>(priority));
        std::vector<double> priority_result_data = generateTestData(30);
        
        bool add_priority_result = mock_result_aggregator->addPartialResult(priority_unit_id, "test_client", priority_result_data);
        EXPECT_TRUE(add_priority_result) << "Result storage should succeed for priority " << static_cast<int>(priority);
        
        std::vector<double> priority_stored_result = mock_result_aggregator->getAggregatedResult(priority_unit_id);
        EXPECT_FALSE(priority_stored_result.empty()) << "Stored result should not be empty for priority " << static_cast<int>(priority);
    }
}

TEST_F(ResultsCollectionTest, ResultRetrieval) {
    // Test result retrieval
    std::string work_unit_id = "test_unit_5";
    std::string client_id = "test_client_5";
    std::vector<double> result_data = generateTestData(100);
    
    // Test result retrieval before storage
    std::vector<double> empty_result = mock_result_aggregator->getAggregatedResult(work_unit_id);
    EXPECT_TRUE(empty_result.empty()) << "Result retrieval should return empty for non-existent work unit";
    
    // Test result storage
    bool add_result = mock_result_aggregator->addPartialResult(work_unit_id, client_id, result_data);
    EXPECT_TRUE(add_result) << "Result storage should succeed";
    
    // Test result retrieval after storage
    std::vector<double> retrieved_result = mock_result_aggregator->getAggregatedResult(work_unit_id);
    EXPECT_EQ(retrieved_result.size(), result_data.size()) << "Retrieved result size should match";
    
    // Test result retrieval with different data sizes
    std::vector<size_t> data_sizes = {1, 5, 10, 50, 100, 1000, 10000};
    for (size_t size : data_sizes) {
        std::string size_unit_id = "test_unit_retrieval_" + std::to_string(size);
        std::vector<double> size_result_data = generateTestData(size);
        
        bool add_size_result = mock_result_aggregator->addPartialResult(size_unit_id, "test_client", size_result_data);
        EXPECT_TRUE(add_size_result) << "Result storage should succeed for size " << size;
        
        std::vector<double> size_retrieved_result = mock_result_aggregator->getAggregatedResult(size_unit_id);
        EXPECT_EQ(size_retrieved_result.size(), size) << "Retrieved result size should match for size " << size;
    }
    
    // Test result retrieval with different work unit types
    for (const auto& type : test_work_unit_types) {
        std::string type_unit_id = "test_unit_retrieval_" + std::to_string(static_cast<int>(type));
        std::vector<double> type_result_data = generateTestData(50);
        
        bool add_type_result = mock_result_aggregator->addPartialResult(type_unit_id, "test_client", type_result_data);
        EXPECT_TRUE(add_type_result) << "Result storage should succeed for " << static_cast<int>(type);
        
        std::vector<double> type_retrieved_result = mock_result_aggregator->getAggregatedResult(type_unit_id);
        EXPECT_FALSE(type_retrieved_result.empty()) << "Retrieved result should not be empty for " << static_cast<int>(type);
    }
    
    // Test result retrieval with different client types
    std::vector<std::string> client_types = {"fast_client", "slow_client", "gpu_client", "cpu_client", "memory_client"};
    for (const auto& client_type : client_types) {
        std::string type_unit_id = "test_unit_retrieval_client_" + client_type;
        std::vector<double> type_result_data = generateTestData(25);
        
        bool add_type_result = mock_result_aggregator->addPartialResult(type_unit_id, client_type, type_result_data);
        EXPECT_TRUE(add_type_result) << "Result storage should succeed for " << client_type;
        
        std::vector<double> type_retrieved_result = mock_result_aggregator->getAggregatedResult(type_unit_id);
        EXPECT_FALSE(type_retrieved_result.empty()) << "Retrieved result should not be empty for " << client_type;
    }
    
    // Test result retrieval with different priorities
    for (const auto& priority : test_priorities) {
        std::string priority_unit_id = "test_unit_retrieval_priority_" + std::to_string(static_cast<int>(priority));
        std::vector<double> priority_result_data = generateTestData(30);
        
        bool add_priority_result = mock_result_aggregator->addPartialResult(priority_unit_id, "test_client", priority_result_data);
        EXPECT_TRUE(add_priority_result) << "Result storage should succeed for priority " << static_cast<int>(priority);
        
        std::vector<double> priority_retrieved_result = mock_result_aggregator->getAggregatedResult(priority_unit_id);
        EXPECT_FALSE(priority_retrieved_result.empty()) << "Retrieved result should not be empty for priority " << static_cast<int>(priority);
    }
    
    // Test result retrieval with multiple clients
    std::string multi_client_unit_id = "test_unit_multi_client";
    std::vector<std::string> multi_client_ids = {"client_1", "client_2", "client_3"};
    std::vector<std::vector<double>> multi_client_result_data = {
        generateTestData(20),
        generateTestData(20),
        generateTestData(20)
    };
    
    for (size_t i = 0; i < multi_client_ids.size(); ++i) {
        bool add_multi_result = mock_result_aggregator->addPartialResult(multi_client_unit_id, multi_client_ids[i], multi_client_result_data[i]);
        EXPECT_TRUE(add_multi_result) << "Result storage should succeed for " << multi_client_ids[i];
    }
    
    std::vector<double> multi_retrieved_result = mock_result_aggregator->getAggregatedResult(multi_client_unit_id);
    EXPECT_FALSE(multi_retrieved_result.empty()) << "Retrieved result should not be empty for multi-client work unit";
    
    // Test result retrieval with result removal
    mock_result_aggregator->removeResult(work_unit_id);
    std::vector<double> removed_result = mock_result_aggregator->getAggregatedResult(work_unit_id);
    EXPECT_TRUE(removed_result.empty()) << "Result retrieval should return empty after removal";
}

// Additional results collection tests
TEST_F(ResultsCollectionTest, ResultsCollectionPerformance) {
    // Test results collection performance
    const int num_operations = 1000;
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    // Test result aggregation performance
    for (int i = 0; i < num_operations; ++i) {
        std::string work_unit_id = "test_unit_perf_" + std::to_string(i);
        std::string client_id = "test_client_perf_" + std::to_string(i);
        std::vector<double> result_data = generateTestData(100);
        
        mock_result_aggregator->addPartialResult(work_unit_id, client_id, result_data);
        mock_result_aggregator->getAggregatedResult(work_unit_id);
        mock_result_aggregator->isResultComplete(work_unit_id);
        mock_result_aggregator->getContributingClients(work_unit_id);
        mock_result_aggregator->calculateResultConfidence(work_unit_id);
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    // Calculate performance metrics
    double time_per_operation = static_cast<double>(duration.count()) / num_operations;
    
    // Results collection operations should be fast
    EXPECT_LT(time_per_operation, 1000.0) << "Results collection operations too slow: " << time_per_operation << " microseconds";
    
    std::cout << "Results collection performance: " << time_per_operation << " microseconds per operation" << std::endl;
}

TEST_F(ResultsCollectionTest, ResultsCollectionAccuracy) {
    // Test results collection accuracy
    std::string work_unit_id = "test_unit_accuracy";
    std::string client_id = "test_client_accuracy";
    std::vector<double> result_data = generateTestData(100);
    
    // Test result storage accuracy
    bool add_result = mock_result_aggregator->addPartialResult(work_unit_id, client_id, result_data);
    EXPECT_TRUE(add_result) << "Result storage should be accurate";
    
    // Test result retrieval accuracy
    std::vector<double> retrieved_result = mock_result_aggregator->getAggregatedResult(work_unit_id);
    EXPECT_EQ(retrieved_result.size(), result_data.size()) << "Result retrieval should be accurate";
    
    // Test result completeness accuracy
    bool is_complete = mock_result_aggregator->isResultComplete(work_unit_id);
    EXPECT_TRUE(is_complete) << "Result completeness should be accurate";
    
    // Test contributing clients accuracy
    std::vector<std::string> contributing_clients = mock_result_aggregator->getContributingClients(work_unit_id);
    EXPECT_EQ(contributing_clients.size(), 1) << "Contributing clients count should be accurate";
    EXPECT_EQ(contributing_clients[0], client_id) << "Contributing client should be accurate";
    
    // Test result confidence accuracy
    double confidence = mock_result_aggregator->calculateResultConfidence(work_unit_id);
    EXPECT_GE(confidence, 0.0) << "Result confidence should be accurate";
    EXPECT_LE(confidence, 1.0) << "Result confidence should be accurate";
    
    // Test result validation accuracy
    bool validation_result = mock_result_aggregator->validateResult(work_unit_id, result_data);
    EXPECT_TRUE(validation_result) << "Result validation should be accurate";
    
    // Test result removal accuracy
    mock_result_aggregator->removeResult(work_unit_id);
    std::vector<double> removed_result = mock_result_aggregator->getAggregatedResult(work_unit_id);
    EXPECT_TRUE(removed_result.empty()) << "Result removal should be accurate";
}

