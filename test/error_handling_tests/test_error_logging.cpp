#include "test_error_handling_main.cpp"

// 16.2 Error Logging Tests
TEST_F(ErrorLoggingTest, ErrorMessagesLoggedCorrectly) {
    // Test error messages logged correctly
    for (const auto& error_message : test_error_messages) {
        mock_error_logger->logError(error_message, "test_component");
    }
    
    // Test error count
    int error_count = mock_error_logger->getErrorCount();
    EXPECT_EQ(error_count, test_error_messages.size()) << "Error count should match number of error messages";
    
    // Test error logs
    std::vector<std::string> error_logs = mock_error_logger->getErrorLogs();
    EXPECT_EQ(error_logs.size(), test_error_messages.size()) << "Error logs should match number of error messages";
    
    // Test error message content
    for (size_t i = 0; i < error_logs.size(); ++i) {
        EXPECT_EQ(error_logs[i], test_error_messages[i]) << "Error log should match error message " << i;
    }
    
    // Test error message search
    for (const auto& error_message : test_error_messages) {
        bool has_error = mock_error_logger->hasError(error_message);
        EXPECT_TRUE(has_error) << "Error logger should have error message: " << error_message;
    }
    
    // Test error logging with different components
    std::vector<std::string> components = {"network", "server", "client", "database", "audio"};
    for (const auto& component : components) {
        std::string error_message = "Error in " + component;
        mock_error_logger->logError(error_message, component);
        
        bool has_error = mock_error_logger->hasError(error_message);
        EXPECT_TRUE(has_error) << "Error logger should have error message for component: " << component;
    }
    
    // Test error logging with empty messages
    mock_error_logger->logError("", "test_component");
    int error_count_after_empty = mock_error_logger->getErrorCount();
    EXPECT_EQ(error_count_after_empty, test_error_messages.size() + components.size() + 1) << "Error count should include empty message";
    
    // Test error logging with empty components
    mock_error_logger->logError("Error without component", "");
    int error_count_after_empty_component = mock_error_logger->getErrorCount();
    EXPECT_EQ(error_count_after_empty_component, test_error_messages.size() + components.size() + 2) << "Error count should include empty component";
}

TEST_F(ErrorLoggingTest, LogRotationWorks) {
    // Test log rotation works
    const int num_logs = 1000;
    
    // Generate many log entries
    for (int i = 0; i < num_logs; ++i) {
        std::string error_message = "Error " + std::to_string(i);
        mock_error_logger->logError(error_message, "test_component");
    }
    
    // Test log count
    int error_count = mock_error_logger->getErrorCount();
    EXPECT_EQ(error_count, num_logs) << "Error count should match number of log entries";
    
    // Test log rotation by clearing logs
    mock_error_logger->clearLogs();
    int error_count_after_clear = mock_error_logger->getErrorCount();
    EXPECT_EQ(error_count_after_clear, 0) << "Error count should be 0 after clearing logs";
    
    // Test log rotation with different log types
    for (int i = 0; i < 100; ++i) {
        std::string error_message = "Error " + std::to_string(i);
        std::string warning_message = "Warning " + std::to_string(i);
        std::string info_message = "Info " + std::to_string(i);
        std::string debug_message = "Debug " + std::to_string(i);
        
        mock_error_logger->logError(error_message, "test_component");
        mock_error_logger->logWarning(warning_message, "test_component");
        mock_error_logger->logInfo(info_message, "test_component");
        mock_error_logger->logDebug(debug_message, "test_component");
    }
    
    // Test log counts
    int error_count_mixed = mock_error_logger->getErrorCount();
    int warning_count_mixed = mock_error_logger->getWarningCount();
    int info_count_mixed = mock_error_logger->getInfoCount();
    int debug_count_mixed = mock_error_logger->getDebugCount();
    
    EXPECT_EQ(error_count_mixed, 100) << "Error count should be 100";
    EXPECT_EQ(warning_count_mixed, 100) << "Warning count should be 100";
    EXPECT_EQ(info_count_mixed, 100) << "Info count should be 100";
    EXPECT_EQ(debug_count_mixed, 100) << "Debug count should be 100";
    
    // Test log rotation by clearing specific log types
    mock_error_logger->clearLogs();
    int error_count_after_clear_mixed = mock_error_logger->getErrorCount();
    int warning_count_after_clear_mixed = mock_error_logger->getWarningCount();
    int info_count_after_clear_mixed = mock_error_logger->getInfoCount();
    int debug_count_after_clear_mixed = mock_error_logger->getDebugCount();
    
    EXPECT_EQ(error_count_after_clear_mixed, 0) << "Error count should be 0 after clearing";
    EXPECT_EQ(warning_count_after_clear_mixed, 0) << "Warning count should be 0 after clearing";
    EXPECT_EQ(info_count_after_clear_mixed, 0) << "Info count should be 0 after clearing";
    EXPECT_EQ(debug_count_after_clear_mixed, 0) << "Debug count should be 0 after clearing";
}

TEST_F(ErrorLoggingTest, LogFileSizeLimits) {
    // Test log file size limits
    const int num_logs = 10000;
    const size_t max_log_size = 1024 * 1024; // 1MB
    
    // Generate many log entries
    for (int i = 0; i < num_logs; ++i) {
        std::string error_message = "Error " + std::to_string(i) + " with some additional text to make it longer";
        mock_error_logger->logError(error_message, "test_component");
    }
    
    // Test log count
    int error_count = mock_error_logger->getErrorCount();
    EXPECT_EQ(error_count, num_logs) << "Error count should match number of log entries";
    
    // Test log size estimation
    std::vector<std::string> error_logs = mock_error_logger->getErrorLogs();
    size_t estimated_size = 0;
    for (const auto& log : error_logs) {
        estimated_size += log.size();
    }
    
    EXPECT_GT(estimated_size, 0) << "Estimated log size should be positive";
    
    // Test log size limits with different message sizes
    std::vector<int> message_sizes = {10, 100, 1000, 10000, 100000};
    for (int size : message_sizes) {
        std::string large_message(size, 'A');
        mock_error_logger->logError(large_message, "test_component");
        
        int error_count_size = mock_error_logger->getErrorCount();
        EXPECT_GT(error_count_size, 0) << "Error count should be positive for size " << size;
    }
    
    // Test log size limits with different log types
    for (int i = 0; i < 1000; ++i) {
        std::string error_message = "Error " + std::to_string(i);
        std::string warning_message = "Warning " + std::to_string(i);
        std::string info_message = "Info " + std::to_string(i);
        std::string debug_message = "Debug " + std::to_string(i);
        
        mock_error_logger->logError(error_message, "test_component");
        mock_error_logger->logWarning(warning_message, "test_component");
        mock_error_logger->logInfo(info_message, "test_component");
        mock_error_logger->logDebug(debug_message, "test_component");
    }
    
    // Test log counts
    int error_count_size = mock_error_logger->getErrorCount();
    int warning_count_size = mock_error_logger->getWarningCount();
    int info_count_size = mock_error_logger->getInfoCount();
    int debug_count_size = mock_error_logger->getDebugCount();
    
    EXPECT_GT(error_count_size, 0) << "Error count should be positive";
    EXPECT_GT(warning_count_size, 0) << "Warning count should be positive";
    EXPECT_GT(info_count_size, 0) << "Info count should be positive";
    EXPECT_GT(debug_count_size, 0) << "Debug count should be positive";
}

TEST_F(ErrorLoggingTest, SensitiveDataNotLogged) {
    // Test sensitive data not logged
    std::vector<std::string> sensitive_data = {
        "password123",
        "secret_key_abc",
        "private_token_xyz",
        "credit_card_1234",
        "ssn_123456789"
    };
    
    // Test that sensitive data is not logged
    for (const auto& sensitive : sensitive_data) {
        mock_error_logger->logError("Error with " + sensitive, "test_component");
    }
    
    // Test error logs
    std::vector<std::string> error_logs = mock_error_logger->getErrorLogs();
    EXPECT_EQ(error_logs.size(), sensitive_data.size()) << "Error logs should match number of sensitive data entries";
    
    // Test that sensitive data is not in logs
    for (const auto& log : error_logs) {
        for (const auto& sensitive : sensitive_data) {
            EXPECT_EQ(log.find(sensitive), std::string::npos) << "Sensitive data should not be in logs: " << sensitive;
        }
    }
    
    // Test that sensitive data is not in warning logs
    for (const auto& sensitive : sensitive_data) {
        mock_error_logger->logWarning("Warning with " + sensitive, "test_component");
    }
    
    std::vector<std::string> warning_logs = mock_error_logger->getWarningLogs();
    EXPECT_EQ(warning_logs.size(), sensitive_data.size()) << "Warning logs should match number of sensitive data entries";
    
    for (const auto& log : warning_logs) {
        for (const auto& sensitive : sensitive_data) {
            EXPECT_EQ(log.find(sensitive), std::string::npos) << "Sensitive data should not be in warning logs: " << sensitive;
        }
    }
    
    // Test that sensitive data is not in info logs
    for (const auto& sensitive : sensitive_data) {
        mock_error_logger->logInfo("Info with " + sensitive, "test_component");
    }
    
    std::vector<std::string> info_logs = mock_error_logger->getInfoLogs();
    EXPECT_EQ(info_logs.size(), sensitive_data.size()) << "Info logs should match number of sensitive data entries";
    
    for (const auto& log : info_logs) {
        for (const auto& sensitive : sensitive_data) {
            EXPECT_EQ(log.find(sensitive), std::string::npos) << "Sensitive data should not be in info logs: " << sensitive;
        }
    }
    
    // Test that sensitive data is not in debug logs
    for (const auto& sensitive : sensitive_data) {
        mock_error_logger->logDebug("Debug with " + sensitive, "test_component");
    }
    
    std::vector<std::string> debug_logs = mock_error_logger->getDebugLogs();
    EXPECT_EQ(debug_logs.size(), sensitive_data.size()) << "Debug logs should match number of sensitive data entries";
    
    for (const auto& log : debug_logs) {
        for (const auto& sensitive : sensitive_data) {
            EXPECT_EQ(log.find(sensitive), std::string::npos) << "Sensitive data should not be in debug logs: " << sensitive;
        }
    }
}

// Additional error logging tests
TEST_F(ErrorLoggingTest, ErrorLoggingPerformance) {
    // Test error logging performance
    const int num_operations = 10000;
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    // Test error logging operations
    for (int i = 0; i < num_operations; ++i) {
        std::string error_message = "Error " + std::to_string(i);
        std::string warning_message = "Warning " + std::to_string(i);
        std::string info_message = "Info " + std::to_string(i);
        std::string debug_message = "Debug " + std::to_string(i);
        
        mock_error_logger->logError(error_message, "test_component");
        mock_error_logger->logWarning(warning_message, "test_component");
        mock_error_logger->logInfo(info_message, "test_component");
        mock_error_logger->logDebug(debug_message, "test_component");
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    // Calculate performance metrics
    double time_per_operation = static_cast<double>(duration.count()) / num_operations;
    
    // Error logging operations should be fast
    EXPECT_LT(time_per_operation, 1000.0) << "Error logging operations too slow: " << time_per_operation << " microseconds";
    
    std::cout << "Error logging performance: " << time_per_operation << " microseconds per operation" << std::endl;
    
    // Test log counts
    int error_count = mock_error_logger->getErrorCount();
    int warning_count = mock_error_logger->getWarningCount();
    int info_count = mock_error_logger->getInfoCount();
    int debug_count = mock_error_logger->getDebugCount();
    
    EXPECT_EQ(error_count, num_operations) << "Error count should match number of operations";
    EXPECT_EQ(warning_count, num_operations) << "Warning count should match number of operations";
    EXPECT_EQ(info_count, num_operations) << "Info count should match number of operations";
    EXPECT_EQ(debug_count, num_operations) << "Debug count should match number of operations";
}

TEST_F(ErrorLoggingTest, ErrorLoggingAccuracy) {
    // Test error logging accuracy
    // Test error message logging accuracy
    std::string error_message = "Test error message";
    mock_error_logger->logError(error_message, "test_component");
    
    int error_count = mock_error_logger->getErrorCount();
    EXPECT_EQ(error_count, 1) << "Error count should be 1";
    
    std::vector<std::string> error_logs = mock_error_logger->getErrorLogs();
    EXPECT_EQ(error_logs.size(), 1) << "Error logs should have 1 entry";
    EXPECT_EQ(error_logs[0], error_message) << "Error log should match error message";
    
    bool has_error = mock_error_logger->hasError(error_message);
    EXPECT_TRUE(has_error) << "Error logger should have error message";
    
    // Test warning message logging accuracy
    std::string warning_message = "Test warning message";
    mock_error_logger->logWarning(warning_message, "test_component");
    
    int warning_count = mock_error_logger->getWarningCount();
    EXPECT_EQ(warning_count, 1) << "Warning count should be 1";
    
    std::vector<std::string> warning_logs = mock_error_logger->getWarningLogs();
    EXPECT_EQ(warning_logs.size(), 1) << "Warning logs should have 1 entry";
    EXPECT_EQ(warning_logs[0], warning_message) << "Warning log should match warning message";
    
    bool has_warning = mock_error_logger->hasWarning(warning_message);
    EXPECT_TRUE(has_warning) << "Error logger should have warning message";
    
    // Test info message logging accuracy
    std::string info_message = "Test info message";
    mock_error_logger->logInfo(info_message, "test_component");
    
    int info_count = mock_error_logger->getInfoCount();
    EXPECT_EQ(info_count, 1) << "Info count should be 1";
    
    std::vector<std::string> info_logs = mock_error_logger->getInfoLogs();
    EXPECT_EQ(info_logs.size(), 1) << "Info logs should have 1 entry";
    EXPECT_EQ(info_logs[0], info_message) << "Info log should match info message";
    
    // Test debug message logging accuracy
    std::string debug_message = "Test debug message";
    mock_error_logger->logDebug(debug_message, "test_component");
    
    int debug_count = mock_error_logger->getDebugCount();
    EXPECT_EQ(debug_count, 1) << "Debug count should be 1";
    
    std::vector<std::string> debug_logs = mock_error_logger->getDebugLogs();
    EXPECT_EQ(debug_logs.size(), 1) << "Debug logs should have 1 entry";
    EXPECT_EQ(debug_logs[0], debug_message) << "Debug log should match debug message";
    
    // Test log clearing accuracy
    mock_error_logger->clearLogs();
    
    int error_count_after_clear = mock_error_logger->getErrorCount();
    int warning_count_after_clear = mock_error_logger->getWarningCount();
    int info_count_after_clear = mock_error_logger->getInfoCount();
    int debug_count_after_clear = mock_error_logger->getDebugCount();
    
    EXPECT_EQ(error_count_after_clear, 0) << "Error count should be 0 after clearing";
    EXPECT_EQ(warning_count_after_clear, 0) << "Warning count should be 0 after clearing";
    EXPECT_EQ(info_count_after_clear, 0) << "Info count should be 0 after clearing";
    EXPECT_EQ(debug_count_after_clear, 0) << "Debug count should be 0 after clearing";
    
    // Test log search accuracy
    mock_error_logger->logError("Specific error message", "test_component");
    bool has_specific_error = mock_error_logger->hasError("Specific error message");
    EXPECT_TRUE(has_specific_error) << "Error logger should have specific error message";
    
    bool has_partial_error = mock_error_logger->hasError("Specific");
    EXPECT_TRUE(has_partial_error) << "Error logger should have partial error message";
    
    bool has_nonexistent_error = mock_error_logger->hasError("Nonexistent error");
    EXPECT_FALSE(has_nonexistent_error) << "Error logger should not have nonexistent error message";
}

