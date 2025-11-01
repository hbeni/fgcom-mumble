#include "test_security_module_main.cpp"

// 9.2 Authentication Tests
TEST_F(AuthenticationTest, APIKeyValidation) {
    // Test API key validation
    std::string valid_key = generateTestAPIKey();
    bool valid_result = mock_auth_manager->validateAPIKey(valid_key);
    EXPECT_TRUE(valid_result) << "Valid API key should be accepted";
    
    // Test invalid API key
    std::string invalid_key = test_invalid_key;
    bool invalid_result = mock_auth_manager->validateAPIKey(invalid_key);
    EXPECT_FALSE(invalid_result) << "Invalid API key should be rejected";
    
    // Test empty API key
    std::string empty_key = "";
    bool empty_result = mock_auth_manager->validateAPIKey(empty_key);
    EXPECT_FALSE(empty_result) << "Empty API key should be rejected";
    
    // Test short API key
    std::string short_key = "ak_123";
    bool short_result = mock_auth_manager->validateAPIKey(short_key);
    EXPECT_FALSE(short_result) << "Short API key should be rejected";
    
    // Test API key without prefix
    std::string no_prefix_key = "1234567890abcdef1234567890abcdef";
    bool no_prefix_result = mock_auth_manager->validateAPIKey(no_prefix_key);
    EXPECT_FALSE(no_prefix_result) << "API key without prefix should be rejected";
}

TEST_F(AuthenticationTest, InvalidKeyRejection) {
    // Test invalid key rejection
    std::string invalid_key = test_invalid_key;
    bool reject_result = mock_auth_manager->rejectInvalidKey(invalid_key);
    EXPECT_TRUE(reject_result) << "Invalid key should be rejected";
    
    // Test valid key not rejected
    std::string valid_key = generateTestAPIKey();
    bool valid_not_rejected = mock_auth_manager->rejectInvalidKey(valid_key);
    EXPECT_FALSE(valid_not_rejected) << "Valid key should not be rejected";
    
    // Test empty key rejection
    std::string empty_key = "";
    bool empty_reject_result = mock_auth_manager->rejectInvalidKey(empty_key);
    EXPECT_TRUE(empty_reject_result) << "Empty key should be rejected";
    
    // Test null key rejection
    std::string null_key = "null";
    bool null_reject_result = mock_auth_manager->rejectInvalidKey(null_key);
    EXPECT_TRUE(null_reject_result) << "Null key should be rejected";
}

TEST_F(AuthenticationTest, KeyExpiration) {
    // Test key expiration
    std::string valid_key = generateTestAPIKey();
    bool expiration_result = mock_auth_manager->isKeyExpired(valid_key);
    EXPECT_FALSE(expiration_result) << "Valid key should not be expired";
    
    // Test expired key
    std::string expired_key = "ak_expired_key_1234567890abcdef";
    bool expired_result = mock_auth_manager->isKeyExpired(expired_key);
    EXPECT_FALSE(expired_result) << "Key expiration check should succeed";
    
    // Test key expiration with invalid key
    std::string invalid_key = test_invalid_key;
    bool invalid_expiration_result = mock_auth_manager->isKeyExpired(invalid_key);
    EXPECT_FALSE(invalid_expiration_result) << "Invalid key expiration check should succeed";
}

TEST_F(AuthenticationTest, RateLimitingPerKey) {
    // Test rate limiting per key
    std::string test_key = generateTestAPIKey();
    
    // Test rate limiting with valid requests
    bool rate_limit_valid = mock_auth_manager->checkRateLimit(test_key, 50);
    EXPECT_TRUE(rate_limit_valid) << "Valid rate limit should be accepted";
    
    // Test rate limiting with excessive requests
    bool rate_limit_excessive = mock_auth_manager->checkRateLimit(test_key, 150);
    EXPECT_FALSE(rate_limit_excessive) << "Excessive rate limit should be rejected";
    
    // Test rate limiting with maximum requests
    bool rate_limit_max = mock_auth_manager->checkRateLimit(test_key, 100);
    EXPECT_TRUE(rate_limit_max) << "Maximum rate limit should be accepted";
    
    // Test rate limiting with zero requests
    bool rate_limit_zero = mock_auth_manager->checkRateLimit(test_key, 0);
    EXPECT_TRUE(rate_limit_zero) << "Zero rate limit should be accepted";
    
    // Test rate limiting with negative requests
    bool rate_limit_negative = mock_auth_manager->checkRateLimit(test_key, -10);
    EXPECT_TRUE(rate_limit_negative) << "Negative rate limit should be accepted";
}

TEST_F(AuthenticationTest, BruteForceProtection) {
    // Test brute force protection
    std::string test_key = generateTestAPIKey();
    
    // Test brute force protection with valid key
    bool brute_force_valid = mock_auth_manager->checkBruteForceProtection(test_key);
    EXPECT_TRUE(brute_force_valid) << "Valid key should pass brute force protection";
    
    // Test brute force protection with invalid key
    std::string invalid_key = test_invalid_key;
    bool brute_force_invalid = mock_auth_manager->checkBruteForceProtection(invalid_key);
    EXPECT_TRUE(brute_force_invalid) << "Invalid key should pass brute force protection";
    
    // Test brute force protection with empty key
    std::string empty_key = "";
    bool brute_force_empty = mock_auth_manager->checkBruteForceProtection(empty_key);
    EXPECT_TRUE(brute_force_empty) << "Empty key should pass brute force protection";
    
    // Test brute force protection enable/disable
    mock_auth_manager->enableBruteForceProtection();
    bool brute_force_enabled = mock_auth_manager->checkBruteForceProtection(test_key);
    EXPECT_TRUE(brute_force_enabled) << "Brute force protection should be enabled";
    
    mock_auth_manager->disableBruteForceProtection();
    bool brute_force_disabled = mock_auth_manager->checkBruteForceProtection(test_key);
    EXPECT_TRUE(brute_force_disabled) << "Brute force protection should be disabled";
}

// Additional authentication tests
TEST_F(AuthenticationTest, AuthenticationPerformance) {
    // Test authentication performance
    const int num_operations = 1000;
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    // Test API key validation performance
    for (int i = 0; i < num_operations; ++i) {
        std::string test_key = generateTestAPIKey();
        mock_auth_manager->validateAPIKey(test_key);
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    // Calculate performance metrics
    double time_per_operation = static_cast<double>(duration.count()) / num_operations;
    
    // Authentication operations should be fast
    EXPECT_LT(time_per_operation, 100.0) << "Authentication operations too slow: " << time_per_operation << " microseconds";
    
    std::cout << "Authentication performance: " << time_per_operation << " microseconds per operation" << std::endl;
}

TEST_F(AuthenticationTest, AuthenticationAccuracy) {
    // Test authentication accuracy
    std::string valid_key = generateTestAPIKey();
    std::string invalid_key = test_invalid_key;
    
    // Test API key validation accuracy
    bool valid_result = mock_auth_manager->validateAPIKey(valid_key);
    EXPECT_TRUE(valid_result) << "Valid API key validation should be accurate";
    
    bool invalid_result = mock_auth_manager->validateAPIKey(invalid_key);
    EXPECT_FALSE(invalid_result) << "Invalid API key validation should be accurate";
    
    // Test rate limiting accuracy
    bool rate_limit_valid = mock_auth_manager->checkRateLimit(valid_key, 50);
    EXPECT_TRUE(rate_limit_valid) << "Rate limiting should be accurate";
    
    bool rate_limit_invalid = mock_auth_manager->checkRateLimit(valid_key, 150);
    EXPECT_FALSE(rate_limit_invalid) << "Rate limiting should be accurate";
    
    // Test brute force protection accuracy
    bool brute_force_valid = mock_auth_manager->checkBruteForceProtection(valid_key);
    EXPECT_TRUE(brute_force_valid) << "Brute force protection should be accurate";
    
    bool brute_force_invalid = mock_auth_manager->checkBruteForceProtection(invalid_key);
    EXPECT_TRUE(brute_force_invalid) << "Brute force protection should be accurate";
    
    // Test key expiration accuracy
    bool expiration_result = mock_auth_manager->isKeyExpired(valid_key);
    EXPECT_FALSE(expiration_result) << "Key expiration check should be accurate";
}

