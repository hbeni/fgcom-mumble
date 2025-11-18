#include "test_security_module_main.cpp"

// 9.3 Input Validation Tests
TEST_F(InputValidationTest, SQLInjectionPrevention) {
    // Test SQL injection prevention
    std::string sql_injection = generateSQLInjection();
    bool sql_result = mock_input_validator->preventSQLInjection(sql_injection);
    EXPECT_FALSE(sql_result) << "SQL injection should be prevented";
    
    // Test valid input
    std::string valid_input = "SELECT * FROM users WHERE id = 1";
    bool valid_result = mock_input_validator->preventSQLInjection(valid_input);
    EXPECT_TRUE(valid_result) << "Valid input should be allowed";
    
    // Test empty input
    std::string empty_input = "";
    bool empty_result = mock_input_validator->preventSQLInjection(empty_input);
    EXPECT_TRUE(empty_result) << "Empty input should be allowed";
    
    // Test various SQL injection patterns
    std::vector<std::string> sql_patterns = {
        "'; DROP TABLE users; --",
        "UNION SELECT * FROM users",
        "OR 1=1",
        "AND 1=1",
        "INSERT INTO users VALUES",
        "UPDATE users SET password",
        "DELETE FROM users",
        "CREATE TABLE malicious"
    };
    
    for (const auto& pattern : sql_patterns) {
        bool pattern_result = mock_input_validator->preventSQLInjection(pattern);
        EXPECT_FALSE(pattern_result) << "SQL injection pattern should be prevented: " << pattern;
    }
    
    // Test safe SQL patterns
    std::vector<std::string> safe_patterns = {
        "SELECT name FROM users",
        "WHERE id = 123",
        "ORDER BY name",
        "GROUP BY category"
    };
    
    for (const auto& pattern : safe_patterns) {
        bool pattern_result = mock_input_validator->preventSQLInjection(pattern);
        EXPECT_TRUE(pattern_result) << "Safe SQL pattern should be allowed: " << pattern;
    }
}

TEST_F(InputValidationTest, XSSPrevention) {
    // Test XSS prevention
    std::string xss_attack = generateXSSAttack();
    bool xss_result = mock_input_validator->preventXSS(xss_attack);
    EXPECT_FALSE(xss_result) << "XSS attack should be prevented";
    
    // Test valid input
    std::string valid_input = "Hello, World!";
    bool valid_result = mock_input_validator->preventXSS(valid_input);
    EXPECT_TRUE(valid_result) << "Valid input should be allowed";
    
    // Test empty input
    std::string empty_input = "";
    bool empty_result = mock_input_validator->preventXSS(empty_input);
    EXPECT_TRUE(empty_result) << "Empty input should be allowed";
    
    // Test various XSS patterns
    std::vector<std::string> xss_patterns = {
        "<script>alert('XSS')</script>",
        "javascript:alert('XSS')",
        "onload=alert('XSS')",
        "onerror=alert('XSS')",
        "onclick=alert('XSS')",
        "onmouseover=alert('XSS')",
        "onfocus=alert('XSS')",
        "onblur=alert('XSS')"
    };
    
    for (const auto& pattern : xss_patterns) {
        bool pattern_result = mock_input_validator->preventXSS(pattern);
        EXPECT_FALSE(pattern_result) << "XSS pattern should be prevented: " << pattern;
    }
    
    // Test safe HTML patterns
    std::vector<std::string> safe_patterns = {
        "<p>Hello, World!</p>",
        "<div>Content</div>",
        "<span>Text</span>",
        "<h1>Title</h1>"
    };
    
    for (const auto& pattern : safe_patterns) {
        bool pattern_result = mock_input_validator->preventXSS(pattern);
        EXPECT_TRUE(pattern_result) << "Safe HTML pattern should be allowed: " << pattern;
    }
}

TEST_F(InputValidationTest, PathTraversalPrevention) {
    // Test path traversal prevention
    std::string path_traversal = generatePathTraversal();
    bool path_result = mock_input_validator->preventPathTraversal(path_traversal);
    EXPECT_FALSE(path_result) << "Path traversal should be prevented";
    
    // Test valid input
    std::string valid_input = "documents/file.txt";
    bool valid_result = mock_input_validator->preventPathTraversal(valid_input);
    EXPECT_TRUE(valid_result) << "Valid input should be allowed";
    
    // Test empty input
    std::string empty_input = "";
    bool empty_result = mock_input_validator->preventPathTraversal(empty_input);
    EXPECT_TRUE(empty_result) << "Empty input should be allowed";
    
    // Test various path traversal patterns
    std::vector<std::string> traversal_patterns = {
        "../etc/passwd",
        "..\\windows\\system32",
        "/../etc/passwd",
        "\\..\\windows\\system32",
        "....//etc/passwd",
        "....\\\\windows\\system32"
    };
    
    for (const auto& pattern : traversal_patterns) {
        bool pattern_result = mock_input_validator->preventPathTraversal(pattern);
        EXPECT_FALSE(pattern_result) << "Path traversal pattern should be prevented: " << pattern;
    }
    
    // Test safe path patterns
    std::vector<std::string> safe_patterns = {
        "documents/file.txt",
        "images/photo.jpg",
        "data/config.json",
        "logs/application.log"
    };
    
    for (const auto& pattern : safe_patterns) {
        bool pattern_result = mock_input_validator->preventPathTraversal(pattern);
        EXPECT_TRUE(pattern_result) << "Safe path pattern should be allowed: " << pattern;
    }
}

TEST_F(InputValidationTest, BufferOverflowPrevention) {
    // Test buffer overflow prevention
    std::string long_input(10000, 'A');
    bool buffer_result = mock_input_validator->preventBufferOverflow(long_input, 1000);
    EXPECT_FALSE(buffer_result) << "Buffer overflow should be prevented";
    
    // Test valid input
    std::string valid_input = "Hello, World!";
    bool valid_result = mock_input_validator->preventBufferOverflow(valid_input, 1000);
    EXPECT_TRUE(valid_result) << "Valid input should be allowed";
    
    // Test empty input
    std::string empty_input = "";
    bool empty_result = mock_input_validator->preventBufferOverflow(empty_input, 1000);
    EXPECT_TRUE(empty_result) << "Empty input should be allowed";
    
    // Test various buffer sizes
    std::vector<size_t> buffer_sizes = {100, 500, 1000, 2000, 5000};
    for (size_t size : buffer_sizes) {
        std::string test_input(size, 'A');
        bool size_result = mock_input_validator->preventBufferOverflow(test_input, size);
        EXPECT_TRUE(size_result) << "Input within buffer size should be allowed: " << size;
        
        bool overflow_result = mock_input_validator->preventBufferOverflow(test_input, size - 1);
        EXPECT_FALSE(overflow_result) << "Input exceeding buffer size should be prevented: " << size;
    }
}

TEST_F(InputValidationTest, IntegerOverflowPrevention) {
    // Test integer overflow prevention
    int large_value = 1000000;
    bool overflow_result = mock_input_validator->preventIntegerOverflow(large_value, 1000);
    EXPECT_FALSE(overflow_result) << "Integer overflow should be prevented";
    
    // Test valid input
    int valid_value = 500;
    bool valid_result = mock_input_validator->preventIntegerOverflow(valid_value, 1000);
    EXPECT_TRUE(valid_result) << "Valid input should be allowed";
    
    // Test zero input
    int zero_value = 0;
    bool zero_result = mock_input_validator->preventIntegerOverflow(zero_value, 1000);
    EXPECT_TRUE(zero_result) << "Zero input should be allowed";
    
    // Test negative input
    int negative_value = -100;
    bool negative_result = mock_input_validator->preventIntegerOverflow(negative_value, 1000);
    EXPECT_FALSE(negative_result) << "Negative input should be prevented";
    
    // Test various integer ranges
    std::vector<int> test_values = {0, 1, 100, 500, 1000, 1001, 2000};
    for (int value : test_values) {
        bool value_result = mock_input_validator->preventIntegerOverflow(value, 1000);
        if (value <= 1000 && value >= 0) {
            EXPECT_TRUE(value_result) << "Valid integer should be allowed: " << value;
        } else {
            EXPECT_FALSE(value_result) << "Invalid integer should be prevented: " << value;
        }
    }
}

// Additional input validation tests
TEST_F(InputValidationTest, InputValidationPerformance) {
    // Test input validation performance
    const int num_operations = 1000;
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    // Test input validation performance
    for (int i = 0; i < num_operations; ++i) {
        std::string test_input = "test_input_" + std::to_string(i);
        mock_input_validator->preventSQLInjection(test_input);
        mock_input_validator->preventXSS(test_input);
        mock_input_validator->preventPathTraversal(test_input);
        mock_input_validator->preventBufferOverflow(test_input, 1000);
        mock_input_validator->preventIntegerOverflow(i, 1000);
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    // Calculate performance metrics
    double time_per_operation = static_cast<double>(duration.count()) / num_operations;
    
    // Input validation operations should be fast
    EXPECT_LT(time_per_operation, 100.0) << "Input validation operations too slow: " << time_per_operation << " microseconds";
    
    std::cout << "Input validation performance: " << time_per_operation << " microseconds per operation" << std::endl;
}

TEST_F(InputValidationTest, InputValidationAccuracy) {
    // Test input validation accuracy
    std::string sql_injection = generateSQLInjection();
    std::string xss_attack = generateXSSAttack();
    std::string path_traversal = generatePathTraversal();
    
    // Test SQL injection prevention accuracy
    bool sql_result = mock_input_validator->preventSQLInjection(sql_injection);
    EXPECT_FALSE(sql_result) << "SQL injection prevention should be accurate";
    
    // Test XSS prevention accuracy
    bool xss_result = mock_input_validator->preventXSS(xss_attack);
    EXPECT_FALSE(xss_result) << "XSS prevention should be accurate";
    
    // Test path traversal prevention accuracy
    bool path_result = mock_input_validator->preventPathTraversal(path_traversal);
    EXPECT_FALSE(path_result) << "Path traversal prevention should be accurate";
    
    // Test buffer overflow prevention accuracy
    std::string long_input(10000, 'A');
    bool buffer_result = mock_input_validator->preventBufferOverflow(long_input, 1000);
    EXPECT_FALSE(buffer_result) << "Buffer overflow prevention should be accurate";
    
    // Test integer overflow prevention accuracy
    int large_value = 1000000;
    bool overflow_result = mock_input_validator->preventIntegerOverflow(large_value, 1000);
    EXPECT_FALSE(overflow_result) << "Integer overflow prevention should be accurate";
    
    // Test valid input accuracy
    std::string valid_input = "Hello, World!";
    bool valid_sql = mock_input_validator->preventSQLInjection(valid_input);
    bool valid_xss = mock_input_validator->preventXSS(valid_input);
    bool valid_path = mock_input_validator->preventPathTraversal(valid_input);
    bool valid_buffer = mock_input_validator->preventBufferOverflow(valid_input, 1000);
    bool valid_integer = mock_input_validator->preventIntegerOverflow(100, 1000);
    
    EXPECT_TRUE(valid_sql) << "Valid SQL input should be accurate";
    EXPECT_TRUE(valid_xss) << "Valid XSS input should be accurate";
    EXPECT_TRUE(valid_path) << "Valid path input should be accurate";
    EXPECT_TRUE(valid_buffer) << "Valid buffer input should be accurate";
    EXPECT_TRUE(valid_integer) << "Valid integer input should be accurate";
}

