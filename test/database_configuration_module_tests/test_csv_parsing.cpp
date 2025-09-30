#include "test_database_configuration_main.cpp"

// 10.1 CSV File Parsing Tests
TEST_F(CSVParsingTest, AmateurRadioBandSegmentsCSV) {
    // Test amateur radio band segments CSV parsing
    std::vector<std::vector<std::string>> csv_data;
    bool parse_result = mock_csv_parser->parseCSVFile(test_csv_file, csv_data);
    EXPECT_TRUE(parse_result) << "CSV file parsing should succeed";
    
    // Test that data was parsed correctly
    EXPECT_GT(csv_data.size(), 0) << "CSV data should not be empty";
    
    // Test first row (160m band data)
    if (csv_data.size() > 0) {
        std::vector<std::string> first_row = csv_data[0];
        EXPECT_EQ(first_row.size(), 9) << "First row should have 9 fields";
        EXPECT_EQ(first_row[0], "160m") << "Band field should be correct";
        EXPECT_EQ(first_row[1], "CW") << "Mode field should be correct";
        EXPECT_EQ(first_row[2], "1810") << "StartFreq field should be correct";
        EXPECT_EQ(first_row[3], "1838") << "EndFreq field should be correct";
        EXPECT_EQ(first_row[4], "1") << "Region field should be correct";
        EXPECT_EQ(first_row[5], "UK") << "Country field should be correct";
        EXPECT_EQ(first_row[6], "Full") << "LicenseClass field should be correct";
        EXPECT_EQ(first_row[7], "1000") << "PowerLimit field should be correct";
        EXPECT_EQ(first_row[8], "CW only below 1838 kHz") << "Notes field should be correct";
    }
    
    // Test second row (Intermediate license)
    if (csv_data.size() > 1) {
        std::vector<std::string> second_row = csv_data[1];
        EXPECT_EQ(second_row.size(), 9) << "Second row should have 9 fields";
        EXPECT_EQ(second_row[6], "Intermediate") << "LicenseClass field should be correct";
        EXPECT_EQ(second_row[7], "50") << "PowerLimit field should be correct";
    }
    
    // Test third row (20m band data)
    if (csv_data.size() > 2) {
        std::vector<std::string> third_row = csv_data[2];
        EXPECT_EQ(third_row.size(), 9) << "Third row should have 9 fields";
        EXPECT_EQ(third_row[0], "20m") << "Band field should be correct";
        EXPECT_EQ(third_row[4], "2") << "Region field should be correct";
        EXPECT_EQ(third_row[5], "USA") << "Country field should be correct";
    }
}

TEST_F(CSVParsingTest, HeaderParsing) {
    // Test header parsing
    std::string header_line = "Band,Mode,StartFreq,EndFreq,Region,Country,LicenseClass,PowerLimit,Notes";
    std::vector<std::string> expected_headers = {
        "Band", "Mode", "StartFreq", "EndFreq", "Region", "Country", "LicenseClass", "PowerLimit", "Notes"
    };
    
    bool header_result = mock_csv_parser->validateCSVHeader(header_line, expected_headers);
    EXPECT_TRUE(header_result) << "Header validation should succeed";
    
    // Test invalid header
    std::string invalid_header = "Band,Mode,StartFreq,EndFreq,Region,Country,LicenseClass,PowerLimit";
    bool invalid_header_result = mock_csv_parser->validateCSVHeader(invalid_header, expected_headers);
    EXPECT_FALSE(invalid_header_result) << "Invalid header should be rejected";
    
    // Test header with extra fields
    std::string extra_header = "Band,Mode,StartFreq,EndFreq,Region,Country,LicenseClass,PowerLimit,Notes,Extra";
    bool extra_header_result = mock_csv_parser->validateCSVHeader(extra_header, expected_headers);
    EXPECT_FALSE(extra_header_result) << "Header with extra fields should be rejected";
    
    // Test header with wrong order
    std::string wrong_order_header = "Mode,Band,StartFreq,EndFreq,Region,Country,LicenseClass,PowerLimit,Notes";
    bool wrong_order_result = mock_csv_parser->validateCSVHeader(wrong_order_header, expected_headers);
    EXPECT_FALSE(wrong_order_result) << "Header with wrong order should be rejected";
}

TEST_F(CSVParsingTest, DataTypeValidation) {
    // Test data type validation
    std::vector<std::string> valid_fields = {"160m", "CW", "1810", "1838", "1", "UK", "Full", "1000", "CW only below 1838 kHz"};
    std::vector<std::string> expected_types = {"string", "string", "float", "float", "int", "string", "string", "float", "string"};
    
    bool type_result = mock_csv_parser->validateDataTypes(valid_fields, expected_types);
    EXPECT_TRUE(type_result) << "Valid data types should be accepted";
    
    // Test invalid data types
    std::vector<std::string> invalid_fields = {"160m", "CW", "invalid_float", "1838", "1", "UK", "Full", "1000", "CW only below 1838 kHz"};
    bool invalid_type_result = mock_csv_parser->validateDataTypes(invalid_fields, expected_types);
    EXPECT_FALSE(invalid_type_result) << "Invalid data types should be rejected";
    
    // Test field count mismatch
    std::vector<std::string> short_fields = {"160m", "CW", "1810", "1838", "1", "UK", "Full", "1000"};
    bool short_fields_result = mock_csv_parser->validateDataTypes(short_fields, expected_types);
    EXPECT_FALSE(short_fields_result) << "Short field count should be rejected";
    
    // Test individual field type validation
    bool string_result = mock_csv_parser->validateFieldType("160m", "string");
    EXPECT_TRUE(string_result) << "String field should be valid";
    
    bool float_result = mock_csv_parser->validateFieldType("1810", "float");
    EXPECT_TRUE(float_result) << "Float field should be valid";
    
    bool int_result = mock_csv_parser->validateFieldType("1", "int");
    EXPECT_TRUE(int_result) << "Int field should be valid";
    
    bool invalid_float_result = mock_csv_parser->validateFieldType("invalid_float", "float");
    EXPECT_FALSE(invalid_float_result) << "Invalid float should be rejected";
    
    bool invalid_int_result = mock_csv_parser->validateFieldType("invalid_int", "int");
    EXPECT_FALSE(invalid_int_result) << "Invalid int should be rejected";
}

TEST_F(CSVParsingTest, MissingFieldHandling) {
    // Test missing field handling
    std::vector<std::string> complete_fields = {"160m", "CW", "1810", "1838", "1", "UK", "Full", "1000", "CW only below 1838 kHz"};
    bool complete_result = mock_csv_parser->handleMissingFields(complete_fields, 9);
    EXPECT_TRUE(complete_result) << "Complete fields should be accepted";
    
    // Test missing fields
    std::vector<std::string> missing_fields = {"160m", "CW", "1810", "1838", "1", "UK", "Full", "1000"};
    bool missing_result = mock_csv_parser->handleMissingFields(missing_fields, 9);
    EXPECT_FALSE(missing_result) << "Missing fields should be rejected";
    
    // Test extra fields
    std::vector<std::string> extra_fields = {"160m", "CW", "1810", "1838", "1", "UK", "Full", "1000", "CW only below 1838 kHz", "Extra"};
    bool extra_result = mock_csv_parser->handleMissingFields(extra_fields, 9);
    EXPECT_TRUE(extra_result) << "Extra fields should be accepted";
    
    // Test empty fields
    std::vector<std::string> empty_fields = {};
    bool empty_result = mock_csv_parser->handleMissingFields(empty_fields, 9);
    EXPECT_FALSE(empty_result) << "Empty fields should be rejected";
}

TEST_F(CSVParsingTest, CommentLineSkipping) {
    // Test comment line skipping
    std::string comment_line = "# This is a comment";
    bool comment_result = mock_csv_parser->skipCommentLines(comment_line);
    EXPECT_TRUE(comment_result) << "Comment line should be skipped";
    
    std::string semicolon_comment = "; This is also a comment";
    bool semicolon_result = mock_csv_parser->skipCommentLines(semicolon_comment);
    EXPECT_TRUE(semicolon_result) << "Semicolon comment should be skipped";
    
    std::string empty_line = "";
    bool empty_result = mock_csv_parser->skipCommentLines(empty_line);
    EXPECT_TRUE(empty_result) << "Empty line should be skipped";
    
    std::string data_line = "160m,CW,1810,1838,1,UK,Full,1000,CW only below 1838 kHz";
    bool data_result = mock_csv_parser->skipCommentLines(data_line);
    EXPECT_FALSE(data_result) << "Data line should not be skipped";
    
    std::string mixed_line = "160m,CW,1810,1838,1,UK,Full,1000,CW only below 1838 kHz # This is a comment";
    bool mixed_result = mock_csv_parser->skipCommentLines(mixed_line);
    EXPECT_FALSE(mixed_result) << "Mixed line should not be skipped";
}

TEST_F(CSVParsingTest, QuoteHandling) {
    // Test quote handling
    std::string quoted_field = "\"CW only below 1838 kHz\"";
    bool quoted_result = mock_csv_parser->handleQuotes(quoted_field);
    EXPECT_TRUE(quoted_result) << "Quoted field should be detected";
    
    std::string unquoted_field = "CW only below 1838 kHz";
    bool unquoted_result = mock_csv_parser->handleQuotes(unquoted_field);
    EXPECT_FALSE(unquoted_result) << "Unquoted field should not be detected";
    
    std::string empty_field = "";
    bool empty_result = mock_csv_parser->handleQuotes(empty_field);
    EXPECT_FALSE(empty_result) << "Empty field should not be detected";
    
    std::string partial_quote = "CW only below 1838 kHz\"";
    bool partial_result = mock_csv_parser->handleQuotes(partial_quote);
    EXPECT_TRUE(partial_result) << "Partial quote should be detected";
    
    // Test CSV line parsing with quotes
    std::string quoted_line = "160m,CW,1810,1838,1,UK,Full,1000,\"CW only below 1838 kHz\"";
    std::vector<std::string> parsed_fields = mock_csv_parser->parseCSVLine(quoted_line);
    EXPECT_EQ(parsed_fields.size(), 9) << "Quoted line should parse correctly";
    EXPECT_EQ(parsed_fields[8], "CW only below 1838 kHz") << "Quoted field should be parsed correctly";
}

TEST_F(CSVParsingTest, DelimiterDetection) {
    // Test delimiter detection
    std::string comma_line = "160m,CW,1810,1838,1,UK,Full,1000,CW only below 1838 kHz";
    char comma_delimiter = mock_csv_parser->detectDelimiter(comma_line);
    EXPECT_EQ(comma_delimiter, ',') << "Comma delimiter should be detected";
    
    std::string semicolon_line = "160m;CW;1810;1838;1;UK;Full;1000;CW only below 1838 kHz";
    char semicolon_delimiter = mock_csv_parser->detectDelimiter(semicolon_line);
    EXPECT_EQ(semicolon_delimiter, ';') << "Semicolon delimiter should be detected";
    
    std::string tab_line = "160m\tCW\t1810\t1838\t1\tUK\tFull\t1000\tCW only below 1838 kHz";
    char tab_delimiter = mock_csv_parser->detectDelimiter(tab_line);
    EXPECT_EQ(tab_delimiter, '\t') << "Tab delimiter should be detected";
    
    std::string mixed_line = "160m,CW;1810,1838;1,UK;Full,1000;CW only below 1838 kHz";
    char mixed_delimiter = mock_csv_parser->detectDelimiter(mixed_line);
    EXPECT_EQ(mixed_delimiter, ',') << "Most common delimiter should be detected";
    
    std::string no_delimiter_line = "160m CW 1810 1838 1 UK Full 1000 CW only below 1838 kHz";
    char no_delimiter = mock_csv_parser->detectDelimiter(no_delimiter_line);
    EXPECT_EQ(no_delimiter, ',') << "Default delimiter should be returned";
}

// Additional CSV parsing tests
TEST_F(CSVParsingTest, CSVParsingPerformance) {
    // Test CSV parsing performance
    const int num_operations = 1000;
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    // Test CSV parsing performance
    for (int i = 0; i < num_operations; ++i) {
        std::vector<std::vector<std::string>> csv_data;
        mock_csv_parser->parseCSVFile(test_csv_file, csv_data);
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    // Calculate performance metrics
    double time_per_operation = static_cast<double>(duration.count()) / num_operations;
    
    // CSV parsing operations should be fast
    EXPECT_LT(time_per_operation, 1000.0) << "CSV parsing operations too slow: " << time_per_operation << " microseconds";
    
    std::cout << "CSV parsing performance: " << time_per_operation << " microseconds per operation" << std::endl;
}

TEST_F(CSVParsingTest, CSVParsingAccuracy) {
    // Test CSV parsing accuracy
    std::vector<std::vector<std::string>> csv_data;
    bool parse_result = mock_csv_parser->parseCSVFile(test_csv_file, csv_data);
    EXPECT_TRUE(parse_result) << "CSV parsing should be accurate";
    
    // Test data accuracy
    EXPECT_GT(csv_data.size(), 0) << "CSV data should be accurate";
    
    // Test field accuracy
    if (csv_data.size() > 0) {
        std::vector<std::string> first_row = csv_data[0];
        EXPECT_EQ(first_row.size(), 9) << "Field count should be accurate";
        EXPECT_EQ(first_row[0], "160m") << "Band field should be accurate";
        EXPECT_EQ(first_row[1], "CW") << "Mode field should be accurate";
        EXPECT_EQ(first_row[2], "1810") << "StartFreq field should be accurate";
        EXPECT_EQ(first_row[3], "1838") << "EndFreq field should be accurate";
        EXPECT_EQ(first_row[4], "1") << "Region field should be accurate";
        EXPECT_EQ(first_row[5], "UK") << "Country field should be accurate";
        EXPECT_EQ(first_row[6], "Full") << "LicenseClass field should be accurate";
        EXPECT_EQ(first_row[7], "1000") << "PowerLimit field should be accurate";
        EXPECT_EQ(first_row[8], "CW only below 1838 kHz") << "Notes field should be accurate";
    }
    
    // Test header accuracy
    std::string header_line = "Band,Mode,StartFreq,EndFreq,Region,Country,LicenseClass,PowerLimit,Notes";
    std::vector<std::string> expected_headers = {
        "Band", "Mode", "StartFreq", "EndFreq", "Region", "Country", "LicenseClass", "PowerLimit", "Notes"
    };
    bool header_result = mock_csv_parser->validateCSVHeader(header_line, expected_headers);
    EXPECT_TRUE(header_result) << "Header validation should be accurate";
    
    // Test data type accuracy
    std::vector<std::string> valid_fields = {"160m", "CW", "1810", "1838", "1", "UK", "Full", "1000", "CW only below 1838 kHz"};
    std::vector<std::string> expected_types = {"string", "string", "float", "float", "int", "string", "string", "float", "string"};
    bool type_result = mock_csv_parser->validateDataTypes(valid_fields, expected_types);
    EXPECT_TRUE(type_result) << "Data type validation should be accurate";
}

