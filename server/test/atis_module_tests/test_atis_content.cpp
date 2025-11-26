#include "atis_test_classes.h"

// 7.3 ATIS Content Tests
TEST_F(ATISContentTest, AirportCodeParsing) {
    // Test airport code parsing
    std::vector<std::string> test_airport_codes = {
        "KJFK", "KLAX", "KORD", "KDFW", "KATL", "KLAS", "KPHX", "KSEA", "KIAH", "KMIA",
        "EGLL", "EGKK", "EGGW", "EGPH", "EGCC", "EGGD", "EGPF", "EGNT", "EGSH", "EGNX",
        "LFPG", "LFPO", "LFMN", "LFML", "LFBO", "LFSB", "LFST", "LFRB", "LFRS", "LFQQ",
        "EDDF", "EDDM", "EDDH", "EDDK", "EDDL", "EDDN", "EDDS", "EDDV", "EDDW", "EDDB"
    };
    
    for (const std::string& code : test_airport_codes) {
        // Test airport code validation
        bool is_valid = isValidAirportCode(code);
        EXPECT_TRUE(is_valid) << "Airport code " << code << " should be valid";
        
        // Test airport code length
        EXPECT_EQ(code.length(), 4) << "Airport code " << code << " should be 4 characters";
        
        // Test airport code format
        for (char c : code) {
            EXPECT_TRUE(std::isalpha(c)) << "Airport code " << code << " should contain only letters";
        }
        
        // Test airport code case
        std::string upper_code = code;
        std::transform(upper_code.begin(), upper_code.end(), upper_code.begin(), ::toupper);
        EXPECT_EQ(upper_code, code) << "Airport code " << code << " should be uppercase";
    }
    
    // Test invalid airport codes
    std::vector<std::string> invalid_codes = {
        "KJF", "KJFK1", "1234", "KJF-", "KJFK ", "KJFK\n", "KJFK\t"
    };
    
    for (const std::string& code : invalid_codes) {
        bool is_valid = isValidAirportCode(code);
        EXPECT_FALSE(is_valid) << "Airport code " << code << " should be invalid";
    }
}

TEST_F(ATISContentTest, WeatherInformationFormatting) {
    // Test weather information formatting
    std::string weather_info = generateWeatherInfo();
    EXPECT_FALSE(weather_info.empty()) << "Weather information should not be empty";
    
    // Test weather information components
    EXPECT_TRUE(weather_info.find("Wind") != std::string::npos) << "Weather information should contain wind";
    EXPECT_TRUE(weather_info.find("visibility") != std::string::npos) << "Weather information should contain visibility";
    EXPECT_TRUE(weather_info.find("ceiling") != std::string::npos) << "Weather information should contain ceiling";
    EXPECT_TRUE(weather_info.find("temperature") != std::string::npos) << "Weather information should contain temperature";
    EXPECT_TRUE(weather_info.find("dew point") != std::string::npos) << "Weather information should contain dew point";
    
    // Test weather information format
    std::vector<std::string> weather_components = {
        "Wind 270 at 15 knots",
        "visibility 10 miles",
        "ceiling 2500 feet",
        "temperature 15 degrees Celsius",
        "dew point 10 degrees Celsius"
    };
    
    for (const std::string& component : weather_components) {
        EXPECT_TRUE(weather_info.find(component) != std::string::npos) << "Weather information should contain " << component;
    }
    
    // Test weather information validation
    EXPECT_GT(weather_info.length(), 50) << "Weather information should be detailed";
    EXPECT_LT(weather_info.length(), 500) << "Weather information should not be too long";
    
    // Test weather information readability
    EXPECT_TRUE(weather_info.find(" ") != std::string::npos) << "Weather information should contain spaces";
    EXPECT_TRUE(weather_info.find(",") != std::string::npos) << "Weather information should contain commas";
}

TEST_F(ATISContentTest, RunwayInformation) {
    // Test runway information
    std::string runway_info = generateRunwayInfo();
    EXPECT_FALSE(runway_info.empty()) << "Runway information should not be empty";
    
    // Test runway information components
    EXPECT_TRUE(runway_info.find("Runway") != std::string::npos) << "Runway information should contain runway";
    EXPECT_TRUE(runway_info.find("04L/22R") != std::string::npos) << "Runway information should contain 04L/22R";
    EXPECT_TRUE(runway_info.find("04R/22L") != std::string::npos) << "Runway information should contain 04R/22L";
    EXPECT_TRUE(runway_info.find("13L/31R") != std::string::npos) << "Runway information should contain 13L/31R";
    EXPECT_TRUE(runway_info.find("13R/31L") != std::string::npos) << "Runway information should contain 13R/31L";
    
    // Test runway information format
    std::vector<std::string> runway_components = {
        "Runway 04L/22R",
        "Runway 04R/22L",
        "Runway 13L/31R",
        "Runway 13R/31L"
    };
    
    for (const std::string& component : runway_components) {
        EXPECT_TRUE(runway_info.find(component) != std::string::npos) << "Runway information should contain " << component;
    }
    
    // Test runway information validation
    EXPECT_GT(runway_info.length(), 20) << "Runway information should be detailed";
    EXPECT_LT(runway_info.length(), 200) << "Runway information should not be too long";
    
    // Test runway information readability
    EXPECT_TRUE(runway_info.find(" ") != std::string::npos) << "Runway information should contain spaces";
    EXPECT_TRUE(runway_info.find(",") != std::string::npos) << "Runway information should contain commas";
}

TEST_F(ATISContentTest, TimeDateStamping) {
    // Test time/date stamping
    std::string timestamp = test_time_stamp;
    EXPECT_FALSE(timestamp.empty()) << "Timestamp should not be empty";
    
    // Test timestamp validation
    bool is_valid = isValidTimeStamp(timestamp);
    EXPECT_TRUE(is_valid) << "Timestamp should be valid";
    
    // Test timestamp format
    EXPECT_EQ(timestamp.length(), 20) << "Timestamp should be 20 characters";
    EXPECT_EQ(timestamp[4], '-') << "Timestamp should contain date separator";
    EXPECT_EQ(timestamp[7], '-') << "Timestamp should contain date separator";
    EXPECT_EQ(timestamp[10], 'T') << "Timestamp should contain time separator";
    EXPECT_EQ(timestamp[13], ':') << "Timestamp should contain time separator";
    EXPECT_EQ(timestamp[16], ':') << "Timestamp should contain time separator";
    EXPECT_EQ(timestamp[19], 'Z') << "Timestamp should end with Z";
    
    // Test timestamp components
    std::string year = timestamp.substr(0, 4);
    std::string month = timestamp.substr(5, 2);
    std::string day = timestamp.substr(8, 2);
    std::string hour = timestamp.substr(11, 2);
    std::string minute = timestamp.substr(14, 2);
    std::string second = timestamp.substr(17, 2);
    
    EXPECT_EQ(year, "2024") << "Timestamp year should be 2024";
    EXPECT_EQ(month, "01") << "Timestamp month should be 01";
    EXPECT_EQ(day, "15") << "Timestamp day should be 15";
    EXPECT_EQ(hour, "10") << "Timestamp hour should be 10";
    EXPECT_EQ(minute, "30") << "Timestamp minute should be 30";
    EXPECT_EQ(second, "00") << "Timestamp second should be 00";
    
    // Test timestamp parsing
    int year_int = std::stoi(year);
    int month_int = std::stoi(month);
    int day_int = std::stoi(day);
    int hour_int = std::stoi(hour);
    int minute_int = std::stoi(minute);
    int second_int = std::stoi(second);
    
    EXPECT_GE(year_int, 2020) << "Timestamp year should be >= 2020";
    EXPECT_LE(year_int, 2030) << "Timestamp year should be <= 2030";
    EXPECT_GE(month_int, 1) << "Timestamp month should be >= 1";
    EXPECT_LE(month_int, 12) << "Timestamp month should be <= 12";
    EXPECT_GE(day_int, 1) << "Timestamp day should be >= 1";
    EXPECT_LE(day_int, 31) << "Timestamp day should be <= 31";
    EXPECT_GE(hour_int, 0) << "Timestamp hour should be >= 0";
    EXPECT_LE(hour_int, 23) << "Timestamp hour should be <= 23";
    EXPECT_GE(minute_int, 0) << "Timestamp minute should be >= 0";
    EXPECT_LE(minute_int, 59) << "Timestamp minute should be <= 59";
    EXPECT_GE(second_int, 0) << "Timestamp second should be >= 0";
    EXPECT_LE(second_int, 59) << "Timestamp second should be <= 59";
}

TEST_F(ATISContentTest, PhoneticAlphabetConversion) {
    // Test phonetic alphabet conversion
    std::string test_text = "KJFK";
    std::string phonetic = convertToPhonetic(test_text);
    EXPECT_FALSE(phonetic.empty()) << "Phonetic conversion should not be empty";
    
    // Test phonetic conversion accuracy
    EXPECT_TRUE(phonetic.find("Kilo") != std::string::npos) << "Phonetic should contain Kilo";
    EXPECT_TRUE(phonetic.find("Juliet") != std::string::npos) << "Phonetic should contain Juliet";
    EXPECT_TRUE(phonetic.find("Foxtrot") != std::string::npos) << "Phonetic should contain Foxtrot";
    EXPECT_TRUE(phonetic.find("Kilo") != std::string::npos) << "Phonetic should contain Kilo";
    
    // Test phonetic alphabet mapping
    std::map<std::string, std::string> test_mappings = {
        {"A", "Alpha"}, {"B", "Bravo"}, {"C", "Charlie"}, {"D", "Delta"},
        {"E", "Echo"}, {"F", "Foxtrot"}, {"G", "Golf"}, {"H", "Hotel"},
        {"I", "India"}, {"J", "Juliet"}, {"K", "Kilo"}, {"L", "Lima"},
        {"M", "Mike"}, {"N", "November"}, {"O", "Oscar"}, {"P", "Papa"},
        {"Q", "Quebec"}, {"R", "Romeo"}, {"S", "Sierra"}, {"T", "Tango"},
        {"U", "Uniform"}, {"V", "Victor"}, {"W", "Whiskey"}, {"X", "X-ray"},
        {"Y", "Yankee"}, {"Z", "Zulu"}
    };
    
    for (const auto& [letter, phonetic_word] : test_mappings) {
        std::string test_letter = letter;
        std::string converted = convertToPhonetic(test_letter);
        EXPECT_TRUE(converted.find(phonetic_word) != std::string::npos) << "Letter " << letter << " should convert to " << phonetic_word;
    }
    
    // Test phonetic conversion with mixed case
    std::string mixed_case = "KjFk";
    std::string mixed_phonetic = convertToPhonetic(mixed_case);
    EXPECT_FALSE(mixed_phonetic.empty()) << "Mixed case phonetic conversion should not be empty";
    
    // Test phonetic conversion with numbers
    std::string with_numbers = "KJFK123";
    std::string number_phonetic = convertToPhonetic(with_numbers);
    EXPECT_FALSE(number_phonetic.empty()) << "Number phonetic conversion should not be empty";
    
    // Test phonetic conversion with special characters
    std::string with_special = "KJFK-";
    std::string special_phonetic = convertToPhonetic(with_special);
    EXPECT_FALSE(special_phonetic.empty()) << "Special character phonetic conversion should not be empty";
}

// Additional ATIS content tests
TEST_F(ATISContentTest, ATISContentPerformance) {
    // Test ATIS content performance
    const int num_content_generations = 1000;
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    // Test content generation performance
    for (int i = 0; i < num_content_generations; ++i) {
        std::string airport_code = "KJFK";
        std::string weather_info = generateWeatherInfo();
        std::string runway_info = generateRunwayInfo();
        
        std::string atis_content = generateATISContent(airport_code, weather_info, runway_info);
        EXPECT_FALSE(atis_content.empty()) << "ATIS content should not be empty";
        
        std::string phonetic = convertToPhonetic(airport_code);
        EXPECT_FALSE(phonetic.empty()) << "Phonetic conversion should not be empty";
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    // Calculate performance metrics
    double time_per_generation = static_cast<double>(duration.count()) / num_content_generations;
    
    // Content generation should be fast
    EXPECT_LT(time_per_generation, 100.0) << "ATIS content generation too slow: " << time_per_generation << " microseconds";
    
    std::cout << "ATIS content generation performance: " << time_per_generation << " microseconds per generation" << std::endl;
}

TEST_F(ATISContentTest, ATISContentAccuracy) {
    // Test ATIS content accuracy
    std::string airport_code = test_airport_code;
    std::string weather_info = generateWeatherInfo();
    std::string runway_info = generateRunwayInfo();
    
    // Test ATIS content generation
    std::string atis_content = generateATISContent(airport_code, weather_info, runway_info);
    EXPECT_FALSE(atis_content.empty()) << "ATIS content should not be empty";
    
    // Test ATIS content components
    EXPECT_TRUE(atis_content.find("This is") != std::string::npos) << "ATIS content should contain introduction";
    EXPECT_TRUE(atis_content.find(airport_code) != std::string::npos) << "ATIS content should contain airport code";
    EXPECT_TRUE(atis_content.find("information") != std::string::npos) << "ATIS content should contain information";
    EXPECT_TRUE(atis_content.find("Advise you have information") != std::string::npos) << "ATIS content should contain closing";
    
    // Test ATIS content format
    EXPECT_GT(atis_content.length(), 50) << "ATIS content should be detailed";
    EXPECT_LT(atis_content.length(), 1000) << "ATIS content should not be too long";
    
    // Test ATIS content readability
    EXPECT_TRUE(atis_content.find(" ") != std::string::npos) << "ATIS content should contain spaces";
    EXPECT_TRUE(atis_content.find(".") != std::string::npos) << "ATIS content should contain periods";
    
    // Test phonetic conversion accuracy
    std::string phonetic = convertToPhonetic(airport_code);
    EXPECT_FALSE(phonetic.empty()) << "Phonetic conversion should not be empty";
    
    // Test phonetic conversion components
    for (char c : airport_code) {
        std::string letter(1, c);
        std::string phonetic_word = test_phonetic_alphabet[letter];
        EXPECT_TRUE(phonetic.find(phonetic_word) != std::string::npos) << "Phonetic should contain " << phonetic_word;
    }
    
    // Test timestamp accuracy
    std::string timestamp = test_time_stamp;
    EXPECT_FALSE(timestamp.empty()) << "Timestamp should not be empty";
    
    bool timestamp_valid = isValidTimeStamp(timestamp);
    EXPECT_TRUE(timestamp_valid) << "Timestamp should be valid";
    
    // Test airport code accuracy
    bool airport_code_valid = isValidAirportCode(airport_code);
    EXPECT_TRUE(airport_code_valid) << "Airport code should be valid";
}

