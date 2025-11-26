#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <rapidcheck.h>
#include <rapidcheck/gtest.h>
#include <rapidcheck/state.h>

#include "../../../scripts/tts/atis_weather_integration.h"

using namespace testing;

class ATISWeatherIntegrationTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Setup test environment
        test_config_file = "test_atis_weather_config.json";
        create_test_config();
    }
    
    void TearDown() override {
        // Cleanup test environment
        if (std::filesystem::exists(test_config_file)) {
            std::filesystem::remove(test_config_file);
        }
    }
    
    void create_test_config() {
        // Create test configuration
        std::ofstream config_file(test_config_file);
        config_file << R"({
            "weather_api_key": "test_key",
            "airports": ["KJFK", "KLAX"],
            "thresholds": {
                "wind_direction_change_deg": 10,
                "wind_speed_change_kts": 5,
                "gust_threshold_kts": 10,
                "temperature_change_celsius": 2.0,
                "pressure_change_hpa": 0.68,
                "visibility_change_km": 1.0,
                "cloud_cover_change_percent": 10
            },
            "update_interval_minutes": 1,
            "max_age_hours": 12,
            "output_directory": "test_atis_recordings",
            "tts_config": {
                "voice": "en_US-lessac-medium",
                "speed": 1.0,
                "pitch": 1.0
            },
            "switches": {
                "enable_weather_monitoring": true,
                "enable_automatic_atis_generation": true,
                "enable_letter_system": true
            }
        })";
        config_file.close();
    }
    
    std::string test_config_file;
};

TEST_F(ATISWeatherIntegrationTest, WeatherDataCreation) {
    // Test WeatherData object creation
    WeatherData weather(
        15.0,  // wind_speed_kts
        270,   // wind_direction_deg
        10.0,  // visibility_km
        50,    // cloud_cover_percent
        20.0,  // temperature_celsius
        15.0,  // dew_point_celsius
        1013.25, // qnh_hpa
        1012.0,  // qfe_hpa
        std::chrono::system_clock::now(), // timestamp
        "KJFK", // airport_icao
        "04L",  // active_runway
        25.0,   // gusts_kts
        false   // wind_shift
    );
    
    EXPECT_EQ(weather.wind_speed_kts, 15.0);
    EXPECT_EQ(weather.wind_direction_deg, 270);
    EXPECT_EQ(weather.airport_icao, "KJFK");
    EXPECT_TRUE(weather.gusts_kts > 0);
}

TEST_F(ATISWeatherIntegrationTest, ATISThresholdsDefault) {
    ATISThresholds thresholds;
    
    EXPECT_EQ(thresholds.wind_direction_change_deg, 10);
    EXPECT_EQ(thresholds.wind_speed_change_kts, 5);
    EXPECT_EQ(thresholds.gust_threshold_kts, 10);
    EXPECT_EQ(thresholds.temperature_change_celsius, 2.0);
    EXPECT_EQ(thresholds.pressure_change_hpa, 0.68);
    EXPECT_EQ(thresholds.update_interval_minutes, 60);
    EXPECT_EQ(thresholds.max_age_hours, 12);
}

TEST_F(ATISWeatherIntegrationTest, ATISLetterSystemProgression) {
    ATISLetterSystem letter_system("test_letters.json");
    
    // Test letter sequence
    std::vector<std::string> letters;
    for (int i = 0; i < 5; ++i) {
        letters.push_back(letter_system.get_next_letter());
    }
    
    std::vector<std::string> expected = {"A", "B", "C", "D", "E"};
    EXPECT_EQ(letters, expected);
}

TEST_F(ATISWeatherIntegrationTest, ATISLetterSystemWraparound) {
    ATISLetterSystem letter_system("test_letters.json");
    
    // Get all 26 letters
    std::vector<std::string> letters;
    for (int i = 0; i < 26; ++i) {
        letters.push_back(letter_system.get_next_letter());
    }
    
    // Should start over
    std::string next_letter = letter_system.get_next_letter();
    EXPECT_EQ(next_letter, "A");
}

TEST_F(ATISWeatherIntegrationTest, WeatherChangeDetection) {
    ATISWeatherMonitor monitor(test_config_file);
    
    // Create initial weather data
    WeatherData initial_weather(
        10.0, 270, 10.0, 50, 20.0, 15.0, 1013.25, 1012.0,
        std::chrono::system_clock::now(), "KJFK", "04L"
    );
    
    // Cache initial weather
    monitor.weather_cache["KJFK"] = initial_weather;
    monitor.last_weather_check["KJFK"] = std::chrono::system_clock::now();
    
    // Create weather with significant wind change
    WeatherData changed_weather(
        20.0, 280, 10.0, 50, 20.0, 15.0, 1013.25, 1012.0,
        std::chrono::system_clock::now(), "KJFK", "04L"
    );
    
    // Mock weather API
    EXPECT_CALL(monitor.weather_api, get_metar_data("KJFK"))
        .WillOnce(Return(changed_weather));
    
    // Check for changes
    bool has_changes = monitor.check_weather_changes("KJFK");
    EXPECT_TRUE(has_changes);
}

TEST_F(ATISWeatherIntegrationTest, ATISTextGeneration) {
    ATISWeatherMonitor monitor(test_config_file);
    
    WeatherData weather(
        15.0, 270, 10.0, 50, 20.0, 15.0, 1013.25, 1012.0,
        std::chrono::system_clock::now(), "KJFK", "04L", 25.0
    );
    
    std::string atis_text = monitor.generate_atis_text(weather);
    
    EXPECT_THAT(atis_text, HasSubstr("ATIS Information"));
    EXPECT_THAT(atis_text, HasSubstr("KJFK"));
    EXPECT_THAT(atis_text, HasSubstr("Wind 270 degrees at 15 knots"));
    EXPECT_THAT(atis_text, HasSubstr("gusts to 25 knots"));
    EXPECT_THAT(atis_text, HasSubstr("Visibility 10 kilometres or more"));
    EXPECT_THAT(atis_text, HasSubstr("Temperature 20, dew point 15"));
    EXPECT_THAT(atis_text, HasSubstr("QNH 1013, QFE 1012"));
    EXPECT_THAT(atis_text, HasSubstr("Advise you have information"));
}

// RapidCheck property-based tests
RC_GTEST_PROP(ATISWeatherIntegrationTest, WeatherDataValidation, ()) {
    // Generate random weather data
    auto wind_speed = *rc::gen::inRange(0.0, 100.0);
    auto wind_direction = *rc::gen::inRange(0, 360);
    auto visibility = *rc::gen::inRange(0.0, 50.0);
    auto cloud_cover = *rc::gen::inRange(0, 100);
    auto temperature = *rc::gen::inRange(-50.0, 50.0);
    auto dew_point = *rc::gen::inRange(-50.0, 50.0);
    auto qnh = *rc::gen::inRange(950.0, 1050.0);
    auto qfe = *rc::gen::inRange(950.0, 1050.0);
    
    WeatherData weather(
        wind_speed, wind_direction, visibility, cloud_cover,
        temperature, dew_point, qnh, qfe,
        std::chrono::system_clock::now(), "KJFK", "04L"
    );
    
    // Validate weather data properties
    RC_ASSERT(weather.wind_speed_kts >= 0.0);
    RC_ASSERT(weather.wind_direction_deg >= 0 && weather.wind_direction_deg <= 360);
    RC_ASSERT(weather.visibility_km >= 0.0);
    RC_ASSERT(weather.cloud_cover_percent >= 0 && weather.cloud_cover_percent <= 100);
    RC_ASSERT(weather.qnh_hpa > 0.0);
    RC_ASSERT(weather.qfe_hpa > 0.0);
}

RC_GTEST_PROP(ATISWeatherIntegrationTest, ATISLetterSystemProperties, ()) {
    ATISLetterSystem letter_system("test_letters.json");
    
    // Test letter system properties
    std::string letter = letter_system.get_next_letter();
    
    RC_ASSERT(letter.length() == 1);
    RC_ASSERT(letter[0] >= 'A' && letter[0] <= 'Z');
}

RC_GTEST_PROP(ATISWeatherIntegrationTest, WeatherChangeThresholds, ()) {
    ATISThresholds thresholds;
    
    // Test threshold properties
    RC_ASSERT(thresholds.wind_direction_change_deg > 0);
    RC_ASSERT(thresholds.wind_speed_change_kts > 0);
    RC_ASSERT(thresholds.gust_threshold_kts > 0);
    RC_ASSERT(thresholds.temperature_change_celsius > 0);
    RC_ASSERT(thresholds.pressure_change_hpa > 0);
    RC_ASSERT(thresholds.visibility_change_km > 0);
    RC_ASSERT(thresholds.cloud_cover_change_percent > 0);
    RC_ASSERT(thresholds.update_interval_minutes > 0);
    RC_ASSERT(thresholds.max_age_hours > 0);
}

// Integration tests
TEST_F(ATISWeatherIntegrationTest, CompleteATISGenerationWorkflow) {
    ATISWeatherMonitor monitor(test_config_file);
    
    // Mock TTS generation
    EXPECT_CALL(monitor, generate_atis_audio(_, _, _, _, _))
        .WillOnce(Return(true));
    
    WeatherData weather(
        15.0, 270, 10.0, 50, 20.0, 15.0, 1013.25, 1012.0,
        std::chrono::system_clock::now(), "KJFK", "04L"
    );
    
    // Generate ATIS recording
    std::string recording_path = monitor.generate_atis_recording("KJFK", weather);
    
    EXPECT_FALSE(recording_path.empty());
    EXPECT_TRUE(std::filesystem::exists(recording_path));
}

TEST_F(ATISWeatherIntegrationTest, WeatherAPIIntegration) {
    WeatherAPI api("test_key", "https://test.api.com");
    
    // Mock API response
    EXPECT_CALL(api, get_metar_data("KJFK"))
        .WillOnce(Return(nlohmann::json{
            {"icaoId", "KJFK"},
            {"rawOb", "KJFK 121200Z 27010KT 10SM FEW050 20/15 A3012"}
        }));
    
    auto metar_data = api.get_metar_data("KJFK");
    EXPECT_TRUE(metar_data.has_value());
    EXPECT_EQ(metar_data.value()["icaoId"], "KJFK");
}

TEST_F(ATISWeatherIntegrationTest, METARDataParsing) {
    WeatherAPI api("test_key");
    
    // Test METAR parsing
    nlohmann::json metar_data = {
        {"icaoId", "KJFK"},
        {"rawOb", "KJFK 121200Z 27010KT 10SM FEW050 20/15 A3012"}
    };
    
    auto weather = api.parse_metar(metar_data);
    EXPECT_TRUE(weather.has_value());
    
    if (weather.has_value()) {
        EXPECT_EQ(weather.value().wind_direction_deg, 270);
        EXPECT_EQ(weather.value().wind_speed_kts, 10.0);
        EXPECT_EQ(weather.value().visibility_km, 16.09); // 10SM in km
        EXPECT_EQ(weather.value().temperature_celsius, 20.0);
        EXPECT_EQ(weather.value().dew_point_celsius, 15.0);
    }
}

TEST_F(ATISWeatherIntegrationTest, ErrorHandling) {
    ATISWeatherMonitor monitor(test_config_file);
    
    // Test error handling for invalid weather data
    EXPECT_CALL(monitor.weather_api, get_metar_data("INVALID"))
        .WillOnce(Return(std::nullopt));
    
    bool has_changes = monitor.check_weather_changes("INVALID");
    EXPECT_FALSE(has_changes);
}

TEST_F(ATISWeatherIntegrationTest, ConfigurationLoading) {
    ATISWeatherMonitor monitor(test_config_file);
    
    EXPECT_EQ(monitor.config["weather_api_key"], "test_key");
    EXPECT_EQ(monitor.config["airports"], std::vector<std::string>{"KJFK", "KLAX"});
    EXPECT_EQ(monitor.config["thresholds"]["wind_direction_change_deg"], 10);
}

TEST_F(ATISWeatherIntegrationTest, PerformanceMonitoring) {
    ATISWeatherMonitor monitor(test_config_file);
    
    // Test performance monitoring
    auto start = std::chrono::high_resolution_clock::now();
    
    WeatherData weather(
        15.0, 270, 10.0, 50, 20.0, 15.0, 1013.25, 1012.0,
        std::chrono::system_clock::now(), "KJFK", "04L"
    );
    
    std::string atis_text = monitor.generate_atis_text(weather);
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    // ATIS generation should be fast (< 100ms)
    EXPECT_LT(duration.count(), 100);
    EXPECT_FALSE(atis_text.empty());
}

// Mock classes for testing
class MockWeatherAPI : public WeatherAPI {
public:
    MOCK_METHOD(std::optional<nlohmann::json>, get_metar_data, (const std::string&), (override));
    MOCK_METHOD(std::optional<WeatherData>, parse_metar, (const nlohmann::json&), (override));
};

class MockATISWeatherMonitor : public ATISWeatherMonitor {
public:
    MOCK_METHOD(bool, generate_atis_audio, (const std::string&, const std::string&, const std::string&, double, double), (override));
    MOCK_METHOD(bool, check_weather_changes, (const std::string&), (override));
};
