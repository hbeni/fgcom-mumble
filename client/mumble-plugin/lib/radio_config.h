#ifndef FGCOM_RADIO_CONFIG_H
#define FGCOM_RADIO_CONFIG_H

#include <string>
#include <map>
#include <memory>

/**
 * CRITICAL FIX: Configuration system to replace hardcoded values
 * This provides a centralized, configurable system for radio parameters
 */
class FGCom_RadioConfig {
private:
    static std::map<std::string, std::string> config_values_;
    static bool initialized_;
    
public:
    // Configuration keys - no more magic numbers!
    static const std::string ECHO_TEST_FREQUENCY;
    static const std::string MAX_FIELD_LENGTH;
    static const std::string DEFAULT_SAMPLE_RATE;
    static const std::string UDP_SERVER_PORT;
    static const std::string NOTIFICATION_INTERVAL;
    
    // Initialize configuration from file or defaults
    static bool initialize(const std::string& config_file = "");
    
    // Get configuration values with type safety
    static std::string getString(const std::string& key, const std::string& default_value = "");
    static int getInt(const std::string& key, int default_value = 0);
    static float getFloat(const std::string& key, float default_value = 0.0f);
    static bool getBool(const std::string& key, bool default_value = false);
    
    // Set configuration values (for testing or runtime changes)
    static void setString(const std::string& key, const std::string& value);
    static void setInt(const std::string& key, int value);
    static void setFloat(const std::string& key, float value);
    static void setBool(const std::string& key, bool value);
    
    // Validation
    static bool isValidFrequency(float frequency);
    static bool isValidPort(int port);
    static bool isValidFieldLength(int length);
};

#endif // FGCOM_RADIO_CONFIG_H
