#include "radio_config.h"
#include <fstream>
#include <sstream>
#include <iostream>
#include <algorithm>

// Configuration key constants
const std::string FGCom_RadioConfig::ECHO_TEST_FREQUENCY = "echo_test_frequency";
const std::string FGCom_RadioConfig::MAX_FIELD_LENGTH = "max_field_length";
const std::string FGCom_RadioConfig::DEFAULT_SAMPLE_RATE = "default_sample_rate";
const std::string FGCom_RadioConfig::UDP_SERVER_PORT = "udp_server_port";
const std::string FGCom_RadioConfig::NOTIFICATION_INTERVAL = "notification_interval";

// Static member initialization
std::map<std::string, std::string> FGCom_RadioConfig::config_values_;
bool FGCom_RadioConfig::initialized_ = false;

bool FGCom_RadioConfig::initialize(const std::string& config_file) {
    // Set default values first
    config_values_[ECHO_TEST_FREQUENCY] = "910.0";
    config_values_[MAX_FIELD_LENGTH] = "256";
    config_values_[DEFAULT_SAMPLE_RATE] = "48000";
    config_values_[UDP_SERVER_PORT] = "16661";
    config_values_[NOTIFICATION_INTERVAL] = "100";
    
    // Load from file if provided
    if (!config_file.empty()) {
        std::ifstream file(config_file);
        if (file.is_open()) {
            std::string line;
            while (std::getline(file, line)) {
                // Skip comments and empty lines
                if (line.empty() || line[0] == '#') continue;
                
                size_t pos = line.find('=');
                if (pos != std::string::npos) {
                    std::string key = line.substr(0, pos);
                    std::string value = line.substr(pos + 1);
                    
                    // Trim whitespace
                    key.erase(0, key.find_first_not_of(" \t"));
                    key.erase(key.find_last_not_of(" \t") + 1);
                    value.erase(0, value.find_first_not_of(" \t"));
                    value.erase(value.find_last_not_of(" \t") + 1);
                    
                    config_values_[key] = value;
                }
            }
            file.close();
        }
    }
    
    initialized_ = true;
    return true;
}

std::string FGCom_RadioConfig::getString(const std::string& key, const std::string& default_value) {
    if (!initialized_) initialize();
    auto it = config_values_.find(key);
    return (it != config_values_.end()) ? it->second : default_value;
}

int FGCom_RadioConfig::getInt(const std::string& key, int default_value) {
    std::string value = getString(key);
    if (value.empty()) return default_value;
    
    try {
        return std::stoi(value);
    } catch (const std::exception&) {
        return default_value;
    }
}

float FGCom_RadioConfig::getFloat(const std::string& key, float default_value) {
    std::string value = getString(key);
    if (value.empty()) return default_value;
    
    try {
        return std::stof(value);
    } catch (const std::exception&) {
        return default_value;
    }
}

bool FGCom_RadioConfig::getBool(const std::string& key, bool default_value) {
    std::string value = getString(key);
    if (value.empty()) return default_value;
    
    std::transform(value.begin(), value.end(), value.begin(), ::tolower);
    return (value == "true" || value == "1" || value == "yes");
}

void FGCom_RadioConfig::setString(const std::string& key, const std::string& value) {
    if (!initialized_) initialize();
    config_values_[key] = value;
}

void FGCom_RadioConfig::setInt(const std::string& key, int value) {
    setString(key, std::to_string(value));
}

void FGCom_RadioConfig::setFloat(const std::string& key, float value) {
    setString(key, std::to_string(value));
}

void FGCom_RadioConfig::setBool(const std::string& key, bool value) {
    setString(key, value ? "true" : "false");
}

bool FGCom_RadioConfig::isValidFrequency(float frequency) {
    return frequency > 0.0f && frequency <= 1000000.0f; // 0 Hz to 1 GHz
}

bool FGCom_RadioConfig::isValidPort(int port) {
    return port > 0 && port <= 65535;
}

bool FGCom_RadioConfig::isValidFieldLength(int length) {
    return length > 0 && length <= 1024; // Reasonable field length limit
}
