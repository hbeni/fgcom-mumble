#include "input_validation.h"
#include <algorithm>
#include <sstream>
#include <fstream>
#include <iostream>
#include <cmath>
#include <cstring>

namespace InputValidation {

// Network validation
bool validatePort(int port) {
    return port > 0 && port <= 65535;
}

bool validateHost(const std::string& host) {
    if (host.empty() || host.length() > 253) {
        return false;
    }
    
    // Check for valid hostname characters
    for (char c : host) {
        if (!std::isalnum(c) && c != '.' && c != '-' && c != ':') {
            return false;
        }
    }
    
    return true;
}

bool validateIPAddress(const std::string& ip) {
    std::regex ipv4_regex(R"(^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$)");
    std::regex ipv6_regex(R"(^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$)");
    
    return std::regex_match(ip, ipv4_regex) || std::regex_match(ip, ipv6_regex);
}

bool validateURL(const std::string& url) {
    std::regex url_regex(R"(^https?://[^\s/$.?#].[^\s]*$)");
    return std::regex_match(url, url_regex);
}

// Geographic validation
bool validateLatitude(double lat) {
    return lat >= -90.0 && lat <= 90.0;
}

bool validateLongitude(double lon) {
    return lon >= -180.0 && lon <= 180.0;
}

bool validateAltitude(float alt) {
    return alt >= -1000.0f && alt <= 100000.0f; // -1km to 100km
}

bool validateDistance(float distance) {
    return distance >= 0.0f && distance <= 40000.0f; // 0 to 40,000 km (Earth circumference)
}

bool validateBearing(float bearing) {
    return bearing >= 0.0f && bearing < 360.0f;
}

// Radio frequency validation
bool validateFrequency(float frequency) {
    return frequency > 0.0f && frequency <= 300000000.0f; // 0 to 300 GHz
}

bool validateFrequencyRange(float min_freq, float max_freq) {
    return validateFrequency(min_freq) && validateFrequency(max_freq) && min_freq <= max_freq;
}

bool validatePower(float power) {
    return power >= 0.0f && power <= 1000000.0f; // 0 to 1 MW
}

bool validateSWR(float swr) {
    return swr >= 1.0f && swr <= 10.0f;
}

bool validateChannelWidth(float channel_width) {
    return channel_width > 0.0f && channel_width <= 1000000.0f; // 0 to 1 MHz
}

// String validation
bool validateCallsign(const std::string& callsign) {
    if (callsign.empty() || callsign.length() > 10) {
        return false;
    }
    
    // Check for valid callsign format (alphanumeric, may contain /)
    for (char c : callsign) {
        if (!std::isalnum(c) && c != '/') {
            return false;
        }
    }
    
    return true;
}

bool validateGridSquare(const std::string& grid) {
    if (grid.empty() || grid.length() < 4 || grid.length() > 6) {
        return false;
    }
    
    // Check for valid Maidenhead grid square format
    for (size_t i = 0; i < grid.length(); ++i) {
        char c = std::toupper(grid[i]);
        if (i % 2 == 0) {
            // Even positions should be letters
            if (c < 'A' || c > 'R') {
                return false;
            }
        } else {
            // Odd positions should be numbers
            if (c < '0' || c > '9') {
                return false;
            }
        }
    }
    
    return true;
}

bool validateMode(const std::string& mode) {
    std::vector<std::string> valid_modes = {
        "SSB", "CW", "AM", "FM", "NFM", "USB", "LSB", "DSB", "ISB", "VSB", "DIGITAL", "FT8", "FT4", "PSK31", "RTTY"
    };
    
    std::string upper_mode = mode;
    std::transform(upper_mode.begin(), upper_mode.end(), upper_mode.begin(), ::toupper);
    
    return std::find(valid_modes.begin(), valid_modes.end(), upper_mode) != valid_modes.end();
}

bool validateBand(const std::string& band) {
    std::vector<std::string> valid_bands = {
        "160m", "80m", "40m", "30m", "20m", "17m", "15m", "12m", "10m", "6m", "2m", "70cm", "23cm", "13cm"
    };
    
    return std::find(valid_bands.begin(), valid_bands.end(), band) != valid_bands.end();
}

bool validateAntennaType(const std::string& antenna_type) {
    std::vector<std::string> valid_types = {
        "vertical", "yagi", "dipole", "loop", "whip", "helical", "parabolic", "log_periodic"
    };
    
    return std::find(valid_types.begin(), valid_types.end(), antenna_type) != valid_types.end();
}

bool validateGroundType(const std::string& ground_type) {
    std::vector<std::string> valid_types = {
        "excellent", "good", "average", "poor", "saltwater", "freshwater", "urban", "rural"
    };
    
    return std::find(valid_types.begin(), valid_types.end(), ground_type) != valid_types.end();
}

// Numeric validation
bool validatePositiveNumber(double value) {
    return value > 0.0;
}

bool validateNonNegativeNumber(double value) {
    return value >= 0.0;
}

bool validateRange(double value, double min_val, double max_val) {
    return value >= min_val && value <= max_val;
}

bool validateInteger(int value, int min_val, int max_val) {
    return value >= min_val && value <= max_val;
}

bool validateFloat(float value, float min_val, float max_val) {
    return value >= min_val && value <= max_val;
}

// JSON validation
bool validateJSONString(const std::string& json_str) {
    if (json_str.empty()) {
        return false;
    }
    
    // Basic JSON structure validation
    int brace_count = 0;
    int bracket_count = 0;
    bool in_string = false;
    bool escaped = false;
    
    for (char c : json_str) {
        if (escaped) {
            escaped = false;
            continue;
        }
        
        if (c == '\\') {
            escaped = true;
            continue;
        }
        
        if (c == '"') {
            in_string = !in_string;
            continue;
        }
        
        if (!in_string) {
            if (c == '{') brace_count++;
            else if (c == '}') brace_count--;
            else if (c == '[') bracket_count++;
            else if (c == ']') bracket_count--;
        }
    }
    
    return brace_count == 0 && bracket_count == 0 && !in_string;
}

bool validateJSONField(const std::string& field_name, const std::string& field_value, const std::string& expected_type) {
    if (field_name.empty() || field_value.empty()) {
        return false;
    }
    
    if (expected_type == "string") {
        return true; // Any non-empty string is valid
    } else if (expected_type == "number") {
        return isNumeric(field_value);
    } else if (expected_type == "boolean") {
        return field_value == "true" || field_value == "false";
    } else if (expected_type == "array") {
        return field_value.front() == '[' && field_value.back() == ']';
    } else if (expected_type == "object") {
        return field_value.front() == '{' && field_value.back() == '}';
    }
    
    return false;
}

// File validation
bool validateFilePath(const std::string& file_path) {
    if (file_path.empty() || file_path.length() > 4096) {
        return false;
    }
    
    // Check for path traversal attempts
    if (file_path.find("..") != std::string::npos) {
        return false;
    }
    
    // Check for valid file path characters
    for (char c : file_path) {
        if (c < 32 || c > 126) { // Printable ASCII only
            return false;
        }
    }
    
    return true;
}

bool validateConfigFile(const std::string& config_file) {
    if (!validateFilePath(config_file)) {
        return false;
    }
    
    // Check file extension
    std::string extension = config_file.substr(config_file.find_last_of('.') + 1);
    std::transform(extension.begin(), extension.end(), extension.begin(), ::tolower);
    
    return extension == "conf" || extension == "ini" || extension == "json" || extension == "yaml";
}

bool validateLogFile(const std::string& log_file) {
    if (!validateFilePath(log_file)) {
        return false;
    }
    
    // Check file extension
    std::string extension = log_file.substr(log_file.find_last_of('.') + 1);
    std::transform(extension.begin(), extension.end(), extension.begin(), ::tolower);
    
    return extension == "log" || extension == "txt";
}

// Security validation
bool validateInputLength(const std::string& input, size_t max_length) {
    return input.length() <= max_length;
}

bool validateInputCharacters(const std::string& input, const std::string& allowed_chars) {
    for (char c : input) {
        if (allowed_chars.find(c) == std::string::npos) {
            return false;
        }
    }
    return true;
}

bool validateNoInjection(const std::string& input) {
    std::vector<std::string> dangerous_patterns = {
        "script", "javascript", "vbscript", "onload", "onerror", "onclick",
        "select", "insert", "update", "delete", "drop", "create", "alter"
    };
    
    std::string lower_input = input;
    std::transform(lower_input.begin(), lower_input.end(), lower_input.begin(), ::tolower);
    
    for (const auto& pattern : dangerous_patterns) {
        if (lower_input.find(pattern) != std::string::npos) {
            return false;
        }
    }
    
    return true;
}

bool validateNoPathTraversal(const std::string& path) {
    return path.find("..") == std::string::npos && 
           path.find("~") == std::string::npos &&
           path.find("\\") == std::string::npos;
}

// Vehicle dynamics validation
bool validateHeading(float heading) {
    return heading >= 0.0f && heading < 360.0f;
}

bool validateSpeed(float speed) {
    return speed >= 0.0f && speed <= 1000.0f; // 0 to 1000 m/s
}

bool validatePitch(float pitch) {
    return pitch >= -90.0f && pitch <= 90.0f;
}

bool validateRoll(float roll) {
    return roll >= -180.0f && roll <= 180.0f;
}

bool validateYaw(float yaw) {
    return yaw >= -180.0f && yaw <= 180.0f;
}

bool validateVerticalSpeed(float vs) {
    return vs >= -100.0f && vs <= 100.0f; // -100 to 100 m/s
}

bool validateAltitudeAGL(float alt_agl) {
    return alt_agl >= 0.0f && alt_agl <= 50000.0f; // 0 to 50 km
}

// Antenna validation
bool validateAntennaAzimuth(float azimuth) {
    return azimuth >= 0.0f && azimuth < 360.0f;
}

bool validateAntennaElevation(float elevation) {
    return elevation >= -90.0f && elevation <= 90.0f;
}

bool validateAntennaRotation(float rotation) {
    return rotation >= 0.0f && rotation < 360.0f;
}

// Power management validation
bool validatePowerEfficiency(float efficiency) {
    return efficiency >= 0.0f && efficiency <= 1.0f;
}

bool validateBatteryLevel(float battery_level) {
    return battery_level >= 0.0f && battery_level <= 1.0f;
}

bool validateTemperature(float temperature) {
    return temperature >= -50.0f && temperature <= 200.0f; // -50°C to 200°C
}

// Utility functions
std::string sanitizeInput(const std::string& input) {
    std::string sanitized = input;
    
    // Remove control characters
    sanitized.erase(std::remove_if(sanitized.begin(), sanitized.end(),
        [](char c) { return c < 32 || c == 127; }), sanitized.end());
    
    // Trim whitespace
    sanitized.erase(0, sanitized.find_first_not_of(" \t\n\r"));
    sanitized.erase(sanitized.find_last_not_of(" \t\n\r") + 1);
    
    return sanitized;
}

std::string normalizeInput(const std::string& input) {
    std::string normalized = sanitizeInput(input);
    std::transform(normalized.begin(), normalized.end(), normalized.begin(), ::tolower);
    return normalized;
}

std::vector<std::string> parseCommaSeparatedValues(const std::string& input) {
    std::vector<std::string> values;
    std::stringstream ss(input);
    std::string item;
    
    while (std::getline(ss, item, ',')) {
        std::string trimmed = sanitizeInput(item);
        if (!trimmed.empty()) {
            values.push_back(trimmed);
        }
    }
    
    return values;
}

bool isNumeric(const std::string& str) {
    if (str.empty()) return false;
    
    size_t start = 0;
    if (str[0] == '-' || str[0] == '+') start = 1;
    
    bool has_digit = false;
    bool has_dot = false;
    
    for (size_t i = start; i < str.length(); ++i) {
        if (std::isdigit(str[i])) {
            has_digit = true;
        } else if (str[i] == '.' && !has_dot) {
            has_dot = true;
        } else {
            return false;
        }
    }
    
    return has_digit;
}

bool isAlphaNumeric(const std::string& str) {
    return std::all_of(str.begin(), str.end(), [](char c) {
        return std::isalnum(c);
    });
}

bool isAlpha(const std::string& str) {
    return std::all_of(str.begin(), str.end(), [](char c) {
        return std::isalpha(c);
    });
}

// ValidationResult implementation
void ValidationResult::addError(const ValidationError& error) {
    errors.push_back(error);
    is_valid = false;
}

void ValidationResult::addError(const std::string& field, const std::string& message, 
                               const std::string& value, const std::string& format) {
    addError(ValidationError(field, message, value, format));
}

std::string ValidationResult::getErrorSummary() const {
    if (errors.empty()) {
        return "Validation passed";
    }
    
    std::stringstream ss;
    ss << "Validation failed with " << errors.size() << " error(s):\n";
    
    for (const auto& error : errors) {
        ss << "- " << error.field_name << ": " << error.error_message;
        if (!error.provided_value.empty()) {
            ss << " (provided: " << error.provided_value << ")";
        }
        if (!error.expected_format.empty()) {
            ss << " (expected: " << error.expected_format << ")";
        }
        ss << "\n";
    }
    
    return ss.str();
}

void ValidationResult::clear() {
    errors.clear();
    is_valid = true;
}

// Comprehensive validation functions (simplified implementations)
ValidationResult validatePropagationRequest(const std::string& json_request) {
    ValidationResult result;
    
    if (!validateJSONString(json_request)) {
        result.addError("request", "Invalid JSON format", json_request);
    }
    
    // Additional validation would be implemented here
    return result;
}

ValidationResult validateSolarDataRequest(const std::string& json_request) {
    ValidationResult result;
    
    if (!validateJSONString(json_request)) {
        result.addError("request", "Invalid JSON format", json_request);
    }
    
    return result;
}

ValidationResult validateBandStatusRequest(const std::string& json_request) {
    ValidationResult result;
    
    if (!validateJSONString(json_request)) {
        result.addError("request", "Invalid JSON format", json_request);
    }
    
    return result;
}

ValidationResult validateAntennaPatternRequest(const std::string& json_request) {
    ValidationResult result;
    
    if (!validateJSONString(json_request)) {
        result.addError("request", "Invalid JSON format", json_request);
    }
    
    return result;
}

ValidationResult validateVehicleDynamicsRequest(const std::string& json_request) {
    ValidationResult result;
    
    if (!validateJSONString(json_request)) {
        result.addError("request", "Invalid JSON format", json_request);
    }
    
    return result;
}

ValidationResult validatePowerManagementRequest(const std::string& json_request) {
    ValidationResult result;
    
    if (!validateJSONString(json_request)) {
        result.addError("request", "Invalid JSON format", json_request);
    }
    
    return result;
}

ValidationResult validateConfigurationFile(const std::string& config_file) {
    ValidationResult result;
    
    if (!validateConfigFile(config_file)) {
        result.addError("config_file", "Invalid configuration file path", config_file);
    }
    
    return result;
}

ValidationResult validateFeatureToggleConfig(const std::string& config) {
    ValidationResult result;
    
    if (!validateJSONString(config)) {
        result.addError("config", "Invalid JSON format", config);
    }
    
    return result;
}

ValidationResult validateThreadingConfig(const std::string& config) {
    ValidationResult result;
    
    if (!validateJSONString(config)) {
        result.addError("config", "Invalid JSON format", config);
    }
    
    return result;
}

ValidationResult validateGPUConfig(const std::string& config) {
    ValidationResult result;
    
    if (!validateJSONString(config)) {
        result.addError("config", "Invalid JSON format", config);
    }
    
    return result;
}

ValidationResult validateAPIRequest(const std::string& endpoint, const std::string& method, 
                                   const std::string& request_body, const std::map<std::string, std::string>& headers) {
    ValidationResult result;
    
    if (endpoint.empty()) {
        result.addError("endpoint", "Endpoint cannot be empty");
    }
    
    if (method.empty()) {
        result.addError("method", "HTTP method cannot be empty");
    }
    
    if (!validateInputLength(request_body, 1024 * 1024)) { // 1MB limit
        result.addError("request_body", "Request body too large", std::to_string(request_body.length()));
    }
    
    return result;
}

bool validateRateLimitRequest(const std::string& client_ip, int requests_per_minute) {
    if (!validateIPAddress(client_ip)) {
        return false;
    }
    
    if (requests_per_minute <= 0 || requests_per_minute > 10000) {
        return false;
    }
    
    return true;
}

bool validateRequestSize(size_t request_size, size_t max_size) {
    return request_size <= max_size;
}

bool validateRequestTimeout(const std::chrono::system_clock::time_point& request_time, 
                           const std::chrono::system_clock::time_point& current_time, 
                           int timeout_seconds) {
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(current_time - request_time);
    return duration.count() <= timeout_seconds;
}

} // namespace InputValidation



