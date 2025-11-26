#ifndef FGCOM_INPUT_VALIDATION_H
#define FGCOM_INPUT_VALIDATION_H

#include <string>
#include <vector>
#include <regex>
#include <limits>
#include <cctype>
#include <stdexcept>
#include <chrono>

// Input validation utilities for FGCom-mumble
namespace InputValidation {
    
    // Network validation
    bool validatePort(int port);
    bool validateHost(const std::string& host);
    bool validateIPAddress(const std::string& ip);
    bool validateURL(const std::string& url);
    
    // Geographic validation
    bool validateLatitude(double lat);
    bool validateLongitude(double lon);
    bool validateAltitude(float alt);
    bool validateDistance(float distance);
    bool validateBearing(float bearing);
    
    // Radio frequency validation
    bool validateFrequency(float frequency);
    bool validateFrequencyRange(float min_freq, float max_freq);
    bool validatePower(float power);
    bool validateSWR(float swr);
    bool validateChannelWidth(float channel_width);
    
    // String validation
    bool validateCallsign(const std::string& callsign);
    bool validateGridSquare(const std::string& grid);
    bool validateMode(const std::string& mode);
    bool validateBand(const std::string& band);
    bool validateAntennaType(const std::string& antenna_type);
    bool validateGroundType(const std::string& ground_type);
    
    // Numeric validation
    bool validatePositiveNumber(double value);
    bool validateNonNegativeNumber(double value);
    bool validateRange(double value, double min_val, double max_val);
    bool validateInteger(int value, int min_val = std::numeric_limits<int>::min(), int max_val = std::numeric_limits<int>::max());
    bool validateFloat(float value, float min_val = std::numeric_limits<float>::min(), float max_val = std::numeric_limits<float>::max());
    
    // JSON validation
    bool validateJSONString(const std::string& json_str);
    bool validateJSONField(const std::string& field_name, const std::string& field_value, const std::string& expected_type);
    
    // File validation
    bool validateFilePath(const std::string& file_path);
    bool validateConfigFile(const std::string& config_file);
    bool validateLogFile(const std::string& log_file);
    
    // Security validation
    bool validateInputLength(const std::string& input, size_t max_length);
    bool validateInputCharacters(const std::string& input, const std::string& allowed_chars);
    bool validateNoInjection(const std::string& input);
    bool validateNoPathTraversal(const std::string& path);
    
    // Vehicle dynamics validation
    bool validateHeading(float heading);
    bool validateSpeed(float speed);
    bool validatePitch(float pitch);
    bool validateRoll(float roll);
    bool validateYaw(float yaw);
    bool validateVerticalSpeed(float vs);
    bool validateAltitudeAGL(float alt_agl);
    
    // Antenna validation
    bool validateAntennaAzimuth(float azimuth);
    bool validateAntennaElevation(float elevation);
    bool validateAntennaRotation(float rotation);
    
    // Power management validation
    bool validatePowerEfficiency(float efficiency);
    bool validateBatteryLevel(float battery_level);
    bool validateTemperature(float temperature);
    
    // Utility functions
    std::string sanitizeInput(const std::string& input);
    std::string normalizeInput(const std::string& input);
    std::vector<std::string> parseCommaSeparatedValues(const std::string& input);
    bool isNumeric(const std::string& str);
    bool isAlphaNumeric(const std::string& str);
    bool isAlpha(const std::string& str);
    
    // Error reporting
    struct ValidationError {
        std::string field_name;
        std::string error_message;
        std::string provided_value;
        std::string expected_format;
        
        ValidationError(const std::string& field, const std::string& message, 
                       const std::string& value = "", const std::string& format = "")
            : field_name(field), error_message(message), provided_value(value), expected_format(format) {}
    };
    
    class ValidationResult {
    private:
        bool is_valid;
        std::vector<ValidationError> errors;
        
    public:
        ValidationResult() : is_valid(true) {}
        
        void addError(const ValidationError& error);
        void addError(const std::string& field, const std::string& message, 
                     const std::string& value = "", const std::string& format = "");
        
        bool isValid() const { return is_valid; }
        const std::vector<ValidationError>& getErrors() const { return errors; }
        std::string getErrorSummary() const;
        void clear();
    };
    
    // Comprehensive validation functions
    ValidationResult validatePropagationRequest(const std::string& json_request);
    ValidationResult validateSolarDataRequest(const std::string& json_request);
    ValidationResult validateBandStatusRequest(const std::string& json_request);
    ValidationResult validateAntennaPatternRequest(const std::string& json_request);
    ValidationResult validateVehicleDynamicsRequest(const std::string& json_request);
    ValidationResult validatePowerManagementRequest(const std::string& json_request);
    
    // Configuration validation
    ValidationResult validateConfigurationFile(const std::string& config_file);
    ValidationResult validateFeatureToggleConfig(const std::string& config);
    ValidationResult validateThreadingConfig(const std::string& config);
    ValidationResult validateGPUConfig(const std::string& config);
    
    // API request validation
    ValidationResult validateAPIRequest(const std::string& endpoint, const std::string& method, 
                                       const std::string& request_body, const std::map<std::string, std::string>& headers);
    
    // Rate limiting validation
    bool validateRateLimitRequest(const std::string& client_ip, int requests_per_minute);
    bool validateRequestSize(size_t request_size, size_t max_size);
    bool validateRequestTimeout(const std::chrono::system_clock::time_point& request_time, 
                               const std::chrono::system_clock::time_point& current_time, 
                               int timeout_seconds);
}

#endif // FGCOM_INPUT_VALIDATION_H



