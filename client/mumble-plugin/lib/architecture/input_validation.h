/* 
 * This file is part of the FGCom-mumble distribution (https://github.com/hbeni/fgcom-mumble).
 * Copyright (c) 2020 Benedikt Hallinger
 * 
 * This program is free software: you can redistribute it and/or modify  
 * it under the terms of the GNU General Public License as published by  
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but 
 * WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU 
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef FGCOM_INPUT_VALIDATION_H
#define FGCOM_INPUT_VALIDATION_H

#include <string>
#include <vector>
#include <regex>
#include <limits>
#include <algorithm>
#include <cctype>

namespace fgcom {
namespace architecture {

/**
 * @brief Validation result structure
 */
struct ValidationResult {
    bool isValid;
    std::string errorMessage;
    std::string sanitizedValue;
    
    ValidationResult() : isValid(true) {}
    ValidationResult(bool valid, const std::string& error) 
        : isValid(valid), errorMessage(error) {}
};

/**
 * @brief Input validation utilities
 * 
 * Provides comprehensive input validation with sanitization
 * and security checks for all input types.
 */
class InputValidator {
public:
    /**
     * @brief Validate and sanitize string input
     * @param input Input string
     * @param maxLength Maximum allowed length
     * @param allowSpecialChars Allow special characters
     * @return ValidationResult Validation result
     */
    static ValidationResult validateString(const std::string& input, 
                                         size_t maxLength = 256,
                                         bool allowSpecialChars = false) {
        ValidationResult result;
        
        // Check length
        if (input.length() > maxLength) {
            result.isValid = false;
            result.errorMessage = "Input too long (max " + std::to_string(maxLength) + " characters)";
            return result;
        }
        
        // Check for null bytes
        if (input.find('\0') != std::string::npos) {
            result.isValid = false;
            result.errorMessage = "Null bytes not allowed";
            return result;
        }
        
        // Sanitize input
        result.sanitizedValue = sanitizeString(input, allowSpecialChars);
        
        // Check if sanitization changed the input significantly
        if (!allowSpecialChars && result.sanitizedValue != input) {
            result.isValid = false;
            result.errorMessage = "Invalid characters detected";
            return result;
        }
        
        result.isValid = true;
        return result;
    }
    
    /**
     * @brief Validate numeric input
     * @param value Numeric value
     * @param minValue Minimum allowed value
     * @param maxValue Maximum allowed value
     * @return ValidationResult Validation result
     */
    template<typename T>
    static ValidationResult validateNumeric(T value, T minValue, T maxValue) {
        ValidationResult result;
        
        if (value < minValue || value > maxValue) {
            result.isValid = false;
            result.errorMessage = "Value out of range [" + 
                                std::to_string(minValue) + ", " + 
                                std::to_string(maxValue) + "]";
            return result;
        }
        
        result.isValid = true;
        result.sanitizedValue = std::to_string(value);
        return result;
    }
    
    /**
     * @brief Validate frequency input
     * @param frequency Frequency in Hz
     * @return ValidationResult Validation result
     */
    static ValidationResult validateFrequency(double frequency) {
        const double MIN_FREQUENCY = 0.0;
        const double MAX_FREQUENCY = 1000000000.0; // 1 GHz
        
        if (frequency < MIN_FREQUENCY || frequency > MAX_FREQUENCY) {
            return ValidationResult(false, "Frequency out of range [0, 1GHz]");
        }
        
        if (std::isnan(frequency) || std::isinf(frequency)) {
            return ValidationResult(false, "Invalid frequency value");
        }
        
        return ValidationResult(true, "");
    }
    
    /**
     * @brief Validate latitude input
     * @param latitude Latitude in degrees
     * @return ValidationResult Validation result
     */
    static ValidationResult validateLatitude(double latitude) {
        const double MIN_LATITUDE = -90.0;
        const double MAX_LATITUDE = 90.0;
        
        if (latitude < MIN_LATITUDE || latitude > MAX_LATITUDE) {
            return ValidationResult(false, "Latitude out of range [-90, 90]");
        }
        
        if (std::isnan(latitude) || std::isinf(latitude)) {
            return ValidationResult(false, "Invalid latitude value");
        }
        
        return ValidationResult(true, "");
    }
    
    /**
     * @brief Validate longitude input
     * @param longitude Longitude in degrees
     * @return ValidationResult Validation result
     */
    static ValidationResult validateLongitude(double longitude) {
        const double MIN_LONGITUDE = -180.0;
        const double MAX_LONGITUDE = 180.0;
        
        if (longitude < MIN_LONGITUDE || longitude > MAX_LONGITUDE) {
            return ValidationResult(false, "Longitude out of range [-180, 180]");
        }
        
        if (std::isnan(longitude) || std::isinf(longitude)) {
            return ValidationResult(false, "Invalid longitude value");
        }
        
        return ValidationResult(true, "");
    }
    
    /**
     * @brief Validate altitude input
     * @param altitude Altitude in meters
     * @return ValidationResult Validation result
     */
    static ValidationResult validateAltitude(double altitude) {
        const double MIN_ALTITUDE = -1000.0;  // Below sea level
        const double MAX_ALTITUDE = 100000.0;  // 100 km
        
        if (altitude < MIN_ALTITUDE || altitude > MAX_ALTITUDE) {
            return ValidationResult(false, "Altitude out of range [-1000m, 100km]");
        }
        
        if (std::isnan(altitude) || std::isinf(altitude)) {
            return ValidationResult(false, "Invalid altitude value");
        }
        
        return ValidationResult(true, "");
    }
    
    /**
     * @brief Validate port number
     * @param port Port number
     * @return ValidationResult Validation result
     */
    static ValidationResult validatePort(int port) {
        const int MIN_PORT = 1;
        const int MAX_PORT = 65535;
        
        if (port < MIN_PORT || port > MAX_PORT) {
            return ValidationResult(false, "Port out of range [1, 65535]");
        }
        
        return ValidationResult(true, "");
    }
    
    /**
     * @brief Validate IP address
     * @param ip IP address string
     * @return ValidationResult Validation result
     */
    static ValidationResult validateIPAddress(const std::string& ip) {
        // IPv4 regex pattern
        std::regex ipv4_pattern(R"(^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$)");
        std::smatch matches;
        
        if (!std::regex_match(ip, matches, ipv4_pattern)) {
            return ValidationResult(false, "Invalid IP address format");
        }
        
        // Validate each octet
        for (int i = 1; i <= 4; ++i) {
            int octet = std::stoi(matches[i].str());
            if (octet < 0 || octet > 255) {
                return ValidationResult(false, "Invalid IP address octet");
            }
        }
        
        return ValidationResult(true, "");
    }
    
    /**
     * @brief Validate callsign
     * @param callsign Callsign string
     * @return ValidationResult Validation result
     */
    static ValidationResult validateCallsign(const std::string& callsign) {
        // Check length
        if (callsign.empty() || callsign.length() > 20) {
            return ValidationResult(false, "Callsign must be 1-20 characters");
        }
        
        // Check for valid characters (letters, numbers, dash, slash)
        std::regex callsign_pattern(R"(^[A-Za-z0-9/-]+$)");
        if (!std::regex_match(callsign, callsign_pattern)) {
            return ValidationResult(false, "Callsign contains invalid characters");
        }
        
        // Sanitize callsign
        std::string sanitized = callsign;
        std::transform(sanitized.begin(), sanitized.end(), sanitized.begin(), ::toupper);
        
        ValidationResult result(true, "");
        result.sanitizedValue = sanitized;
        return result;
    }
    
    /**
     * @brief Validate file path
     * @param path File path string
     * @return ValidationResult Validation result
     */
    static ValidationResult validateFilePath(const std::string& path) {
        // Check for path traversal attempts
        if (path.find("..") != std::string::npos) {
            return ValidationResult(false, "Path traversal not allowed");
        }
        
        // Check for null bytes
        if (path.find('\0') != std::string::npos) {
            return ValidationResult(false, "Null bytes not allowed in path");
        }
        
        // Check length
        if (path.length() > 4096) {
            return ValidationResult(false, "Path too long");
        }
        
        return ValidationResult(true, "");
    }
    
    /**
     * @brief Validate configuration key
     * @param key Configuration key
     * @return ValidationResult Validation result
     */
    static ValidationResult validateConfigKey(const std::string& key) {
        // Check length
        if (key.empty() || key.length() > 100) {
            return ValidationResult(false, "Config key must be 1-100 characters");
        }
        
        // Check for valid characters
        std::regex key_pattern(R"(^[A-Za-z0-9_.-]+$)");
        if (!std::regex_match(key, key_pattern)) {
            return ValidationResult(false, "Config key contains invalid characters");
        }
        
        return ValidationResult(true, "");
    }
    
    /**
     * @brief Validate configuration value
     * @param value Configuration value
     * @return ValidationResult Validation result
     */
    static ValidationResult validateConfigValue(const std::string& value) {
        // Check length
        if (value.length() > 1000) {
            return ValidationResult(false, "Config value too long");
        }
        
        // Check for null bytes
        if (value.find('\0') != std::string::npos) {
            return ValidationResult(false, "Null bytes not allowed in config value");
        }
        
        return ValidationResult(true, "");
    }
    
private:
    /**
     * @brief Sanitize string input
     * @param input Input string
     * @param allowSpecialChars Allow special characters
     * @return std::string Sanitized string
     */
    static std::string sanitizeString(const std::string& input, bool allowSpecialChars) {
        std::string sanitized = input;
        
        if (!allowSpecialChars) {
            // Remove or replace special characters
            sanitized.erase(std::remove_if(sanitized.begin(), sanitized.end(),
                [](char c) {
                    return !std::isalnum(c) && c != ' ' && c != '-' && c != '_';
                }), sanitized.end());
        }
        
        // Remove null bytes
        sanitized.erase(std::remove(sanitized.begin(), sanitized.end(), '\0'), sanitized.end());
        
        return sanitized;
    }
};

} // namespace architecture
} // namespace fgcom

#endif // FGCOM_ERROR_HANDLER_H
