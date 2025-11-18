#ifndef TERRAIN_EXCEPTIONS_H
#define TERRAIN_EXCEPTIONS_H

#include <stdexcept>
#include <string>

namespace FGCom_TerrainEnvironmental {

    /**
     * @brief Base exception class for terrain and environmental operations
     * 
     * Provides consistent error handling with error codes and detailed messages.
     * All terrain-related exceptions inherit from this base class.
     */
    class TerrainException : public std::runtime_error {
    public:
        explicit TerrainException(const std::string& message, int errorCode = 0)
            : std::runtime_error(message), error_code_(errorCode) {}
        
        int getErrorCode() const noexcept { return error_code_; }
        
    private:
        const int error_code_;
    };

    /**
     * @brief Exception for invalid coordinate data
     * 
     * Thrown when coordinate values are outside valid bounds or malformed.
     */
    class InvalidCoordinateException : public TerrainException {
    public:
        explicit InvalidCoordinateException(const std::string& message)
            : TerrainException("Invalid coordinate: " + message, 1001) {}
    };

    /**
     * @brief Exception for invalid frequency values
     * 
     * Thrown when frequency is outside valid radio frequency range.
     */
    class InvalidFrequencyException : public TerrainException {
    public:
        explicit InvalidFrequencyException(const std::string& message)
            : TerrainException("Invalid frequency: " + message, 1002) {}
    };

    /**
     * @brief Exception for terrain data access failures
     * 
     * Thrown when terrain data cannot be retrieved or is corrupted.
     */
    class TerrainDataException : public TerrainException {
    public:
        explicit TerrainDataException(const std::string& message)
            : TerrainException("Terrain data error: " + message, 1003) {}
    };

    /**
     * @brief Exception for environmental data access failures
     * 
     * Thrown when environmental data cannot be retrieved or is invalid.
     */
    class EnvironmentalDataException : public TerrainException {
    public:
        explicit EnvironmentalDataException(const std::string& message)
            : TerrainException("Environmental data error: " + message, 1004) {}
    };

    /**
     * @brief Exception for calculation errors
     * 
     * Thrown when mathematical calculations fail or produce invalid results.
     */
    class CalculationException : public TerrainException {
    public:
        explicit CalculationException(const std::string& message)
            : TerrainException("Calculation error: " + message, 1005) {}
    };

    /**
     * @brief Exception for API server errors
     * 
     * Thrown when API server operations fail.
     */
    class APIServerException : public TerrainException {
    public:
        explicit APIServerException(const std::string& message)
            : TerrainException("API server error: " + message, 1006) {}
    };

    /**
     * @brief Exception for configuration errors
     * 
     * Thrown when configuration parameters are invalid or missing.
     */
    class ConfigurationException : public TerrainException {
    public:
        explicit ConfigurationException(const std::string& message)
            : TerrainException("Configuration error: " + message, 1007) {}
    };

} // namespace FGCom_TerrainEnvironmental

#endif // TERRAIN_EXCEPTIONS_H
