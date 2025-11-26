#ifndef FGCOM_SECURITY_H
#define FGCOM_SECURITY_H

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <chrono>
#include <mutex>
#include <atomic>
#include <random>

// Security utilities for FGCom-mumble
namespace Security {
    
    // Input sanitization
    class InputSanitizer {
    public:
        static std::string sanitizeString(const std::string& input, size_t max_length = 1024);
        static std::string sanitizeFilename(const std::string& filename);
        static std::string sanitizePath(const std::string& path);
        static std::string sanitizeJSON(const std::string& json);
        static std::string sanitizeSQL(const std::string& sql);
        static std::string sanitizeHTML(const std::string& html);
        static std::string sanitizeXML(const std::string& xml);
        
        // Remove dangerous characters
        static std::string removeControlCharacters(const std::string& input);
        static std::string removeUnicodeCharacters(const std::string& input);
        static std::string normalizeWhitespace(const std::string& input);
        
        // Validate input format
        static bool isValidASCII(const std::string& input);
        static bool isValidUTF8(const std::string& input);
        static bool isValidBase64(const std::string& input);
        static bool isValidHex(const std::string& input);
    };
    
    // Authentication and authorization
    class AuthenticationManager {
    private:
        std::map<std::string, std::string> user_credentials_;
        std::map<std::string, std::chrono::system_clock::time_point> session_tokens_;
        mutable std::mutex auth_mutex_;
        std::atomic<bool> enabled_;
        
    public:
        AuthenticationManager();
        ~AuthenticationManager();
        
        // User management
        bool addUser(const std::string& username, const std::string& password);
        bool removeUser(const std::string& username);
        bool changePassword(const std::string& username, const std::string& old_password, const std::string& new_password);
        
        // Authentication
        bool authenticate(const std::string& username, const std::string& password);
        std::string generateSessionToken(const std::string& username);
        bool validateSessionToken(const std::string& token);
        void invalidateSessionToken(const std::string& token);
        
        // Configuration
        void setEnabled(bool enabled) { enabled_ = enabled; }
        bool isEnabled() const { return enabled_.load(); }
        
        // Security
        void clearExpiredSessions();
        void clearAllSessions();
        size_t getActiveSessionCount() const;
    };
    
    // Rate limiting
    class RateLimiter {
    private:
        struct RateLimitEntry {
            std::chrono::system_clock::time_point last_request;
            int request_count;
            std::chrono::system_clock::time_point window_start;
        };
        
        std::map<std::string, RateLimitEntry> rate_limits_;
        mutable std::mutex rate_limit_mutex_;
        int max_requests_per_minute_;
        int max_requests_per_hour_;
        int max_requests_per_day_;
        
    public:
        RateLimiter(int per_minute = 100, int per_hour = 1000, int per_day = 10000);
        ~RateLimiter();
        
        // Rate limiting
        bool isAllowed(const std::string& client_id);
        bool isAllowed(const std::string& client_id, int custom_limit);
        void recordRequest(const std::string& client_id);
        
        // Configuration
        void setLimits(int per_minute, int per_hour, int per_day);
        void clearRateLimit(const std::string& client_id);
        void clearAllRateLimits();
        
        // Statistics
        int getRequestCount(const std::string& client_id) const;
        std::chrono::system_clock::time_point getLastRequestTime(const std::string& client_id) const;
    };
    
    // Encryption utilities
    class Encryption {
    public:
        // Hash functions
        static std::string hashSHA256(const std::string& input);
        static std::string hashSHA1(const std::string& input);
        static std::string hashMD5(const std::string& input);
        static std::string hashPassword(const std::string& password, const std::string& salt);
        
        // Salt generation
        static std::string generateSalt(size_t length = 32);
        static std::string generateRandomString(size_t length);
        
        // Base64 encoding/decoding
        static std::string encodeBase64(const std::string& input);
        static std::string decodeBase64(const std::string& input);
        
        // Simple XOR encryption (for basic obfuscation)
        static std::string encryptXOR(const std::string& input, const std::string& key);
        static std::string decryptXOR(const std::string& input, const std::string& key);
        
        // Key generation
        static std::string generateKey(size_t length = 32);
        static std::string generateUUID();
    };
    
    // Security headers
    class SecurityHeaders {
    public:
        static std::map<std::string, std::string> getDefaultHeaders();
        static std::map<std::string, std::string> getCORSHeaders();
        static std::map<std::string, std::string> getSecurityHeaders();
        static std::map<std::string, std::string> getAPIHeaders();
        
        // Individual headers
        static std::string getContentSecurityPolicy();
        static std::string getXFrameOptions();
        static std::string getXContentTypeOptions();
        static std::string getXSSProtection();
        static std::string getStrictTransportSecurity();
        static std::string getReferrerPolicy();
    };
    
    // Security validation
    class SecurityValidator {
    public:
        // File security
        static bool validateFileUpload(const std::string& filename, size_t file_size, const std::string& content_type);
        static bool validateFileExtension(const std::string& filename);
        static bool validateFileSize(size_t file_size, size_t max_size);
        static bool validateFileContent(const std::string& file_path);
        
        // Network security
        static bool validateIPAddress(const std::string& ip);
        static bool validatePort(int port);
        static bool validateURL(const std::string& url);
        static bool validateDomain(const std::string& domain);
        
        // Input security
        static bool validateNoSQLInjection(const std::string& input);
        static bool validateNoXSS(const std::string& input);
        static bool validateNoPathTraversal(const std::string& path);
        static bool validateNoCommandInjection(const std::string& input);
        
        // Configuration security
        static bool validateConfigFile(const std::string& config_file);
        static bool validateLogFile(const std::string& log_file);
        static bool validateTempFile(const std::string& temp_file);
    };
    
    // Security monitoring
    class SecurityMonitor {
    private:
        struct SecurityEvent {
            std::chrono::system_clock::time_point timestamp;
            std::string event_type;
            std::string source_ip;
            std::string user_agent;
            std::string description;
            int severity; // 1-10 scale
        };
        
        std::vector<SecurityEvent> security_events_;
        mutable std::mutex monitor_mutex_;
        std::atomic<bool> enabled_;
        size_t max_events_;
        
    public:
        SecurityMonitor(size_t max_events = 10000);
        ~SecurityMonitor();
        
        // Event logging
        void logEvent(const std::string& event_type, const std::string& source_ip, 
                     const std::string& user_agent, const std::string& description, int severity = 5);
        void logSuspiciousActivity(const std::string& source_ip, const std::string& description);
        void logFailedAuthentication(const std::string& source_ip, const std::string& username);
        void logRateLimitExceeded(const std::string& source_ip);
        void logInvalidInput(const std::string& source_ip, const std::string& input);
        
        // Event retrieval
        std::vector<SecurityEvent> getRecentEvents(int minutes = 60) const;
        std::vector<SecurityEvent> getEventsByType(const std::string& event_type) const;
        std::vector<SecurityEvent> getEventsByIP(const std::string& source_ip) const;
        std::vector<SecurityEvent> getHighSeverityEvents() const;
        
        // Statistics
        size_t getEventCount() const;
        size_t getEventCountByType(const std::string& event_type) const;
        size_t getEventCountByIP(const std::string& source_ip) const;
        
        // Configuration
        void setEnabled(bool enabled) { enabled_ = enabled; }
        bool isEnabled() const { return enabled_.load(); }
        void setMaxEvents(size_t max_events) { max_events_ = max_events; }
        void clearEvents();
    };
    
    // Security configuration
    class SecurityConfig {
    private:
        std::map<std::string, std::string> config_values_;
        mutable std::mutex config_mutex_;
        
    public:
        SecurityConfig();
        ~SecurityConfig();
        
        // Configuration management
        void setValue(const std::string& key, const std::string& value);
        std::string getValue(const std::string& key, const std::string& default_value = "") const;
        bool hasValue(const std::string& key) const;
        void removeValue(const std::string& key);
        
        // Security settings
        void setAuthenticationEnabled(bool enabled);
        bool isAuthenticationEnabled() const;
        
        void setRateLimitingEnabled(bool enabled);
        bool isRateLimitingEnabled() const;
        
        void setSecurityMonitoringEnabled(bool enabled);
        bool isSecurityMonitoringEnabled() const;
        
        void setMaxRequestSize(size_t max_size);
        size_t getMaxRequestSize() const;
        
        void setMaxFileSize(size_t max_size);
        size_t getMaxFileSize() const;
        
        void setSessionTimeout(int timeout_minutes);
        int getSessionTimeout() const;
        
        // Load/save configuration
        bool loadFromFile(const std::string& config_file);
        bool saveToFile(const std::string& config_file) const;
        
        // Default configuration
        void setDefaultConfiguration();
    };
    
    // Security manager (main security interface)
    class SecurityManager {
    private:
        std::unique_ptr<AuthenticationManager> auth_manager_;
        std::unique_ptr<RateLimiter> rate_limiter_;
        std::unique_ptr<SecurityMonitor> security_monitor_;
        std::unique_ptr<SecurityConfig> security_config_;
        mutable std::mutex manager_mutex_;
        std::atomic<bool> initialized_;
        
    public:
        SecurityManager();
        ~SecurityManager();
        
        // Initialization
        bool initialize();
        void shutdown();
        bool isInitialized() const { return initialized_.load(); }
        
        // Authentication
        bool authenticateUser(const std::string& username, const std::string& password);
        std::string createSession(const std::string& username);
        bool validateSession(const std::string& session_token);
        void destroySession(const std::string& session_token);
        
        // Rate limiting
        bool checkRateLimit(const std::string& client_id);
        void recordRequest(const std::string& client_id);
        
        // Security monitoring
        void logSecurityEvent(const std::string& event_type, const std::string& source_ip, 
                             const std::string& description, int severity = 5);
        
        // Input validation
        bool validateInput(const std::string& input, const std::string& input_type);
        std::string sanitizeInput(const std::string& input, const std::string& input_type);
        
        // Configuration
        SecurityConfig* getConfig() const { return security_config_.get(); }
        AuthenticationManager* getAuthManager() const { return auth_manager_.get(); }
        RateLimiter* getRateLimiter() const { return rate_limiter_.get(); }
        SecurityMonitor* getSecurityMonitor() const { return security_monitor_.get(); }
        
        // Security status
        std::string getSecurityStatus() const;
        std::vector<std::string> getSecurityRecommendations() const;
    };
    
    // Global security manager instance
    extern std::unique_ptr<SecurityManager> g_security_manager;
    
    // Utility functions
    namespace Utils {
        // IP address utilities
        std::string getClientIP(const std::string& request_headers);
        bool isPrivateIP(const std::string& ip);
        bool isLocalhost(const std::string& ip);
        
        // User agent utilities
        std::string getUserAgent(const std::string& request_headers);
        bool isSuspiciousUserAgent(const std::string& user_agent);
        
        // Request utilities
        std::string getRequestPath(const std::string& request_uri);
        std::map<std::string, std::string> parseQueryParameters(const std::string& query_string);
        
        // Security utilities
        std::string generateCSRFToken();
        bool validateCSRFToken(const std::string& token);
        std::string maskSensitiveData(const std::string& data);
        
        // Logging utilities
        void logSecurityViolation(const std::string& violation_type, const std::string& details);
        void logSecuritySuccess(const std::string& operation, const std::string& details);
    }
}

#endif // FGCOM_SECURITY_H



