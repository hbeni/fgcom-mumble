#ifndef FGCOM_WORK_UNIT_SECURITY_H
#define FGCOM_WORK_UNIT_SECURITY_H

#include <vector>
#include <string>
#include <memory>
#include <map>
#include <chrono>
#include <mutex>
#include <atomic>
#include <thread>
#include <queue>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <unordered_set>
#include <future>
// Secure OpenSSL wrapper to prevent direct usage
namespace SecureOpenSSL {
    class OpenSSLInitializer {
    private:
        static std::atomic<bool> initialized;
        static std::mutex init_mutex;
    public:
        static bool initialize();
        static void cleanup();
        static bool isInitialized();
    };
    
    class SecureRandom {
    public:
        static bool generateBytes(unsigned char* buffer, size_t length);
        static std::string generateSecureToken(size_t length);
    };
    
    class SecureHash {
    public:
        static std::string sha256(const std::string& data);
        static std::string hmacSha256(const std::string& data, const std::string& key);
        static bool verifyHash(const std::string& data, const std::string& hash);
    };
    
    class SecureEncryption {
    public:
        static std::string encryptAES256(const std::string& data, const std::string& key);
        static std::string decryptAES256(const std::string& encrypted_data, const std::string& key);
        static std::string generateAESKey();
    };
}

// Forward declarations
#include "work_unit_distributor.h"

// Security levels for work units
enum class SecurityLevel {
    LOW = 0,        // Basic validation only
    MEDIUM = 1,     // Signature validation + rate limiting
    HIGH = 2,       // Full encryption + client certificates
    CRITICAL = 3    // Military-grade security
};

// Client authentication methods
enum class AuthenticationMethod {
    NONE = 0,           // No authentication
    API_KEY = 1,        // API key only
    CLIENT_CERT = 2,     // Client certificate
    JWT_TOKEN = 3,       // JWT token
    OAUTH2 = 4,          // OAuth2 flow
    MULTI_FACTOR = 5     // Multiple methods combined
};

// Authentication data - focused on authentication only
struct AuthenticationData {
    std::string client_id;
    std::string api_key_hash;
    std::string certificate_fingerprint;
    std::string public_key_pem;
    AuthenticationMethod auth_method;
    std::chrono::system_clock::time_point last_auth;
    std::chrono::system_clock::time_point created_time;
    int failed_auth_attempts;
    std::chrono::system_clock::time_point last_failed_auth;
};

// Rate limiting data - focused on rate limiting only
struct RateLimitingData {
    std::map<std::string, int> rate_limits;
    std::map<std::string, int> current_usage;
    std::chrono::system_clock::time_point last_reset;
    std::chrono::system_clock::time_point next_reset;
};

// Reputation data - focused on reputation only
struct ReputationData {
    double reputation_score;
    std::vector<std::string> security_violations;
    std::chrono::system_clock::time_point last_violation;
    int violation_count;
    double trust_level;
};

// Client security profile - composed of focused components
struct ClientSecurityProfile {
    AuthenticationData auth_data;
    RateLimitingData rate_data;
    ReputationData reputation_data;
    SecurityLevel security_level;
    bool is_trusted;
    bool is_blocked;
    std::vector<std::string> allowed_work_unit_types;
};

// Work unit security wrapper
struct SecureWorkUnit {
    WorkUnit work_unit;
    std::string digital_signature;
    std::string encryption_key_id;
    std::string integrity_hash;
    std::chrono::system_clock::time_point signature_time;
    std::string signer_client_id;
    SecurityLevel required_security_level;
    std::vector<std::string> allowed_recipients;
    bool is_encrypted;
    std::string encrypted_data;
};

// Result validation data
struct ResultValidation {
    std::string work_unit_id;
    std::string client_id;
    std::vector<double> result_data;
    std::string result_signature;
    std::string validation_hash;
    bool is_validated;
    double confidence_score;
    std::chrono::system_clock::time_point validation_time;
    std::vector<std::string> validator_clients;
    std::map<std::string, double> consensus_scores;
};

// Security monitoring event
struct SecurityEvent {
    std::string event_id;
    std::string event_type;
    std::string client_id;
    std::string description;
    SecurityLevel severity;
    std::chrono::system_clock::time_point timestamp;
    std::map<std::string, std::string> metadata;
    bool requires_action;
    std::string recommended_action;
};

// Main security manager class
class FGCom_WorkUnitSecurityManager {
private:
    static std::unique_ptr<FGCom_WorkUnitSecurityManager> instance;
    static std::mutex instance_mutex;
    
    // Configuration
    SecurityLevel global_security_level;
    bool security_enabled;
    bool encryption_enabled;
    bool signature_validation_enabled;
    bool rate_limiting_enabled;
    bool monitoring_enabled;
    
    // Client management
    std::map<std::string, ClientSecurityProfile> client_profiles;
    std::map<std::string, std::string> api_keys;
    std::map<std::string, std::string> client_certificates;
    std::map<std::string, std::string> jwt_secrets;
    
    // Security keys and certificates
    EVP_PKEY* server_private_key;
    EVP_PKEY* server_public_key;
    X509* server_certificate;
    std::map<std::string, EVP_PKEY*> client_public_keys;
    std::map<std::string, X509*> client_certificates_x509;
    
    // Rate limiting
    std::map<std::string, std::map<std::string, std::queue<std::chrono::system_clock::time_point>>> rate_limit_queues;
    std::mutex rate_limit_mutex;
    
    // Security monitoring
    std::vector<SecurityEvent> security_events;
    std::mutex events_mutex;
    std::thread monitoring_thread;
    std::atomic<bool> monitoring_running;
    
    // Threading and synchronization
    std::mutex security_mutex;
    std::mutex clients_mutex;
    
    // Internal methods
    void initializeSecurityKeys();
    void loadServerCertificate();
    void startSecurityMonitoring();
    void stopSecurityMonitoring();
    void monitoringThreadFunction();
    void processSecurityEvent(const SecurityEvent& event);
    bool validateClientCertificate(const std::string& client_id, const std::string& certificate);
    bool validateAPIKey(const std::string& client_id, const std::string& api_key);
    bool validateJWTToken(const std::string& client_id, const std::string& token);
    std::string generateDigitalSignature(const WorkUnit& work_unit, const std::string& client_id);
    bool verifyDigitalSignature(const SecureWorkUnit& secure_work_unit);
    std::string encryptWorkUnitData(const WorkUnit& work_unit, const std::string& client_id);
    WorkUnit decryptWorkUnitData(const std::string& encrypted_data, const std::string& client_id);
    bool checkRateLimit(const std::string& client_id, const std::string& operation);
    void updateClientReputation(const std::string& client_id, double reputation_delta);
    void logSecurityEvent(const std::string& event_type, const std::string& client_id, 
                         const std::string& description, SecurityLevel severity);
    
public:
    // Singleton access
    static FGCom_WorkUnitSecurityManager& getInstance();
    static void destroyInstance();
    
    // Initialization and configuration
    bool initialize(SecurityLevel security_level = SecurityLevel::MEDIUM);
    void shutdown();
    void setSecurityLevel(SecurityLevel level);
    void setSecurityFeatures(bool encryption, bool signatures, bool rate_limiting, bool monitoring);
    
    // Client authentication and authorization
    bool registerClient(const std::string& client_id, const ClientSecurityProfile& profile);
    bool authenticateClient(const std::string& client_id, const std::string& auth_data, 
                          AuthenticationMethod method);
    bool authorizeClient(const std::string& client_id, const std::string& operation);
    bool revokeClientAccess(const std::string& client_id);
    ClientSecurityProfile getClientProfile(const std::string& client_id);
    std::vector<std::string> getTrustedClients();
    std::vector<std::string> getBlockedClients();
    
    // Work unit security
    SecureWorkUnit createSecureWorkUnit(const WorkUnit& work_unit, const std::string& client_id);
    WorkUnit extractWorkUnit(const SecureWorkUnit& secure_work_unit, const std::string& client_id);
    bool validateWorkUnitIntegrity(const SecureWorkUnit& secure_work_unit);
    bool validateWorkUnitAuthorization(const SecureWorkUnit& secure_work_unit, const std::string& client_id);
    
    // Result validation and consensus
    bool validateResult(const ResultValidation& validation);
    double calculateResultConfidence(const std::string& work_unit_id);
    bool addResultValidation(const std::string& work_unit_id, const std::string& client_id, 
                           const std::vector<double>& result_data);
    std::vector<double> getConsensusResult(const std::string& work_unit_id);
    bool isResultConsensusReached(const std::string& work_unit_id);
    
    // Rate limiting and abuse prevention
    bool checkClientRateLimit(const std::string& client_id, const std::string& operation);
    void updateClientUsage(const std::string& client_id, const std::string& operation);
    void resetClientUsage(const std::string& client_id);
    std::map<std::string, int> getClientUsage(const std::string& client_id);
    
    // Security monitoring and threat detection
    std::vector<SecurityEvent> getSecurityEvents(SecurityLevel min_severity = SecurityLevel::LOW);
    std::vector<SecurityEvent> getClientSecurityEvents(const std::string& client_id);
    void addSecurityEvent(const SecurityEvent& event);
    void clearSecurityEvents();
    std::map<std::string, double> getSecurityStatistics();
    
    // Utility methods
    void cleanup();
    bool isHealthy();
    std::string getSecurityReport();
    std::string generateAPIKey(const std::string& client_id);
    std::string generateJWTToken(const std::string& client_id, const std::map<std::string, std::string>& claims);
    bool validateJWTToken(const std::string& token, std::map<std::string, std::string>& claims);
};

// Client security coordinator
class FGCom_ClientSecurityCoordinator {
private:
    std::string client_id;
    std::string server_url;
    std::string api_key;
    std::string client_certificate_path;
    std::string client_private_key_path;
    std::string jwt_secret;
    SecurityLevel security_level;
    bool security_enabled;
    
    // Security keys
    EVP_PKEY* client_private_key;
    EVP_PKEY* client_public_key;
    X509* client_certificate;
    
public:
    FGCom_ClientSecurityCoordinator(const std::string& client_id, const std::string& server_url);
    ~FGCom_ClientSecurityCoordinator();
    
    // Initialization
    bool initialize(SecurityLevel security_level = SecurityLevel::MEDIUM);
    void shutdown();
    
    // Client authentication
    bool authenticateWithServer();
    bool registerWithServer(const ClientSecurityProfile& profile);
    bool updateClientProfile(const ClientSecurityProfile& profile);
    
    // Work unit security
    SecureWorkUnit createSecureWorkUnit(const WorkUnit& work_unit);
    WorkUnit extractSecureWorkUnit(const SecureWorkUnit& secure_work_unit);
    bool validateWorkUnitSignature(const SecureWorkUnit& secure_work_unit);
    
    // Result security
    ResultValidation createResultValidation(const std::string& work_unit_id, 
                                          const std::vector<double>& result_data);
    bool submitResultValidation(const ResultValidation& validation);
    
    // Security monitoring
    void reportSecurityEvent(const std::string& event_type, const std::string& description);
    std::vector<SecurityEvent> getSecurityEvents();
    
    // Utility methods
    bool isAuthenticated();
    std::string getClientID();
    SecurityLevel getSecurityLevel();
    std::string getSecurityReport();
};

// Cryptographic utilities
class FGCom_CryptographicUtils {
public:
    // Key generation
    static EVP_PKEY* generateRSAKeyPair(int key_size = 2048);
    static EVP_PKEY* generateECKeyPair(int curve = NID_secp256r1);
    static std::string exportPublicKeyPEM(EVP_PKEY* public_key);
    static std::string exportPrivateKeyPEM(EVP_PKEY* private_key);
    static EVP_PKEY* importPublicKeyPEM(const std::string& pem_data);
    static EVP_PKEY* importPrivateKeyPEM(const std::string& pem_data);
    
    // Digital signatures
    static std::string signData(const std::string& data, EVP_PKEY* private_key);
    static bool verifySignature(const std::string& data, const std::string& signature, EVP_PKEY* public_key);
    static std::string signWorkUnit(const WorkUnit& work_unit, EVP_PKEY* private_key);
    static bool verifyWorkUnitSignature(const WorkUnit& work_unit, const std::string& signature, EVP_PKEY* public_key);
    
    // Encryption and decryption
    static std::string encryptData(const std::string& data, const std::string& key);
    static std::string decryptData(const std::string& encrypted_data, const std::string& key);
    static std::string generateEncryptionKey();
    static std::string encryptWorkUnit(const WorkUnit& work_unit, const std::string& key);
    static WorkUnit decryptWorkUnit(const std::string& encrypted_data, const std::string& key);
    
    // Hashing and integrity
    static std::string calculateSHA256(const std::string& data);
    static std::string calculateHMAC(const std::string& data, const std::string& key);
    static std::string calculateWorkUnitHash(const WorkUnit& work_unit);
    static bool verifyWorkUnitHash(const WorkUnit& work_unit, const std::string& hash);
    
    // JWT token handling
    static std::string createJWTToken(const std::map<std::string, std::string>& claims, 
                                    const std::string& secret, int expiration_hours = 24);
    static bool validateJWTToken(const std::string& token, const std::string& secret, 
                                std::map<std::string, std::string>& claims);
    static std::string extractJWTClaims(const std::string& token);
    
    // Certificate handling
    static X509* generateSelfSignedCertificate(EVP_PKEY* private_key, const std::string& common_name);
    static std::string exportCertificatePEM(X509* certificate);
    static X509* importCertificatePEM(const std::string& pem_data);
    static bool validateCertificate(X509* certificate);
    static std::string getCertificateFingerprint(X509* certificate);
    
    // Random number generation
    static std::string generateRandomBytes(size_t length);
    static std::string generateUUID();
    static std::string generateAPIKey(size_t length = 32);
    static std::string generateSecureToken(size_t length = 64);
};

// Security event logger
class FGCom_SecurityEventLogger {
private:
    std::string log_file_path;
    std::mutex log_mutex;
    bool logging_enabled;
    
public:
    FGCom_SecurityEventLogger(const std::string& log_file_path = "security_events.log");
    ~FGCom_SecurityEventLogger();
    
    void logEvent(const SecurityEvent& event);
    void logEvent(const std::string& event_type, const std::string& client_id, 
                 const std::string& description, SecurityLevel severity);
    void enableLogging(bool enable);
    void setLogFile(const std::string& file_path);
    std::vector<SecurityEvent> readEvents(SecurityLevel min_severity = SecurityLevel::LOW);
    void clearLog();
};

#endif // FGCOM_WORK_UNIT_SECURITY_H
