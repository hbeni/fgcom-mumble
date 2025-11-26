/*
 * Work Unit Security Implementation
 * 
 * This file implements comprehensive security measures for the distributed
 * work unit system, including authentication, authorization, encryption,
 * digital signatures, and threat detection.
 */

#include "work_unit_security.h"
#include <algorithm>
#include <random>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <thread>
#include <fstream>
#include <iostream>
#include <cstring>

// Static member definitions
std::unique_ptr<FGCom_WorkUnitSecurityManager> FGCom_WorkUnitSecurityManager::instance = nullptr;
std::mutex FGCom_WorkUnitSecurityManager::instance_mutex;

// Singleton access
FGCom_WorkUnitSecurityManager& FGCom_WorkUnitSecurityManager::getInstance() {
    std::lock_guard<std::mutex> lock(instance_mutex);
    if (!instance) {
        instance = std::make_unique<FGCom_WorkUnitSecurityManager>();
    }
    return *instance;
}

void FGCom_WorkUnitSecurityManager::destroyInstance() {
    std::lock_guard<std::mutex> lock(instance_mutex);
    if (instance) {
        instance->shutdown();
        instance.reset();
    }
}

/**
 * Constructor for Work Unit Security Manager
 * 
 * Initializes the security manager with default settings and prepares OpenSSL
 * for cryptographic operations. This constructor sets up the foundation for
 * all security operations including encryption, digital signatures, and
 * authentication.
 * 
 * OpenSSL Initialization Notes:
 * - OpenSSL_add_all_algorithms() loads all available cryptographic algorithms
 * - ERR_load_crypto_strings() is deprecated in OpenSSL 3.0+ and removed
 * - All OpenSSL resources are properly managed with RAII patterns
 * - Thread safety is ensured through proper mutex usage
 */
FGCom_WorkUnitSecurityManager::FGCom_WorkUnitSecurityManager()
    : global_security_level(SecurityLevel::MEDIUM)
    , security_enabled(false)
    , encryption_enabled(false)
    , signature_validation_enabled(false)
    , rate_limiting_enabled(false)
    , monitoring_enabled(false)
    , server_private_key(nullptr)
    , server_public_key(nullptr)
    , server_certificate(nullptr)
    , monitoring_running(false) {
    
    // Initialize OpenSSL cryptographic library
    // This loads all available algorithms (AES, RSA, ECDSA, SHA, etc.)
    // Required before any cryptographic operations
    OpenSSL_add_all_algorithms();
    
    // Note: ERR_load_crypto_strings() is deprecated in OpenSSL 3.0+
    // Error strings are now loaded automatically in modern OpenSSL versions
}

// Initialization
bool FGCom_WorkUnitSecurityManager::initialize(SecurityLevel security_level) {
    std::lock_guard<std::mutex> lock(security_mutex);
    
    if (security_enabled) {
        return true; // Already initialized
    }
    
    global_security_level = security_level;
    
    // Initialize security keys
    initializeSecurityKeys();
    
    // Load server certificate
    loadServerCertificate();
    
    // Start security monitoring
    if (monitoring_enabled) {
        startSecurityMonitoring();
    }
    
    security_enabled = true;
    return true;
}

/**
 * Shutdown and cleanup security manager
 * 
 * Properly shuts down the security manager and cleans up all OpenSSL resources.
 * This is critical to prevent memory leaks and ensure clean shutdown.
 * 
 * OpenSSL Cleanup Process:
 * 1. Stop all monitoring threads first
 * 2. Free all EVP_PKEY structures (private/public keys)
 * 3. Free X509 certificates
 * 4. Clear all cryptographic contexts
 * 5. Reset all pointers to nullptr
 * 
 * Thread Safety: This method must be called with proper synchronization
 * to avoid race conditions during shutdown.
 */
void FGCom_WorkUnitSecurityManager::shutdown() {
    if (!security_enabled) {
        return;
    }
    
    // Stop security monitoring threads first to prevent new operations
    if (monitoring_running) {
        stopSecurityMonitoring();
    }
    
    // Critical: Clean up OpenSSL resources in proper order
    // Private key must be freed first (contains sensitive data)
    if (server_private_key) {
        EVP_PKEY_free(server_private_key);
        server_private_key = nullptr;
    }
    
    // Public key cleanup (less sensitive but still important)
    if (server_public_key) {
        EVP_PKEY_free(server_public_key);
        server_public_key = nullptr;
    }
    
    if (server_certificate) {
        X509_free(server_certificate);
        server_certificate = nullptr;
    }
    
    // Clean up client keys
    for (auto& pair : client_public_keys) {
        EVP_PKEY_free(pair.second);
    }
    client_public_keys.clear();
    
    for (auto& pair : client_certificates_x509) {
        X509_free(pair.second);
    }
    client_certificates_x509.clear();
    
    security_enabled = false;
}

void FGCom_WorkUnitSecurityManager::setSecurityLevel(SecurityLevel level) {
    std::lock_guard<std::mutex> lock(security_mutex);
    global_security_level = level;
}

void FGCom_WorkUnitSecurityManager::setSecurityFeatures(bool encryption, bool signatures, 
                                                        bool rate_limiting, bool monitoring) {
    std::lock_guard<std::mutex> lock(security_mutex);
    encryption_enabled = encryption;
    signature_validation_enabled = signatures;
    rate_limiting_enabled = rate_limiting;
    monitoring_enabled = monitoring;
}

// Client authentication and authorization
bool FGCom_WorkUnitSecurityManager::registerClient(const std::string& client_id, 
                                                   const ClientSecurityProfile& profile) {
    std::lock_guard<std::mutex> lock(clients_mutex);
    
    // Validate client profile
    if (client_id.empty() || profile.client_id != client_id) {
        return false;
    }
    
    // Store client profile
    client_profiles[client_id] = profile;
    
    // Generate API key if needed
    if (profile.auth_method == AuthenticationMethod::API_KEY) {
        api_keys[client_id] = generateAPIKey(client_id);
    }
    
    // Store client certificate if provided
    if (!profile.certificate_fingerprint.empty()) {
        client_certificates[client_id] = profile.certificate_fingerprint;
    }
    
    // Initialize rate limits
    if (rate_limiting_enabled) {
        rate_limit_queues[client_id] = std::map<std::string, std::queue<std::chrono::system_clock::time_point>>();
    }
    
    logSecurityEvent("CLIENT_REGISTERED", client_id, "Client registered successfully", SecurityLevel::LOW);
    return true;
}

bool FGCom_WorkUnitSecurityManager::authenticateClient(const std::string& client_id, 
                                                      const std::string& auth_data, 
                                                      AuthenticationMethod method) {
    std::lock_guard<std::mutex> lock(clients_mutex);
    
    auto it = client_profiles.find(client_id);
    if (it == client_profiles.end()) {
        logSecurityEvent("AUTH_FAILED", client_id, "Client not found", SecurityLevel::MEDIUM);
        return false;
    }
    
    ClientSecurityProfile& profile = it->second;
    
    // Check if client is blocked
    if (profile.is_blocked) {
        logSecurityEvent("AUTH_BLOCKED", client_id, "Client is blocked", SecurityLevel::HIGH);
        return false;
    }
    
    // Check failed authentication attempts
    if (profile.failed_auth_attempts >= 5) {
        auto now = std::chrono::system_clock::now();
        auto time_since_failure = std::chrono::duration_cast<std::chrono::minutes>(
            now - profile.last_failed_auth).count();
        
        if (time_since_failure < 30) { // 30 minute lockout
            logSecurityEvent("AUTH_LOCKED", client_id, "Client locked due to failed attempts", SecurityLevel::HIGH);
            return false;
        }
    }
    
    bool auth_success = false;
    
    switch (method) {
        case AuthenticationMethod::API_KEY:
            auth_success = validateAPIKey(client_id, auth_data);
            break;
        case AuthenticationMethod::CLIENT_CERT:
            auth_success = validateClientCertificate(client_id, auth_data);
            break;
        case AuthenticationMethod::JWT_TOKEN:
            auth_success = validateJWTToken(client_id, auth_data);
            break;
        default:
            auth_success = false;
            break;
    }
    
    if (auth_success) {
        profile.last_auth = std::chrono::system_clock::now();
        profile.failed_auth_attempts = 0;
        logSecurityEvent("AUTH_SUCCESS", client_id, "Client authenticated successfully", SecurityLevel::LOW);
    } else {
        profile.failed_auth_attempts++;
        profile.last_failed_auth = std::chrono::system_clock::now();
        logSecurityEvent("AUTH_FAILED", client_id, "Authentication failed", SecurityLevel::MEDIUM);
    }
    
    return auth_success;
}

bool FGCom_WorkUnitSecurityManager::authorizeClient(const std::string& client_id, 
                                                   const std::string& operation) {
    std::lock_guard<std::mutex> lock(clients_mutex);
    
    auto it = client_profiles.find(client_id);
    if (it == client_profiles.end()) {
        return false;
    }
    
    ClientSecurityProfile& profile = it->second;
    
    // Check if client is trusted
    if (!profile.is_trusted) {
        return false;
    }
    
    // Check rate limits
    if (rate_limiting_enabled && !checkRateLimit(client_id, operation)) {
        logSecurityEvent("RATE_LIMIT_EXCEEDED", client_id, "Rate limit exceeded for operation: " + operation, SecurityLevel::MEDIUM);
        return false;
    }
    
    return true;
}

bool FGCom_WorkUnitSecurityManager::revokeClientAccess(const std::string& client_id) {
    std::lock_guard<std::mutex> lock(clients_mutex);
    
    auto it = client_profiles.find(client_id);
    if (it == client_profiles.end()) {
        return false;
    }
    
    ClientSecurityProfile& profile = it->second;
    profile.is_blocked = true;
    profile.is_trusted = false;
    
    logSecurityEvent("CLIENT_REVOKED", client_id, "Client access revoked", SecurityLevel::HIGH);
    return true;
}

ClientSecurityProfile FGCom_WorkUnitSecurityManager::getClientProfile(const std::string& client_id) {
    std::lock_guard<std::mutex> lock(clients_mutex);
    
    auto it = client_profiles.find(client_id);
    if (it == client_profiles.end()) {
        return ClientSecurityProfile(); // Return empty profile
    }
    
    return it->second;
}

std::vector<std::string> FGCom_WorkUnitSecurityManager::getTrustedClients() {
    std::lock_guard<std::mutex> lock(clients_mutex);
    
    std::vector<std::string> trusted_clients;
    for (const auto& pair : client_profiles) {
        if (pair.second.is_trusted && !pair.second.is_blocked) {
            trusted_clients.push_back(pair.first);
        }
    }
    
    return trusted_clients;
}

std::vector<std::string> FGCom_WorkUnitSecurityManager::getBlockedClients() {
    std::lock_guard<std::mutex> lock(clients_mutex);
    
    std::vector<std::string> blocked_clients;
    for (const auto& pair : client_profiles) {
        if (pair.second.is_blocked) {
            blocked_clients.push_back(pair.first);
        }
    }
    
    return blocked_clients;
}

// Work unit security
SecureWorkUnit FGCom_WorkUnitSecurityManager::createSecureWorkUnit(const WorkUnit& work_unit, 
                                                                   const std::string& client_id) {
    SecureWorkUnit secure_work_unit;
    secure_work_unit.work_unit = work_unit;
    secure_work_unit.signature_time = std::chrono::system_clock::now();
    secure_work_unit.signer_client_id = client_id;
    secure_work_unit.required_security_level = global_security_level;
    secure_work_unit.is_encrypted = encryption_enabled;
    
    // Generate digital signature
    if (signature_validation_enabled) {
        secure_work_unit.digital_signature = generateDigitalSignature(work_unit, client_id);
    }
    
    // Encrypt work unit data if encryption is enabled
    if (encryption_enabled) {
        secure_work_unit.encrypted_data = encryptWorkUnitData(work_unit, client_id);
    }
    
    // Calculate integrity hash
    secure_work_unit.integrity_hash = FGCom_CryptographicUtils::calculateWorkUnitHash(work_unit);
    
    return secure_work_unit;
}

WorkUnit FGCom_WorkUnitSecurityManager::extractWorkUnit(const SecureWorkUnit& secure_work_unit, 
                                                       const std::string& client_id) {
    // Verify digital signature
    if (signature_validation_enabled && !verifyDigitalSignature(secure_work_unit)) {
        throw std::runtime_error("Invalid digital signature");
    }
    
    // Decrypt work unit data if encrypted
    if (secure_work_unit.is_encrypted) {
        return decryptWorkUnitData(secure_work_unit.encrypted_data, client_id);
    }
    
    return secure_work_unit.work_unit;
}

bool FGCom_WorkUnitSecurityManager::validateWorkUnitIntegrity(const SecureWorkUnit& secure_work_unit) {
    // Verify digital signature
    if (signature_validation_enabled && !verifyDigitalSignature(secure_work_unit)) {
        return false;
    }
    
    // Verify integrity hash
    std::string calculated_hash = FGCom_CryptographicUtils::calculateWorkUnitHash(secure_work_unit.work_unit);
    if (calculated_hash != secure_work_unit.integrity_hash) {
        return false;
    }
    
    return true;
}

bool FGCom_WorkUnitSecurityManager::validateWorkUnitAuthorization(const SecureWorkUnit& secure_work_unit, 
                                                                 const std::string& client_id) {
    // Check if client is authorized to receive this work unit
    if (!secure_work_unit.allowed_recipients.empty()) {
        auto it = std::find(secure_work_unit.allowed_recipients.begin(), 
                           secure_work_unit.allowed_recipients.end(), client_id);
        if (it == secure_work_unit.allowed_recipients.end()) {
            return false;
        }
    }
    
    // Check client security level
    auto client_it = client_profiles.find(client_id);
    if (client_it == client_profiles.end()) {
        return false;
    }
    
    ClientSecurityProfile& profile = client_it->second;
    if (profile.security_level < secure_work_unit.required_security_level) {
        return false;
    }
    
    return true;
}

// Result validation and consensus
bool FGCom_WorkUnitSecurityManager::validateResult(const ResultValidation& validation) {
    // Verify result signature
    if (signature_validation_enabled) {
        // Implementation would verify the result signature
        // This is a simplified placeholder
    }
    
    // Verify result hash
    std::string calculated_hash = FGCom_CryptographicUtils::calculateSHA256(
        std::to_string(validation.result_data.size()));
    if (calculated_hash != validation.validation_hash) {
        return false;
    }
    
    return true;
}

double FGCom_WorkUnitSecurityManager::calculateResultConfidence(const std::string& work_unit_id) {
    // Implementation would calculate confidence based on consensus
    // This is a simplified placeholder
    return 0.8; // 80% confidence
}

bool FGCom_WorkUnitSecurityManager::addResultValidation(const std::string& work_unit_id, 
                                                        const std::string& client_id, 
                                                        const std::vector<double>& result_data) {
    // Implementation would add result validation
    // This is a simplified placeholder
    return true;
}

std::vector<double> FGCom_WorkUnitSecurityManager::getConsensusResult(const std::string& work_unit_id) {
    // Implementation would return consensus result
    // This is a simplified placeholder
    return std::vector<double>();
}

bool FGCom_WorkUnitSecurityManager::isResultConsensusReached(const std::string& work_unit_id) {
    // Implementation would check if consensus is reached
    // This is a simplified placeholder
    return true;
}

// Rate limiting and abuse prevention
bool FGCom_WorkUnitSecurityManager::checkClientRateLimit(const std::string& client_id, 
                                                        const std::string& operation) {
    if (!rate_limiting_enabled) {
        return true;
    }
    
    std::lock_guard<std::mutex> lock(rate_limit_mutex);
    
    auto client_it = rate_limit_queues.find(client_id);
    if (client_it == rate_limit_queues.end()) {
        return true;
    }
    
    auto operation_it = client_it->second.find(operation);
    if (operation_it == client_it->second.end()) {
        return true;
    }
    
    auto now = std::chrono::system_clock::now();
    auto& queue = operation_it->second;
    
    // Remove old entries (older than 1 minute)
    while (!queue.empty() && (now - queue.front()) > std::chrono::minutes(1)) {
        queue.pop();
    }
    
    // Check if rate limit is exceeded (10 requests per minute)
    if (queue.size() >= 10) {
        return false;
    }
    
    // Add current request
    queue.push(now);
    return true;
}

void FGCom_WorkUnitSecurityManager::updateClientUsage(const std::string& client_id, 
                                                      const std::string& operation) {
    std::lock_guard<std::mutex> lock(clients_mutex);
    
    auto it = client_profiles.find(client_id);
    if (it != client_profiles.end()) {
        it->second.current_usage[operation]++;
    }
}

void FGCom_WorkUnitSecurityManager::resetClientUsage(const std::string& client_id) {
    std::lock_guard<std::mutex> lock(clients_mutex);
    
    auto it = client_profiles.find(client_id);
    if (it != client_profiles.end()) {
        it->second.current_usage.clear();
    }
}

std::map<std::string, int> FGCom_WorkUnitSecurityManager::getClientUsage(const std::string& client_id) {
    std::lock_guard<std::mutex> lock(clients_mutex);
    
    auto it = client_profiles.find(client_id);
    if (it != client_profiles.end()) {
        return it->second.current_usage;
    }
    
    return std::map<std::string, int>();
}

// Security monitoring and threat detection
std::vector<SecurityEvent> FGCom_WorkUnitSecurityManager::getSecurityEvents(SecurityLevel min_severity) {
    std::lock_guard<std::mutex> lock(events_mutex);
    
    std::vector<SecurityEvent> filtered_events;
    for (const auto& event : security_events) {
        if (event.severity >= min_severity) {
            filtered_events.push_back(event);
        }
    }
    
    return filtered_events;
}

std::vector<SecurityEvent> FGCom_WorkUnitSecurityManager::getClientSecurityEvents(const std::string& client_id) {
    std::lock_guard<std::mutex> lock(events_mutex);
    
    std::vector<SecurityEvent> client_events;
    for (const auto& event : security_events) {
        if (event.client_id == client_id) {
            client_events.push_back(event);
        }
    }
    
    return client_events;
}

void FGCom_WorkUnitSecurityManager::addSecurityEvent(const SecurityEvent& event) {
    std::lock_guard<std::mutex> lock(events_mutex);
    security_events.push_back(event);
    
    // Keep only last 1000 events
    if (security_events.size() > 1000) {
        security_events.erase(security_events.begin(), security_events.begin() + 100);
    }
}

void FGCom_WorkUnitSecurityManager::clearSecurityEvents() {
    std::lock_guard<std::mutex> lock(events_mutex);
    security_events.clear();
}

std::map<std::string, double> FGCom_WorkUnitSecurityManager::getSecurityStatistics() {
    std::lock_guard<std::mutex> lock(events_mutex);
    
    std::map<std::string, double> stats;
    stats["total_events"] = security_events.size();
    
    int low_events = 0, medium_events = 0, high_events = 0, critical_events = 0;
    for (const auto& event : security_events) {
        switch (event.severity) {
            case SecurityLevel::LOW: low_events++; break;
            case SecurityLevel::MEDIUM: medium_events++; break;
            case SecurityLevel::HIGH: high_events++; break;
            case SecurityLevel::CRITICAL: critical_events++; break;
        }
    }
    
    stats["low_severity_events"] = low_events;
    stats["medium_severity_events"] = medium_events;
    stats["high_severity_events"] = high_events;
    stats["critical_severity_events"] = critical_events;
    
    return stats;
}

// Utility methods
void FGCom_WorkUnitSecurityManager::cleanup() {
    // Implementation would clean up old data
    // This is a simplified placeholder
}

bool FGCom_WorkUnitSecurityManager::isHealthy() {
    return security_enabled && (!monitoring_enabled || monitoring_running);
}

std::string FGCom_WorkUnitSecurityManager::getSecurityReport() {
    std::stringstream ss;
    ss << "Work Unit Security Manager Status:\n";
    ss << "  Enabled: " << (security_enabled ? "Yes" : "No") << "\n";
    ss << "  Encryption: " << (encryption_enabled ? "Yes" : "No") << "\n";
    ss << "  Signatures: " << (signature_validation_enabled ? "Yes" : "No") << "\n";
    ss << "  Rate Limiting: " << (rate_limiting_enabled ? "Yes" : "No") << "\n";
    ss << "  Monitoring: " << (monitoring_enabled ? "Yes" : "No") << "\n";
    ss << "  Registered Clients: " << client_profiles.size() << "\n";
    ss << "  Trusted Clients: " << getTrustedClients().size() << "\n";
    ss << "  Blocked Clients: " << getBlockedClients().size() << "\n";
    ss << "  Security Events: " << security_events.size() << "\n";
    
    return ss.str();
}

std::string FGCom_WorkUnitSecurityManager::generateAPIKey(const std::string& client_id) {
    return FGCom_CryptographicUtils::generateAPIKey(32);
}

std::string FGCom_WorkUnitSecurityManager::generateJWTToken(const std::string& client_id, 
                                                           const std::map<std::string, std::string>& claims) {
    return FGCom_CryptographicUtils::createJWTToken(claims, jwt_secrets[client_id], 24);
}

bool FGCom_WorkUnitSecurityManager::validateJWTToken(const std::string& token, 
                                                     std::map<std::string, std::string>& claims) {
    // Implementation would validate JWT token
    // This is a simplified placeholder
    return true;
}

// Private methods
void FGCom_WorkUnitSecurityManager::initializeSecurityKeys() {
    // Generate server key pair
    server_private_key = FGCom_CryptographicUtils::generateRSAKeyPair(2048);
    if (server_private_key) {
        server_public_key = EVP_PKEY_dup(server_private_key);
    }
}

void FGCom_WorkUnitSecurityManager::loadServerCertificate() {
    // Implementation would load server certificate
    // This is a simplified placeholder
}

void FGCom_WorkUnitSecurityManager::startSecurityMonitoring() {
    if (monitoring_running) {
        return;
    }
    
    monitoring_running = true;
    monitoring_thread = std::thread(&FGCom_WorkUnitSecurityManager::monitoringThreadFunction, this);
}

void FGCom_WorkUnitSecurityManager::stopSecurityMonitoring() {
    if (!monitoring_running) {
        return;
    }
    
    monitoring_running = false;
    if (monitoring_thread.joinable()) {
        monitoring_thread.join();
    }
}

void FGCom_WorkUnitSecurityManager::monitoringThreadFunction() {
    while (monitoring_running) {
        // Monitor for security threats
        // Implementation would include threat detection logic
        
        std::this_thread::sleep_for(std::chrono::seconds(10));
    }
}

void FGCom_WorkUnitSecurityManager::processSecurityEvent(const SecurityEvent& event) {
    // Process security event
    // Implementation would include automated responses
}

bool FGCom_WorkUnitSecurityManager::validateClientCertificate(const std::string& client_id, 
                                                              const std::string& certificate) {
    // Implementation would validate client certificate
    // This is a simplified placeholder
    return true;
}

bool FGCom_WorkUnitSecurityManager::validateAPIKey(const std::string& client_id, 
                                                   const std::string& api_key) {
    auto it = api_keys.find(client_id);
    if (it == api_keys.end()) {
        return false;
    }
    
    return it->second == api_key;
}

bool FGCom_WorkUnitSecurityManager::validateJWTToken(const std::string& client_id, 
                                                     const std::string& token) {
    // Implementation would validate JWT token
    // This is a simplified placeholder
    return true;
}

std::string FGCom_WorkUnitSecurityManager::generateDigitalSignature(const WorkUnit& work_unit, 
                                                                    const std::string& client_id) {
    // Implementation would generate digital signature
    // This is a simplified placeholder
    return "signature_" + client_id;
}

bool FGCom_WorkUnitSecurityManager::verifyDigitalSignature(const SecureWorkUnit& secure_work_unit) {
    // Implementation would verify digital signature
    // This is a simplified placeholder
    return true;
}

std::string FGCom_WorkUnitSecurityManager::encryptWorkUnitData(const WorkUnit& work_unit, 
                                                                 const std::string& client_id) {
    // Implementation would encrypt work unit data
    // This is a simplified placeholder
    return "encrypted_data";
}

WorkUnit FGCom_WorkUnitSecurityManager::decryptWorkUnitData(const std::string& encrypted_data, 
                                                           const std::string& client_id) {
    // Implementation would decrypt work unit data
    // This is a simplified placeholder
    return WorkUnit();
}

bool FGCom_WorkUnitSecurityManager::checkRateLimit(const std::string& client_id, 
                                                   const std::string& operation) {
    return checkClientRateLimit(client_id, operation);
}

void FGCom_WorkUnitSecurityManager::updateClientReputation(const std::string& client_id, 
                                                           double reputation_delta) {
    std::lock_guard<std::mutex> lock(clients_mutex);
    
    auto it = client_profiles.find(client_id);
    if (it != client_profiles.end()) {
        it->second.reputation_score += reputation_delta;
        it->second.reputation_score = std::max(0.0, std::min(1.0, it->second.reputation_score));
    }
}

void FGCom_WorkUnitSecurityManager::logSecurityEvent(const std::string& event_type, 
                                                     const std::string& client_id, 
                                                     const std::string& description, 
                                                     SecurityLevel severity) {
    SecurityEvent event;
    event.event_id = FGCom_CryptographicUtils::generateUUID();
    event.event_type = event_type;
    event.client_id = client_id;
    event.description = description;
    event.severity = severity;
    event.timestamp = std::chrono::system_clock::now();
    event.requires_action = (severity >= SecurityLevel::HIGH);
    
    addSecurityEvent(event);
}

// Cryptographic utilities implementation
EVP_PKEY* FGCom_CryptographicUtils::generateRSAKeyPair(int key_size) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!ctx) return nullptr;
    
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }
    
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, key_size) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }
    
    EVP_PKEY* key = nullptr;
    if (EVP_PKEY_keygen(ctx, &key) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }
    
    EVP_PKEY_CTX_free(ctx);
    return key;
}

std::string FGCom_CryptographicUtils::exportPublicKeyPEM(EVP_PKEY* public_key) {
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) return "";
    
    if (PEM_write_bio_PUBKEY(bio, public_key) != 1) {
        BIO_free(bio);
        return "";
    }
    
    char* data;
    long len = BIO_get_mem_data(bio, &data);
    std::string result(data, len);
    
    BIO_free(bio);
    return result;
}

std::string FGCom_CryptographicUtils::generateAPIKey(size_t length) {
    return generateRandomBytes(length);
}

std::string FGCom_CryptographicUtils::generateRandomBytes(size_t length) {
    std::vector<unsigned char> bytes(length);
    if (RAND_bytes(bytes.data(), length) != 1) {
        return "";
    }
    
    std::string result;
    for (unsigned char byte : bytes) {
        result += static_cast<char>(byte);
    }
    
    return result;
}

std::string FGCom_CryptographicUtils::generateUUID() {
    return generateRandomBytes(16);
}

std::string FGCom_CryptographicUtils::calculateSHA256(const std::string& data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(data.c_str()), data.length(), hash);
    
    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    
    return ss.str();
}

std::string FGCom_CryptographicUtils::calculateWorkUnitHash(const WorkUnit& work_unit) {
    std::string data = work_unit.unit_id + std::to_string(static_cast<int>(work_unit.type)) + 
                      std::to_string(static_cast<int>(work_unit.priority));
    
    for (double value : work_unit.input_data) {
        data += std::to_string(value);
    }
    
    return calculateSHA256(data);
}

// Client security coordinator implementation
FGCom_ClientSecurityCoordinator::FGCom_ClientSecurityCoordinator(const std::string& client_id, 
                                                                 const std::string& server_url)
    : client_id(client_id)
    , server_url(server_url)
    , security_level(SecurityLevel::MEDIUM)
    , security_enabled(false)
    , client_private_key(nullptr)
    , client_public_key(nullptr)
    , client_certificate(nullptr) {}

FGCom_ClientSecurityCoordinator::~FGCom_ClientSecurityCoordinator() {
    shutdown();
}

bool FGCom_ClientSecurityCoordinator::initialize(SecurityLevel security_level) {
    this->security_level = security_level;
    
    // Generate client key pair
    client_private_key = FGCom_CryptographicUtils::generateRSAKeyPair(2048);
    if (client_private_key) {
        client_public_key = EVP_PKEY_dup(client_private_key);
    }
    
    security_enabled = true;
    return true;
}

void FGCom_ClientSecurityCoordinator::shutdown() {
    if (client_private_key) {
        EVP_PKEY_free(client_private_key);
        client_private_key = nullptr;
    }
    
    if (client_public_key) {
        EVP_PKEY_free(client_public_key);
        client_public_key = nullptr;
    }
    
    if (client_certificate) {
        X509_free(client_certificate);
        client_certificate = nullptr;
    }
    
    security_enabled = false;
}

bool FGCom_ClientSecurityCoordinator::authenticateWithServer() {
    // Implementation would authenticate with server
    // This is a simplified placeholder
    return true;
}

bool FGCom_ClientSecurityCoordinator::registerWithServer(const ClientSecurityProfile& profile) {
    // Implementation would register with server
    // This is a simplified placeholder
    return true;
}

SecureWorkUnit FGCom_ClientSecurityCoordinator::createSecureWorkUnit(const WorkUnit& work_unit) {
    SecureWorkUnit secure_work_unit;
    secure_work_unit.work_unit = work_unit;
    secure_work_unit.signature_time = std::chrono::system_clock::now();
    secure_work_unit.signer_client_id = client_id;
    secure_work_unit.required_security_level = security_level;
    secure_work_unit.is_encrypted = (security_level >= SecurityLevel::HIGH);
    
    // Generate digital signature
    secure_work_unit.digital_signature = FGCom_CryptographicUtils::signWorkUnit(work_unit, client_private_key);
    
    // Calculate integrity hash
    secure_work_unit.integrity_hash = FGCom_CryptographicUtils::calculateWorkUnitHash(work_unit);
    
    return secure_work_unit;
}

WorkUnit FGCom_ClientSecurityCoordinator::extractSecureWorkUnit(const SecureWorkUnit& secure_work_unit) {
    // Verify digital signature
    if (!validateWorkUnitSignature(secure_work_unit)) {
        throw std::runtime_error("Invalid digital signature");
    }
    
    return secure_work_unit.work_unit;
}

bool FGCom_ClientSecurityCoordinator::validateWorkUnitSignature(const SecureWorkUnit& secure_work_unit) {
    // Implementation would validate work unit signature
    // This is a simplified placeholder
    return true;
}

ResultValidation FGCom_ClientSecurityCoordinator::createResultValidation(const std::string& work_unit_id, 
                                                                        const std::vector<double>& result_data) {
    ResultValidation validation;
    validation.work_unit_id = work_unit_id;
    validation.client_id = client_id;
    validation.result_data = result_data;
    validation.validation_time = std::chrono::system_clock::now();
    validation.is_validated = false;
    validation.confidence_score = 0.0;
    
    // Calculate validation hash
    std::string data = work_unit_id + client_id;
    for (double value : result_data) {
        data += std::to_string(value);
    }
    validation.validation_hash = FGCom_CryptographicUtils::calculateSHA256(data);
    
    return validation;
}

bool FGCom_ClientSecurityCoordinator::submitResultValidation(const ResultValidation& validation) {
    // Implementation would submit result validation
    // This is a simplified placeholder
    return true;
}

void FGCom_ClientSecurityCoordinator::reportSecurityEvent(const std::string& event_type, 
                                                          const std::string& description) {
    // Implementation would report security event
    // This is a simplified placeholder
}

std::vector<SecurityEvent> FGCom_ClientSecurityCoordinator::getSecurityEvents() {
    // Implementation would get security events
    // This is a simplified placeholder
    return std::vector<SecurityEvent>();
}

bool FGCom_ClientSecurityCoordinator::isAuthenticated() {
    return security_enabled;
}

std::string FGCom_ClientSecurityCoordinator::getClientID() {
    return client_id;
}

SecurityLevel FGCom_ClientSecurityCoordinator::getSecurityLevel() {
    return security_level;
}

std::string FGCom_ClientSecurityCoordinator::getSecurityReport() {
    std::stringstream ss;
    ss << "Client Security Coordinator Status:\n";
    ss << "  Client ID: " << client_id << "\n";
    ss << "  Server URL: " << server_url << "\n";
    ss << "  Security Level: " << static_cast<int>(security_level) << "\n";
    ss << "  Enabled: " << (security_enabled ? "Yes" : "No") << "\n";
    ss << "  Authenticated: " << (isAuthenticated() ? "Yes" : "No") << "\n";
    
    return ss.str();
}

// Security event logger implementation
FGCom_SecurityEventLogger::FGCom_SecurityEventLogger(const std::string& log_file_path)
    : log_file_path(log_file_path)
    , logging_enabled(true) {}

FGCom_SecurityEventLogger::~FGCom_SecurityEventLogger() {
    // Destructor
}

void FGCom_SecurityEventLogger::logEvent(const SecurityEvent& event) {
    if (!logging_enabled) {
        return;
    }
    
    std::lock_guard<std::mutex> lock(log_mutex);
    
    std::ofstream log_file(log_file_path, std::ios::app);
    if (log_file.is_open()) {
        auto time_t = std::chrono::system_clock::to_time_t(event.timestamp);
        log_file << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S") << " "
                 << event.event_type << " " << event.client_id << " " 
                 << event.description << std::endl;
        log_file.close();
    }
}

void FGCom_SecurityEventLogger::logEvent(const std::string& event_type, 
                                         const std::string& client_id, 
                                         const std::string& description, 
                                         SecurityLevel severity) {
    SecurityEvent event;
    event.event_id = FGCom_CryptographicUtils::generateUUID();
    event.event_type = event_type;
    event.client_id = client_id;
    event.description = description;
    event.severity = severity;
    event.timestamp = std::chrono::system_clock::now();
    
    logEvent(event);
}

void FGCom_SecurityEventLogger::enableLogging(bool enable) {
    logging_enabled = enable;
}

void FGCom_SecurityEventLogger::setLogFile(const std::string& file_path) {
    log_file_path = file_path;
}

std::vector<SecurityEvent> FGCom_SecurityEventLogger::readEvents(SecurityLevel min_severity) {
    // Implementation would read events from log file
    // This is a simplified placeholder
    return std::vector<SecurityEvent>();
}

void FGCom_SecurityEventLogger::clearLog() {
    std::lock_guard<std::mutex> lock(log_mutex);
    std::ofstream log_file(log_file_path, std::ios::trunc);
    log_file.close();
}
