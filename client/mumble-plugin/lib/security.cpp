#include "security.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <regex>
#include <cctype>
#include <cstring>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <uuid/uuid.h>

namespace Security {

// InputSanitizer Implementation
std::string InputSanitizer::sanitizeString(const std::string& input, size_t max_length) {
    std::string sanitized = input;
    
    // Remove control characters
    sanitized.erase(std::remove_if(sanitized.begin(), sanitized.end(),
        [](char c) { return c < 32 || c == 127; }), sanitized.end());
    
    // Limit length
    if (sanitized.length() > max_length) {
        sanitized = sanitized.substr(0, max_length);
    }
    
    // Trim whitespace
    sanitized.erase(0, sanitized.find_first_not_of(" \t\n\r"));
    sanitized.erase(sanitized.find_last_not_of(" \t\n\r") + 1);
    
    return sanitized;
}

std::string InputSanitizer::sanitizeFilename(const std::string& filename) {
    std::string sanitized = filename;
    
    // Remove path traversal attempts
    while (sanitized.find("../") != std::string::npos) {
        sanitized.replace(sanitized.find("../"), 3, "");
    }
    while (sanitized.find("..\\") != std::string::npos) {
        sanitized.replace(sanitized.find("..\\"), 3, "");
    }
    
    // Remove dangerous characters
    std::string dangerous_chars = "<>:\"|?*\\/";
    for (char c : dangerous_chars) {
        sanitized.erase(std::remove(sanitized.begin(), sanitized.end(), c), sanitized.end());
    }
    
    // Remove control characters
    sanitized.erase(std::remove_if(sanitized.begin(), sanitized.end(),
        [](char c) { return c < 32 || c == 127; }), sanitized.end());
    
    return sanitized;
}

std::string InputSanitizer::sanitizePath(const std::string& path) {
    std::string sanitized = path;
    
    // Remove path traversal attempts
    while (sanitized.find("../") != std::string::npos) {
        sanitized.replace(sanitized.find("../"), 3, "");
    }
    while (sanitized.find("..\\") != std::string::npos) {
        sanitized.replace(sanitized.find("..\\"), 3, "");
    }
    
    // Remove null bytes
    sanitized.erase(std::remove(sanitized.begin(), sanitized.end(), '\0'), sanitized.end());
    
    return sanitized;
}

std::string InputSanitizer::sanitizeJSON(const std::string& json) {
    std::string sanitized = json;
    
    // Remove control characters except newlines and tabs
    sanitized.erase(std::remove_if(sanitized.begin(), sanitized.end(),
        [](char c) { return c < 32 && c != '\n' && c != '\t' && c != '\r'; }), sanitized.end());
    
    return sanitized;
}

std::string InputSanitizer::sanitizeSQL(const std::string& sql) {
    std::string sanitized = sql;
    
    // Remove SQL injection patterns
    std::vector<std::string> dangerous_patterns = {
        "union", "select", "insert", "update", "delete", "drop", "create", "alter",
        "exec", "execute", "script", "javascript", "vbscript"
    };
    
    std::string lower_sql = sql;
    std::transform(lower_sql.begin(), lower_sql.end(), lower_sql.begin(), ::tolower);
    
    for (const auto& pattern : dangerous_patterns) {
        if (lower_sql.find(pattern) != std::string::npos) {
            return ""; // Reject potentially dangerous input
        }
    }
    
    return sanitized;
}

std::string InputSanitizer::sanitizeHTML(const std::string& html) {
    std::string sanitized = html;
    
    // Remove HTML tags
    std::regex html_tag_regex("<[^>]*>");
    sanitized = std::regex_replace(sanitized, html_tag_regex, "");
    
    // Decode HTML entities
    std::map<std::string, std::string> html_entities = {
        {"&lt;", "<"}, {"&gt;", ">"}, {"&amp;", "&"}, {"&quot;", "\""}, {"&#39;", "'"}
    };
    
    for (const auto& entity : html_entities) {
        size_t pos = 0;
        while ((pos = sanitized.find(entity.first, pos)) != std::string::npos) {
            sanitized.replace(pos, entity.first.length(), entity.second);
            pos += entity.second.length();
        }
    }
    
    return sanitized;
}

std::string InputSanitizer::sanitizeXML(const std::string& xml) {
    std::string sanitized = xml;
    
    // Remove XML tags
    std::regex xml_tag_regex("<[^>]*>");
    sanitized = std::regex_replace(sanitized, xml_tag_regex, "");
    
    // Remove XML declarations
    std::regex xml_decl_regex("<\\?xml[^>]*\\?>");
    sanitized = std::regex_replace(sanitized, xml_decl_regex, "");
    
    return sanitized;
}

std::string InputSanitizer::removeControlCharacters(const std::string& input) {
    std::string result = input;
    result.erase(std::remove_if(result.begin(), result.end(),
        [](char c) { return c < 32 || c == 127; }), result.end());
    return result;
}

std::string InputSanitizer::removeUnicodeCharacters(const std::string& input) {
    std::string result;
    for (char c : input) {
        if (c >= 0 && c <= 127) { // ASCII only
            result += c;
        }
    }
    return result;
}

std::string InputSanitizer::normalizeWhitespace(const std::string& input) {
    std::string result = input;
    
    // Replace multiple whitespace with single space
    std::regex whitespace_regex("\\s+");
    result = std::regex_replace(result, whitespace_regex, " ");
    
    // Trim leading and trailing whitespace
    result.erase(0, result.find_first_not_of(" \t\n\r"));
    result.erase(result.find_last_not_of(" \t\n\r") + 1);
    
    return result;
}

bool InputSanitizer::isValidASCII(const std::string& input) {
    return std::all_of(input.begin(), input.end(), [](char c) { return c >= 0 && c <= 127; });
}

bool InputSanitizer::isValidUTF8(const std::string& input) {
    // Simplified UTF-8 validation
    for (size_t i = 0; i < input.length(); ++i) {
        unsigned char c = static_cast<unsigned char>(input[i]);
        if (c < 128) {
            // ASCII character
            continue;
        } else if ((c & 0xE0) == 0xC0) {
            // 2-byte character
            if (i + 1 >= input.length() || (input[i + 1] & 0xC0) != 0x80) {
                return false;
            }
            i += 1;
        } else if ((c & 0xF0) == 0xE0) {
            // 3-byte character
            if (i + 2 >= input.length() || (input[i + 1] & 0xC0) != 0x80 || (input[i + 2] & 0xC0) != 0x80) {
                return false;
            }
            i += 2;
        } else if ((c & 0xF8) == 0xF0) {
            // 4-byte character
            if (i + 3 >= input.length() || (input[i + 1] & 0xC0) != 0x80 || 
                (input[i + 2] & 0xC0) != 0x80 || (input[i + 3] & 0xC0) != 0x80) {
                return false;
            }
            i += 3;
        } else {
            return false;
        }
    }
    return true;
}

bool InputSanitizer::isValidBase64(const std::string& input) {
    if (input.empty() || input.length() % 4 != 0) {
        return false;
    }
    
    std::string valid_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
    return std::all_of(input.begin(), input.end(), [&valid_chars](char c) {
        return valid_chars.find(c) != std::string::npos;
    });
}

bool InputSanitizer::isValidHex(const std::string& input) {
    if (input.empty() || input.length() % 2 != 0) {
        return false;
    }
    
    std::string valid_chars = "0123456789ABCDEFabcdef";
    return std::all_of(input.begin(), input.end(), [&valid_chars](char c) {
        return valid_chars.find(c) != std::string::npos;
    });
}

// AuthenticationManager Implementation
AuthenticationManager::AuthenticationManager() : enabled_(true) {
}

AuthenticationManager::~AuthenticationManager() {
    clearAllSessions();
}

bool AuthenticationManager::addUser(const std::string& username, const std::string& password) {
    if (username.empty() || password.empty()) {
        return false;
    }
    
    std::lock_guard<std::mutex> lock(auth_mutex_);
    
    // Hash the password
    std::string salt = Encryption::generateSalt();
    std::string hashed_password = Encryption::hashPassword(password, salt);
    
    user_credentials_[username] = hashed_password + ":" + salt;
    return true;
}

bool AuthenticationManager::removeUser(const std::string& username) {
    std::lock_guard<std::mutex> lock(auth_mutex_);
    
    auto it = user_credentials_.find(username);
    if (it != user_credentials_.end()) {
        user_credentials_.erase(it);
        return true;
    }
    
    return false;
}

bool AuthenticationManager::changePassword(const std::string& username, const std::string& old_password, const std::string& new_password) {
    if (!authenticate(username, old_password)) {
        return false;
    }
    
    return addUser(username, new_password);
}

bool AuthenticationManager::authenticate(const std::string& username, const std::string& password) {
    if (!enabled_.load()) {
        return true; // Authentication disabled
    }
    
    std::lock_guard<std::mutex> lock(auth_mutex_);
    
    auto it = user_credentials_.find(username);
    if (it == user_credentials_.end()) {
        return false;
    }
    
    // Parse stored password and salt
    std::string stored_data = it->second;
    size_t colon_pos = stored_data.find(':');
    if (colon_pos == std::string::npos) {
        return false;
    }
    
    std::string stored_hash = stored_data.substr(0, colon_pos);
    std::string salt = stored_data.substr(colon_pos + 1);
    
    // Hash the provided password with the stored salt
    std::string hashed_password = Encryption::hashPassword(password, salt);
    
    return hashed_password == stored_hash;
}

std::string AuthenticationManager::generateSessionToken(const std::string& username) {
    std::string token = Encryption::generateUUID();
    
    std::lock_guard<std::mutex> lock(auth_mutex_);
    session_tokens_[token] = std::chrono::system_clock::now();
    
    return token;
}

bool AuthenticationManager::validateSessionToken(const std::string& token) {
    if (!enabled_.load()) {
        return true; // Authentication disabled
    }
    
    std::lock_guard<std::mutex> lock(auth_mutex_);
    
    auto it = session_tokens_.find(token);
    if (it == session_tokens_.end()) {
        return false;
    }
    
    // Check if session is expired (24 hours)
    auto now = std::chrono::system_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::hours>(now - it->second);
    
    if (duration.count() > 24) {
        session_tokens_.erase(it);
        return false;
    }
    
    return true;
}

void AuthenticationManager::invalidateSessionToken(const std::string& token) {
    std::lock_guard<std::mutex> lock(auth_mutex_);
    session_tokens_.erase(token);
}

void AuthenticationManager::clearExpiredSessions() {
    std::lock_guard<std::mutex> lock(auth_mutex_);
    
    auto now = std::chrono::system_clock::now();
    auto it = session_tokens_.begin();
    
    while (it != session_tokens_.end()) {
        auto duration = std::chrono::duration_cast<std::chrono::hours>(now - it->second);
        if (duration.count() > 24) {
            it = session_tokens_.erase(it);
        } else {
            ++it;
        }
    }
}

void AuthenticationManager::clearAllSessions() {
    std::lock_guard<std::mutex> lock(auth_mutex_);
    session_tokens_.clear();
}

size_t AuthenticationManager::getActiveSessionCount() const {
    std::lock_guard<std::mutex> lock(auth_mutex_);
    return session_tokens_.size();
}

// RateLimiter Implementation
RateLimiter::RateLimiter(int per_minute, int per_hour, int per_day)
    : max_requests_per_minute_(per_minute), max_requests_per_hour_(per_hour), max_requests_per_day_(per_day) {
}

RateLimiter::~RateLimiter() {
    clearAllRateLimits();
}

bool RateLimiter::isAllowed(const std::string& client_id) {
    return isAllowed(client_id, max_requests_per_minute_);
}

bool RateLimiter::isAllowed(const std::string& client_id, int custom_limit) {
    std::lock_guard<std::mutex> lock(rate_limit_mutex_);
    
    auto now = std::chrono::system_clock::now();
    auto& entry = rate_limits_[client_id];
    
    // Reset counters if window has passed
    auto duration = std::chrono::duration_cast<std::chrono::minutes>(now - entry.window_start);
    if (duration.count() >= 1) {
        entry.request_count = 0;
        entry.window_start = now;
    }
    
    return entry.request_count < custom_limit;
}

void RateLimiter::recordRequest(const std::string& client_id) {
    std::lock_guard<std::mutex> lock(rate_limit_mutex_);
    
    auto now = std::chrono::system_clock::now();
    auto& entry = rate_limits_[client_id];
    
    entry.last_request = now;
    entry.request_count++;
    
    if (entry.window_start == std::chrono::system_clock::time_point{}) {
        entry.window_start = now;
    }
}

void RateLimiter::setLimits(int per_minute, int per_hour, int per_day) {
    std::lock_guard<std::mutex> lock(rate_limit_mutex_);
    max_requests_per_minute_ = per_minute;
    max_requests_per_hour_ = per_hour;
    max_requests_per_day_ = per_day;
}

void RateLimiter::clearRateLimit(const std::string& client_id) {
    std::lock_guard<std::mutex> lock(rate_limit_mutex_);
    rate_limits_.erase(client_id);
}

void RateLimiter::clearAllRateLimits() {
    std::lock_guard<std::mutex> lock(rate_limit_mutex_);
    rate_limits_.clear();
}

int RateLimiter::getRequestCount(const std::string& client_id) const {
    std::lock_guard<std::mutex> lock(rate_limit_mutex_);
    
    auto it = rate_limits_.find(client_id);
    if (it != rate_limits_.end()) {
        return it->second.request_count;
    }
    
    return 0;
}

std::chrono::system_clock::time_point RateLimiter::getLastRequestTime(const std::string& client_id) const {
    std::lock_guard<std::mutex> lock(rate_limit_mutex_);
    
    auto it = rate_limits_.find(client_id);
    if (it != rate_limits_.end()) {
        return it->second.last_request;
    }
    
    return std::chrono::system_clock::time_point{};
}

// Encryption Implementation
std::string Encryption::hashSHA256(const std::string& input) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, input.c_str(), input.length());
    SHA256_Final(hash, &sha256);
    
    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    
    return ss.str();
}

std::string Encryption::hashSHA1(const std::string& input) {
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1(reinterpret_cast<const unsigned char*>(input.c_str()), input.length(), hash);
    
    std::stringstream ss;
    for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    
    return ss.str();
}

std::string Encryption::hashMD5(const std::string& input) {
    unsigned char hash[MD5_DIGEST_LENGTH];
    MD5(reinterpret_cast<const unsigned char*>(input.c_str()), input.length(), hash);
    
    std::stringstream ss;
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    
    return ss.str();
}

std::string Encryption::hashPassword(const std::string& password, const std::string& salt) {
    return hashSHA256(password + salt);
}

std::string Encryption::generateSalt(size_t length) {
    std::string salt;
    salt.reserve(length);
    
    for (size_t i = 0; i < length; ++i) {
        salt += static_cast<char>(rand() % 256);
    }
    
    return salt;
}

std::string Encryption::generateRandomString(size_t length) {
    const std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    std::string result;
    result.reserve(length);
    
    for (size_t i = 0; i < length; ++i) {
        result += chars[rand() % chars.length()];
    }
    
    return result;
}

std::string Encryption::encodeBase64(const std::string& input) {
    const std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string result;
    int val = 0, valb = -6;
    
    for (unsigned char c : input) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            result.push_back(chars[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    
    if (valb > -6) {
        result.push_back(chars[((val << 8) >> (valb + 8)) & 0x3F]);
    }
    
    while (result.size() % 4) {
        result.push_back('=');
    }
    
    return result;
}

std::string Encryption::decodeBase64(const std::string& input) {
    const std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string result;
    int val = 0, valb = -8;
    
    for (char c : input) {
        if (chars.find(c) == std::string::npos) break;
        val = (val << 6) + chars.find(c);
        valb += 6;
        if (valb >= 0) {
            result.push_back(char((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    
    return result;
}

std::string Encryption::encryptXOR(const std::string& input, const std::string& key) {
    std::string result = input;
    
    for (size_t i = 0; i < result.length(); ++i) {
        result[i] ^= key[i % key.length()];
    }
    
    return result;
}

std::string Encryption::decryptXOR(const std::string& input, const std::string& key) {
    return encryptXOR(input, key); // XOR is symmetric
}

std::string Encryption::generateKey(size_t length) {
    return generateRandomString(length);
}

std::string Encryption::generateUUID() {
    uuid_t uuid;
    uuid_generate(uuid);
    
    char uuid_str[37];
    uuid_unparse(uuid, uuid_str);
    
    return std::string(uuid_str);
}

// Global security manager instance
std::unique_ptr<SecurityManager> g_security_manager = nullptr;

} // namespace Security



