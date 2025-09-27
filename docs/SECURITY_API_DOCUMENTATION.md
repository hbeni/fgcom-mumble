# Security API Documentation

## Overview

The Security API provides comprehensive security features for the distributed work unit system, including authentication, authorization, encryption, digital signatures, and threat detection.

## Table of Contents

1. [Authentication Methods](#authentication-methods)
2. [Client Registration](#client-registration)
3. [Security Levels](#security-levels)
4. [API Endpoints](#api-endpoints)
5. [Usage Examples](#usage-examples)
6. [Security Best Practices](#security-best-practices)
7. [Threat Detection](#threat-detection)
8. [Troubleshooting](#troubleshooting)

## Authentication Methods

### 1. API Key Authentication

**Description:** Simple API key-based authentication for basic security requirements.

**Security Level:** LOW to MEDIUM

**Usage:**
```json
{
  "client_id": "client_001",
  "auth_data": "ak_1234567890abcdef",
  "auth_method": "api_key"
}
```

**Advantages:**
- Simple to implement
- Low overhead
- Easy to manage

**Disadvantages:**
- Single point of failure
- No certificate validation
- Limited security features

### 2. Client Certificate Authentication

**Description:** X.509 certificate-based authentication for high security requirements.

**Security Level:** HIGH to CRITICAL

**Usage:**
```json
{
  "client_id": "client_001",
  "auth_data": "-----BEGIN CERTIFICATE-----\nMIIDXTCCAkWgAwIBAgIJAKoK/Ovj8u...",
  "auth_method": "client_cert"
}
```

**Advantages:**
- Strong authentication
- Certificate validation
- Non-repudiation

**Disadvantages:**
- Complex setup
- Certificate management
- Higher overhead

### 3. JWT Token Authentication

**Description:** JSON Web Token-based authentication with claims validation.

**Security Level:** MEDIUM to HIGH

**Usage:**
```json
{
  "client_id": "client_001",
  "auth_data": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "auth_method": "jwt_token"
}
```

**Advantages:**
- Stateless authentication
- Claims-based authorization
- Industry standard

**Disadvantages:**
- Token management
- Clock synchronization
- Key rotation complexity

### 4. OAuth2 Authentication

**Description:** OAuth2 flow for enterprise integration.

**Security Level:** HIGH

**Usage:**
```json
{
  "client_id": "client_001",
  "auth_data": "oauth2_access_token",
  "auth_method": "oauth2"
}
```

**Advantages:**
- Industry standard
- Enterprise integration
- Delegated authorization

**Disadvantages:**
- Complex implementation
- Multiple endpoints
- Token refresh handling

## Client Registration

### Registration Process

1. **Submit Registration Request**
2. **Server Validates Client**
3. **Generate Security Credentials**
4. **Return Registration Response**

### Registration Request

**Endpoint:** `POST /api/v1/security/register`

**Request Body:**
```json
{
  "client_id": "client_001",
  "auth_method": "api_key",
  "security_level": "medium",
  "capabilities": {
    "max_memory_mb": 2048,
    "supports_gpu": true,
    "supports_double_precision": true,
    "network_bandwidth_mbps": 100.0,
    "processing_latency_ms": 50.0
  },
  "supported_work_unit_types": [
    "PROPAGATION_GRID",
    "ANTENNA_PATTERN",
    "FREQUENCY_OFFSET",
    "AUDIO_PROCESSING"
  ]
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "registered": true,
    "client_id": "client_001",
    "api_key": "ak_1234567890abcdef",
    "security_level": "medium",
    "auth_method": "api_key",
    "rate_limits": {
      "work_unit_requests": 10,
      "result_submissions": 20,
      "heartbeat": 60
    }
  }
}
```

### Registration with Client Certificate

**Request Body:**
```json
{
  "client_id": "client_001",
  "auth_method": "client_cert",
  "security_level": "high",
  "certificate": "-----BEGIN CERTIFICATE-----\nMIIDXTCCAkWgAwIBAgIJAKoK/Ovj8u...",
  "public_key": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A...",
  "capabilities": {
    "max_memory_mb": 4096,
    "supports_gpu": true,
    "supports_double_precision": true,
    "network_bandwidth_mbps": 1000.0,
    "processing_latency_ms": 25.0
  }
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "registered": true,
    "client_id": "client_001",
    "certificate_fingerprint": "sha256:abc123...",
    "security_level": "high",
    "auth_method": "client_cert",
    "rate_limits": {
      "work_unit_requests": 20,
      "result_submissions": 50,
      "heartbeat": 30
    }
  }
}
```

## Security Levels

### LOW Security Level

**Use Case:** Development and testing environments

**Features:**
- Basic API key authentication
- Minimal rate limiting
- Basic logging

**Configuration:**
```json
{
  "security_level": "low",
  "encryption_enabled": false,
  "signature_validation_enabled": false,
  "rate_limiting_enabled": true,
  "monitoring_enabled": false
}
```

### MEDIUM Security Level

**Use Case:** Production environments with moderate security requirements

**Features:**
- API key or JWT authentication
- Digital signatures for work units
- Rate limiting and quotas
- Security monitoring

**Configuration:**
```json
{
  "security_level": "medium",
  "encryption_enabled": false,
  "signature_validation_enabled": true,
  "rate_limiting_enabled": true,
  "monitoring_enabled": true
}
```

### HIGH Security Level

**Use Case:** Production environments with high security requirements

**Features:**
- Client certificate authentication
- End-to-end encryption
- Digital signatures
- Advanced rate limiting
- Comprehensive monitoring

**Configuration:**
```json
{
  "security_level": "high",
  "encryption_enabled": true,
  "signature_validation_enabled": true,
  "rate_limiting_enabled": true,
  "monitoring_enabled": true
}
```

### CRITICAL Security Level

**Use Case:** Military or government environments

**Features:**
- Multi-factor authentication
- Military-grade encryption
- Advanced threat detection
- Zero-trust architecture

**Configuration:**
```json
{
  "security_level": "critical",
  "encryption_enabled": true,
  "signature_validation_enabled": true,
  "rate_limiting_enabled": true,
  "monitoring_enabled": true,
  "multi_factor_auth": true,
  "zero_trust": true
}
```

## API Endpoints

### Security Status

**GET /api/v1/security/status**

Returns overall security system status and statistics.

**Response:**
```json
{
  "success": true,
  "data": {
    "security_enabled": true,
    "security_report": "Work Unit Security Manager Status:\n  Enabled: Yes\n  Encryption: Yes\n  Signatures: Yes\n  Rate Limiting: Yes\n  Monitoring: Yes\n  Registered Clients: 5\n  Trusted Clients: 4\n  Blocked Clients: 1\n  Security Events: 23",
    "trusted_clients": 4,
    "blocked_clients": 1,
    "security_statistics": {
      "total_events": 23,
      "low_severity_events": 15,
      "medium_severity_events": 6,
      "high_severity_events": 2,
      "critical_severity_events": 0
    }
  }
}
```

### Security Events

**GET /api/v1/security/events?severity=medium**

Returns security events filtered by severity level.

**Query Parameters:**
- `severity` - Filter by severity level (low, medium, high, critical)

**Response:**
```json
{
  "success": true,
  "data": {
    "events": [
      {
        "event_id": "evt_1234567890",
        "event_type": "AUTH_FAILED",
        "client_id": "client_001",
        "description": "Authentication failed",
        "severity": 1,
        "timestamp": 1703123456789,
        "requires_action": false,
        "recommended_action": "Check credentials"
      },
      {
        "event_id": "evt_1234567891",
        "event_type": "RATE_LIMIT_EXCEEDED",
        "client_id": "client_002",
        "description": "Rate limit exceeded for operation: work_unit_requests",
        "severity": 1,
        "timestamp": 1703123456790,
        "requires_action": true,
        "recommended_action": "Review client behavior"
      }
    ],
    "total_events": 2,
    "min_severity": 1
  }
}
```

### Client Authentication

**POST /api/v1/security/authenticate**

Authenticates a client using the specified authentication method.

**Request Body:**
```json
{
  "client_id": "client_001",
  "auth_data": "ak_1234567890abcdef",
  "auth_method": "api_key"
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "authenticated": true,
    "session_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "client_id": "client_001",
    "auth_method": "api_key",
    "expires_at": "2023-12-22T10:30:00Z"
  }
}
```

### Client Registration

**POST /api/v1/security/register**

Registers a new client with the security system.

**Request Body:**
```json
{
  "client_id": "client_001",
  "auth_method": "api_key",
  "security_level": "medium",
  "capabilities": {
    "max_memory_mb": 2048,
    "supports_gpu": true,
    "network_bandwidth_mbps": 100.0
  }
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "registered": true,
    "client_id": "client_001",
    "api_key": "ak_1234567890abcdef",
    "security_level": "medium",
    "auth_method": "api_key"
  }
}
```

## Usage Examples

### Python Security Client

```python
import requests
import json
import time
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime

class SecurityClient:
    def __init__(self, server_url, client_id):
        self.server_url = server_url
        self.client_id = client_id
        self.session_token = None
        self.api_key = None
        
    def register_with_api_key(self, security_level="medium"):
        """Register client with API key authentication"""
        response = requests.post(f"{self.server_url}/api/v1/security/register", 
                               json={
                                   "client_id": self.client_id,
                                   "auth_method": "api_key",
                                   "security_level": security_level,
                                   "capabilities": {
                                       "max_memory_mb": 2048,
                                       "supports_gpu": True,
                                       "network_bandwidth_mbps": 100.0,
                                       "processing_latency_ms": 50.0
                                   }
                               })
        
        if response.status_code == 200:
            data = response.json()
            if data["success"]:
                self.api_key = data["data"]["api_key"]
                return True
        return False
    
    def register_with_certificate(self, private_key, certificate):
        """Register client with certificate authentication"""
        # Convert certificate to PEM format
        cert_pem = certificate.public_bytes(serialization.Encoding.PEM).decode()
        key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()
        
        response = requests.post(f"{self.server_url}/api/v1/security/register", 
                               json={
                                   "client_id": self.client_id,
                                   "auth_method": "client_cert",
                                   "security_level": "high",
                                   "certificate": cert_pem,
                                   "public_key": key_pem,
                                   "capabilities": {
                                       "max_memory_mb": 4096,
                                       "supports_gpu": True,
                                       "network_bandwidth_mbps": 1000.0,
                                       "processing_latency_ms": 25.0
                                   }
                               })
        
        return response.status_code == 200 and response.json()["success"]
    
    def authenticate(self, auth_method="api_key"):
        """Authenticate with the server"""
        if auth_method == "api_key" and self.api_key:
            auth_data = self.api_key
        else:
            raise ValueError("Invalid authentication method or missing credentials")
        
        response = requests.post(f"{self.server_url}/api/v1/security/authenticate", 
                               json={
                                   "client_id": self.client_id,
                                   "auth_data": auth_data,
                                   "auth_method": auth_method
                               })
        
        if response.status_code == 200:
            data = response.json()
            if data["success"]:
                self.session_token = data["data"]["session_token"]
                return True
        return False
    
    def get_security_status(self):
        """Get security system status"""
        response = requests.get(f"{self.server_url}/api/v1/security/status")
        return response.json() if response.status_code == 200 else None
    
    def get_security_events(self, severity="medium"):
        """Get security events"""
        response = requests.get(f"{self.server_url}/api/v1/security/events", 
                              params={"severity": severity})
        return response.json() if response.status_code == 200 else None

# Usage example
def main():
    client = SecurityClient("http://localhost:8080", "client_001")
    
    # Register with API key
    if client.register_with_api_key("medium"):
        print("Registration successful")
        
        # Authenticate
        if client.authenticate("api_key"):
            print("Authentication successful")
            
            # Get security status
            status = client.get_security_status()
            if status:
                print(f"Security status: {status['data']['security_enabled']}")
            
            # Get security events
            events = client.get_security_events("medium")
            if events:
                print(f"Security events: {len(events['data']['events'])}")
        else:
            print("Authentication failed")
    else:
        print("Registration failed")

if __name__ == "__main__":
    main()
```

### C++ Security Client

```cpp
#include "client_work_unit_coordinator.h"
#include "work_unit_security.h"
#include <iostream>
#include <thread>
#include <chrono>

class SecurityClient {
private:
    FGCom_ClientSecurityCoordinator& security_coordinator;
    std::string server_url;
    std::string client_id;
    
public:
    SecurityClient(const std::string& server_url, const std::string& client_id)
        : security_coordinator(FGCom_ClientSecurityCoordinator::getInstance())
        , server_url(server_url)
        , client_id(client_id) {}
    
    bool initialize(SecurityLevel security_level = SecurityLevel::MEDIUM) {
        // Initialize security coordinator
        if (!security_coordinator.initialize(security_level)) {
            std::cerr << "Failed to initialize security coordinator" << std::endl;
            return false;
        }
        
        // Create client security profile
        ClientSecurityProfile profile;
        profile.client_id = client_id;
        profile.security_level = security_level;
        profile.auth_method = AuthenticationMethod::API_KEY;
        profile.is_trusted = true;
        profile.is_blocked = false;
        profile.failed_auth_attempts = 0;
        profile.reputation_score = 0.5;
        profile.created_time = std::chrono::system_clock::now();
        
        // Set capabilities
        profile.max_memory_mb = 2048;
        profile.supports_gpu = true;
        profile.supports_double_precision = true;
        profile.network_bandwidth_mbps = 100.0;
        profile.processing_latency_ms = 50.0;
        profile.is_online = true;
        
        // Set supported work unit types
        profile.allowed_work_unit_types = {
            "PROPAGATION_GRID",
            "ANTENNA_PATTERN",
            "FREQUENCY_OFFSET",
            "AUDIO_PROCESSING"
        };
        
        // Set rate limits
        profile.rate_limits = {
            {"work_unit_requests", 10},
            {"result_submissions", 20},
            {"heartbeat", 60}
        };
        
        // Register with server
        if (!security_coordinator.registerWithServer(profile)) {
            std::cerr << "Failed to register with server" << std::endl;
            return false;
        }
        
        // Authenticate with server
        if (!security_coordinator.authenticateWithServer()) {
            std::cerr << "Failed to authenticate with server" << std::endl;
            return false;
        }
        
        std::cout << "Security client initialized successfully" << std::endl;
        return true;
    }
    
    void run() {
        std::cout << "Security client running" << std::endl;
        
        while (true) {
            // Check authentication status
            if (!security_coordinator.isAuthenticated()) {
                std::cout << "Not authenticated, attempting to re-authenticate..." << std::endl;
                if (!security_coordinator.authenticateWithServer()) {
                    std::cout << "Re-authentication failed, waiting..." << std::endl;
                    std::this_thread::sleep_for(std::chrono::seconds(30));
                    continue;
                }
            }
            
            // Get security events
            auto events = security_coordinator.getSecurityEvents();
            if (!events.empty()) {
                std::cout << "Security events: " << events.size() << std::endl;
                for (const auto& event : events) {
                    std::cout << "  " << event.event_type << ": " << event.description << std::endl;
                }
            }
            
            // Print security report
            std::cout << security_coordinator.getSecurityReport() << std::endl;
            
            // Sleep for a bit
            std::this_thread::sleep_for(std::chrono::seconds(60));
        }
    }
    
    void shutdown() {
        security_coordinator.shutdown();
        std::cout << "Security client shutdown complete" << std::endl;
    }
};

int main() {
    std::cout << "FGCom Security Client Example" << std::endl;
    
    // Create security client
    SecurityClient client("http://localhost:8080", "client_001");
    
    // Initialize
    if (!client.initialize(SecurityLevel::MEDIUM)) {
        std::cerr << "Failed to initialize security client" << std::endl;
        return 1;
    }
    
    // Run client
    try {
        client.run();
    } catch (const std::exception& e) {
        std::cerr << "Security client error: " << e.what() << std::endl;
    }
    
    // Shutdown
    client.shutdown();
    
    return 0;
}
```

### JavaScript/Node.js Security Client

```javascript
const axios = require('axios');
const crypto = require('crypto');

class SecurityClient {
    constructor(serverUrl, clientId) {
        this.serverUrl = serverUrl;
        this.clientId = clientId;
        this.sessionToken = null;
        this.apiKey = null;
    }
    
    async registerWithApiKey(securityLevel = 'medium') {
        try {
            const response = await axios.post(`${this.serverUrl}/api/v1/security/register`, {
                client_id: this.clientId,
                auth_method: 'api_key',
                security_level: securityLevel,
                capabilities: {
                    max_memory_mb: 2048,
                    supports_gpu: true,
                    network_bandwidth_mbps: 100.0,
                    processing_latency_ms: 50.0
                }
            });
            
            if (response.data.success) {
                this.apiKey = response.data.data.api_key;
                return true;
            }
        } catch (error) {
            console.error('Registration failed:', error.message);
        }
        return false;
    }
    
    async authenticate(authMethod = 'api_key') {
        try {
            let authData;
            if (authMethod === 'api_key' && this.apiKey) {
                authData = this.apiKey;
            } else {
                throw new Error('Invalid authentication method or missing credentials');
            }
            
            const response = await axios.post(`${this.serverUrl}/api/v1/security/authenticate`, {
                client_id: this.clientId,
                auth_data: authData,
                auth_method: authMethod
            });
            
            if (response.data.success) {
                this.sessionToken = response.data.data.session_token;
                return true;
            }
        } catch (error) {
            console.error('Authentication failed:', error.message);
        }
        return false;
    }
    
    async getSecurityStatus() {
        try {
            const response = await axios.get(`${this.serverUrl}/api/v1/security/status`);
            return response.data;
        } catch (error) {
            console.error('Failed to get security status:', error.message);
            return null;
        }
    }
    
    async getSecurityEvents(severity = 'medium') {
        try {
            const response = await axios.get(`${this.serverUrl}/api/v1/security/events`, {
                params: { severity }
            });
            return response.data;
        } catch (error) {
            console.error('Failed to get security events:', error.message);
            return null;
        }
    }
    
    async monitorSecurity() {
        console.log('Starting security monitoring...');
        
        while (true) {
            try {
                const status = await this.getSecurityStatus();
                if (status) {
                    console.log(`Security enabled: ${status.data.security_enabled}`);
                    console.log(`Trusted clients: ${status.data.trusted_clients}`);
                    console.log(`Blocked clients: ${status.data.blocked_clients}`);
                }
                
                const events = await this.getSecurityEvents('medium');
                if (events && events.data.events.length > 0) {
                    console.log(`Security events: ${events.data.events.length}`);
                    events.data.events.forEach(event => {
                        console.log(`  ${event.event_type}: ${event.description}`);
                    });
                }
                
                await new Promise(resolve => setTimeout(resolve, 60000)); // Wait 1 minute
                
            } catch (error) {
                console.error('Error in security monitoring:', error.message);
                await new Promise(resolve => setTimeout(resolve, 30000)); // Wait 30 seconds on error
            }
        }
    }
}

// Usage
async function main() {
    const client = new SecurityClient('http://localhost:8080', 'client_001');
    
    if (await client.registerWithApiKey('medium')) {
        console.log('Registration successful');
        
        if (await client.authenticate('api_key')) {
            console.log('Authentication successful');
            await client.monitorSecurity();
        } else {
            console.log('Authentication failed');
        }
    } else {
        console.log('Registration failed');
    }
}

main().catch(console.error);
```

## Security Best Practices

### 1. Authentication

- **Use strong authentication methods** for production environments
- **Implement certificate-based authentication** for high security requirements
- **Regularly rotate API keys** and certificates
- **Use multi-factor authentication** for critical systems

### 2. Encryption

- **Enable end-to-end encryption** for sensitive data
- **Use strong encryption algorithms** (AES-256, RSA-2048+)
- **Implement proper key management** with regular rotation
- **Secure key storage** using hardware security modules when possible

### 3. Rate Limiting

- **Set appropriate rate limits** based on client capabilities
- **Monitor rate limit violations** and adjust limits as needed
- **Implement progressive penalties** for repeated violations
- **Use different limits** for different client types

### 4. Monitoring

- **Enable comprehensive security monitoring** for all environments
- **Set up alerts** for security events
- **Regularly review security logs** for anomalies
- **Implement automated responses** to security threats

### 5. Client Management

- **Maintain client reputation scores** based on behavior
- **Implement client blocking** for security violations
- **Regularly audit client access** and permissions
- **Use least privilege principle** for client capabilities

## Threat Detection

### Security Event Types

1. **Authentication Events**
   - `AUTH_SUCCESS` - Successful authentication
   - `AUTH_FAILED` - Failed authentication attempt
   - `AUTH_BLOCKED` - Client blocked due to failed attempts
   - `AUTH_LOCKED` - Client locked due to repeated failures

2. **Rate Limiting Events**
   - `RATE_LIMIT_EXCEEDED` - Client exceeded rate limits
   - `RATE_LIMIT_WARNING` - Client approaching rate limits
   - `RATE_LIMIT_RESET` - Rate limits reset for client

3. **Security Violations**
   - `SECURITY_VIOLATION` - General security violation
   - `UNAUTHORIZED_ACCESS` - Unauthorized access attempt
   - `DATA_TAMPERING` - Suspected data tampering
   - `MALICIOUS_ACTIVITY` - Detected malicious activity

4. **System Events**
   - `CLIENT_REGISTERED` - New client registered
   - `CLIENT_REVOKED` - Client access revoked
   - `SECURITY_LEVEL_CHANGED` - Security level changed
   - `CONFIGURATION_CHANGED` - Security configuration changed

### Automated Responses

The system can automatically respond to security threats:

1. **Temporary Blocking** - Block clients temporarily for rate limit violations
2. **Permanent Blocking** - Permanently block clients for serious violations
3. **Security Level Adjustment** - Increase security requirements for suspicious clients
4. **Alert Generation** - Generate alerts for security administrators

## Troubleshooting

### Common Issues

1. **Authentication Failures**
   - Check API key validity
   - Verify client ID
   - Ensure proper authentication method

2. **Rate Limit Exceeded**
   - Check client rate limits
   - Implement exponential backoff
   - Contact administrator for limit increases

3. **Certificate Issues**
   - Verify certificate validity
   - Check certificate chain
   - Ensure proper certificate format

4. **Encryption Errors**
   - Verify encryption keys
   - Check key rotation status
   - Ensure proper key management

### Debugging

1. **Enable Debug Logging**
   ```json
   {
     "debug": true,
     "log_level": "DEBUG",
     "security_logging": true
   }
   ```

2. **Check Security Events**
   ```bash
   curl -X GET "http://localhost:8080/api/v1/security/events?severity=low"
   ```

3. **Monitor Security Status**
   ```bash
   curl -X GET "http://localhost:8080/api/v1/security/status"
   ```

4. **Test Authentication**
   ```bash
   curl -X POST "http://localhost:8080/api/v1/security/authenticate" \
        -H "Content-Type: application/json" \
        -d '{"client_id":"test","auth_data":"test","auth_method":"api_key"}'
   ```

## Conclusion

The Security API provides comprehensive security features for the distributed work unit system. By following the documentation and best practices, you can implement secure clients that protect against various threats while maintaining system performance and usability.
