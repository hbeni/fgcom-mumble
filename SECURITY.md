Data protection / Security
==========================
The components of this system do never collect or store any personal data.

They however exchange data you provide with the Mumble server you connect to, as well as other mumble clients, so be sure to never supply personal data like real names etc. Also never enter passwords or something like that into one of the systems components; it's all password free.                                                                     

The data exchanged locally (like FGFS or RadioGui to the plugin) is in plaintext, but the data the plugin sends to the Mumble server is encrypted using mumbles own facilities; however bear in mind that the server itself as well as other mumble clients can see the data in plaintext.                                                                     


Security Policy of the project
==============================

## Supported Versions
The project will maintain the latest stable release. Security patches are usually included in the next ordinary release.                                                                                                                  
Fixing security bugs has priority over other issues, so we try to fix them as soon as possible.


## Reporting a Vulnerability
If you find a vulnerability, please report it as issue on the tracker, using the prefix `Security: ` so attention is rised.                                                                                                               
If the issue is of higher danger, you should consider "responsible disclosure" (send the report privately to the project first).                                                                                                          

Please describe the issue as detailed as possible. If possible, it would be cool if you could provide a patch when reporting.                                                                                                             

---

# FGCom-Mumble Security Guide

This document provides comprehensive security information for setting up secure connections with fgcom-mumble, including TLS/SSL configuration, authentication, and best practices for external clients like supermorse-web.

## Table of Contents

1. [Overview](#overview)
2. [Mumble Server Security](#mumble-server-security)
3. [Certificate-Based Authentication](#certificate-based-authentication)
4. [Token-Based Authentication](#token-based-authentication)
5. [Client Security Configuration](#client-security-configuration)
6. [External Client Integration](#external-client-integration)
7. [Security Best Practices](#security-best-practices)
8. [Troubleshooting](#troubleshooting)

## Overview

FGCom-mumble provides multiple layers of security:

- **Transport Layer Security (TLS)**: Encrypts all communication
- **Certificate Authentication**: Replaces password-based authentication
- **Token-Based Authorization**: Additional access control layer
- **Encrypted Voice Transmission**: Built-in Mumble encryption
- **Session Management**: Secure session handling with expiration

## Mumble Server Security

### TLS/SSL Configuration

Configure your Mumble server (Murmur) with TLS encryption:

#### 1. Generate Server Certificates

```bash
# Generate server certificate and key
openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=your-server.com"

# Set proper permissions
chmod 600 server.key
chmod 644 server.crt
```

#### 2. Configure Murmur Server

Edit your `murmur.ini` configuration file:

```ini
# Basic server settings
host=0.0.0.0
port=64738

# TLS/SSL Configuration
sslCert=/path/to/server.crt
sslKey=/path/to/server.key
sslCA=/path/to/ca.crt
certrequired=true

# Security settings
allowping=false
bandwidth=128000
users=100
textmessagelength=5000
imagemessagelength=131072

# Authentication settings
registerName=Register
registerPassword=your-register-password
registerUrl=https://your-server.com/register

# Logging for security monitoring
logfile=/var/log/murmur/murmur.log
```

#### 3. Start Secure Server

```bash
# Start Murmur with TLS
murmur -ini /path/to/murmur.ini
```

### Server Security Hardening

#### Firewall Configuration

```bash
# Allow only necessary ports
ufw allow 64738/tcp  # Mumble server
ufw allow 64738/udp  # Mumble voice
ufw deny 64738       # Block unencrypted connections
```

#### System Security

```bash
# Run as non-root user
useradd -r -s /bin/false murmur
chown -R murmur:murmur /var/lib/murmur
chown -R murmur:murmur /var/log/murmur
```

## Certificate-Based Authentication

### Client Certificate Generation

#### For Individual Users

```bash
# Generate user certificate
openssl genrsa -out user.key 2048
openssl req -new -sha256 -key user.key -out user.csr -subj "/CN=username"
openssl x509 -req -in user.csr -signkey user.key -out user.pem -days 365
```

#### For Bot Services

```bash
# Generate bot certificates (as documented in server/Readme.server.md)
for w in rec play status;
  do  openssl genrsa -out ${w}bot.key 2048 2> /dev/null
  openssl req -new -sha256 -key ${w}bot.key -out ${w}bot.csr -subj "/"
  openssl x509 -req -in ${w}bot.csr -signkey ${w}bot.key -out ${w}bot.pem 2> /dev/null
done
```

### Certificate Management

#### Certificate Authority (CA) Setup

```bash
# Create CA
openssl genrsa -out ca.key 4096
openssl req -new -x509 -key ca.key -out ca.crt -days 365 \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=CA"

# Sign client certificates
openssl x509 -req -in user.csr -CA ca.crt -CAkey ca.key -out user.pem -days 365
```

#### Certificate Validation

```bash
# Verify certificate
openssl x509 -in user.pem -text -noout

# Check certificate chain
openssl verify -CAfile ca.crt user.pem
```

## Token-Based Authentication

### Server-Side Token Configuration

Configure authentication tokens in your bot configuration:

```lua
-- In fgcom-sharedFunctions.inc.lua
fgcom.auth = {
    authToken = "your-secure-random-token-here",
    authedUsers = {},
    
    -- Token validation
    isAuthenticated = function(user)
        for _, authedUser in ipairs(fgcom.auth.authedUsers) do
            if authedUser:getSession() == user:getSession() then
                return true
            end
        end
        return false
    end,
    
    -- Handle authentication
    handleAuthentication = function(user, token)
        if token and fgcom.auth.authToken and token == fgcom.auth.authToken then
            table.insert(fgcom.auth.authedUsers, user)
            fgcom.log("successfully authenticated user "..user:getName())
            user:message("successfully authenticated")
            return true
        end
        return false
    end
}
```

### Client Authentication Flow

```javascript
// External client authentication
const mumbleClient = new MumbleClient({
    host: 'your-server.com',
    port: 64738,
    username: 'client-name',
    cert: 'client.pem',
    key: 'client.key'
});

// Connect and authenticate
mumbleClient.on('connected', () => {
    // Send authentication token
    mumbleClient.sendMessage('/auth your-secure-token');
});
```

## Client Security Configuration

### RadioGUI Security Setup

#### 1. Certificate Configuration

```bash
# Generate RadioGUI certificate
openssl genrsa -out radiogui.key 2048
openssl req -new -sha256 -key radiogui.key -out radiogui.csr \
  -subj "/CN=radiogui-client"
openssl x509 -req -in radiogui.csr -signkey radiogui.key -out radiogui.pem -days 365
```

#### 2. Secure Connection

```java
// In radioGUI configuration
public class SecureConnection {
    private static final String CERT_PATH = "/path/to/radiogui.pem";
    private static final String KEY_PATH = "/path/to/radiogui.key";
    private static final String AUTH_TOKEN = "your-secure-token";
    
    public void connectSecurely() {
        // Use certificate-based authentication
        // No passwords required
    }
}
```

### Mumble Client Security

#### Connection Parameters

```javascript
const secureConfig = {
    host: 'your-server.com',
    port: 64738,
    username: 'client-name',
    
    // Certificate authentication
    cert: 'client.pem',
    key: 'client.key',
    
    // TLS settings
    rejectUnauthorized: true,
    secure: true,
    
    // Authentication token
    authToken: 'your-secure-token'
};
```

## External Client Integration

### supermorse-web Security Setup

#### 1. Certificate Generation

```bash
# Generate supermorse certificate
openssl genrsa -out supermorse.key 2048
openssl req -new -sha256 -key supermorse.key -out supermorse.csr \
  -subj "/CN=supermorse-client"
openssl x509 -req -in supermorse.csr -signkey supermorse.key -out supermorse.pem -days 365
```

#### 2. Secure Connection Code

```javascript
// supermorse-web secure connection
const mumbleConfig = {
    host: 'fgcom-server.com',
    port: 64738,
    username: 'supermorse-user',
    
    // Certificate-based authentication
    cert: fs.readFileSync('supermorse.pem'),
    key: fs.readFileSync('supermorse.key'),
    
    // TLS encryption
    rejectUnauthorized: true,
    secure: true,
    
    // Additional security
    authToken: process.env.FGCOM_AUTH_TOKEN
};

// Connect with security
const client = new MumbleClient(mumbleConfig);
client.on('connected', () => {
    // Authenticate with token
    client.sendMessage(`/auth ${process.env.FGCOM_AUTH_TOKEN}`);
});
```

#### 3. Environment Variables

```bash
# .env file for supermorse-web
FGCOM_SERVER=your-server.com
FGCOM_PORT=64738
FGCOM_AUTH_TOKEN=your-secure-token
FGCOM_CERT_PATH=/path/to/supermorse.pem
FGCOM_KEY_PATH=/path/to/supermorse.key
```

### Other External Clients

#### Python Client Example

```python
import mumble
import ssl

# Secure connection configuration
config = {
    'host': 'your-server.com',
    'port': 64738,
    'username': 'python-client',
    'certfile': 'client.pem',
    'keyfile': 'client.key',
    'ssl': ssl.create_default_context()
}

# Connect securely
client = mumble.MumbleClient(**config)
client.connect()
client.authenticate('/auth your-secure-token')
```

## Security Best Practices

### 1. Certificate Management

- **Use strong keys**: 2048-bit RSA minimum, 4096-bit recommended
- **Regular rotation**: Rotate certificates every 90-365 days
- **Secure storage**: Store private keys with restricted permissions (600)
- **Certificate validation**: Always validate certificate chains

### 2. Token Security

- **Strong tokens**: Use cryptographically secure random tokens (32+ characters)
- **Token rotation**: Rotate authentication tokens regularly
- **Secure storage**: Store tokens in environment variables or secure key stores
- **Access logging**: Log all authentication attempts

### 3. Network Security

- **Firewall rules**: Restrict access to necessary ports only
- **VPN access**: Consider VPN for additional security layer
- **Network monitoring**: Monitor for suspicious connection patterns
- **DDoS protection**: Implement rate limiting and connection limits

### 4. Server Hardening

- **Non-root execution**: Run services as non-privileged users
- **File permissions**: Restrict access to configuration and certificate files
- **Logging**: Enable comprehensive security logging
- **Updates**: Keep all components updated

### 5. Client Security

- **Certificate validation**: Always validate server certificates
- **Secure storage**: Store client certificates securely
- **Connection validation**: Verify server identity before connecting
- **Error handling**: Implement proper error handling for security failures

## Troubleshooting

### Common Security Issues

#### 1. Certificate Errors

```bash
# Check certificate validity
openssl x509 -in certificate.pem -text -noout

# Verify certificate chain
openssl verify -CAfile ca.crt certificate.pem

# Check certificate expiration
openssl x509 -in certificate.pem -noout -dates
```

#### 2. Connection Failures

```bash
# Test TLS connection
openssl s_client -connect your-server.com:64738 -cert client.pem -key client.key

# Check server certificate
openssl s_client -connect your-server.com:64738 -showcerts
```

#### 3. Authentication Issues

```bash
# Check server logs
tail -f /var/log/murmur/murmur.log

# Verify token configuration
grep -r "authToken" /path/to/fgcom/config/
```

### Security Monitoring

#### Log Analysis

```bash
# Monitor authentication attempts
grep "authentication" /var/log/murmur/murmur.log

# Check for failed connections
grep "connection failed" /var/log/murmur/murmur.log

# Monitor certificate validation
grep "certificate" /var/log/murmur/murmur.log
```

#### Performance Monitoring

```bash
# Monitor connection count
netstat -an | grep :64738 | wc -l

# Check SSL/TLS performance
ss -tuln | grep :64738
```

## Security Checklist

### Server Setup
- [ ] TLS/SSL certificates configured
- [ ] Certificate validation enabled
- [ ] Firewall rules configured
- [ ] Non-root user execution
- [ ] Security logging enabled
- [ ] Authentication tokens configured

### Client Setup
- [ ] Client certificates generated
- [ ] Certificate validation enabled
- [ ] Secure connection parameters
- [ ] Authentication token configured
- [ ] Error handling implemented

### Monitoring
- [ ] Security logging enabled
- [ ] Connection monitoring active
- [ ] Certificate expiration tracking
- [ ] Authentication attempt logging
- [ ] Performance monitoring

## Additional Resources

- [Mumble Security Documentation](https://wiki.mumble.info/wiki/Security)
- [OpenSSL Certificate Management](https://www.openssl.org/docs/)
- [TLS/SSL Best Practices](https://wiki.mozilla.org/Security/Server_Side_TLS)
- [Certificate Authority Setup](https://jamielinux.com/docs/openssl-certificate-authority/)

---

**Note**: This security guide should be regularly updated as new security features are added to fgcom-mumble. Always follow the principle of least privilege and implement defense in depth for maximum security.