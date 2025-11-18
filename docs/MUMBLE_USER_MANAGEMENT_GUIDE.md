# FGCom-mumble Mumble User Management Guide

**Complete guide for managing users, channels, and permissions in FGCom-mumble**

## Table of Contents

1. [Overview](#overview)
2. [Mumble User Management](#mumble-user-management)
3. [Admin User Setup Procedures](#admin-user-setup-procedures)
4. [Channel Access Control Documentation](#channel-access-control-documentation)
5. [Permission Management Guide](#permission-management-guide)
6. [Authentication Setup Instructions](#authentication-setup-instructions)
7. [Troubleshooting](#troubleshooting)

## Overview

FGCom-mumble uses Mumble as its communication infrastructure. This guide covers all aspects of user management, from basic user creation to advanced permission control.

### Key Components:
- **Mumble Server**: Communication infrastructure
- **FGCom-mumble Plugin**: Radio simulation layer
- **User Management**: Authentication and authorization
- **Channel Management**: Radio communication channels
- **Permission System**: Access control and user roles

## Mumble User Management

### 1. Basic User Registration

#### Method 1: Using Mumble Client (Recommended)
```bash
# Connect to Mumble server with Mumble client
# Right-click on server name → "Register"
# Enter username and password
# User is now registered
```

#### Method 2: Using Command Line
```bash
# Register user via command line
murmur -ini /etc/mumble/mumble-server.ini -supw username password

# Example:
murmur -ini /etc/mumble/mumble-server.ini -supw admin myadminpassword
```

#### Method 3: Using Configuration File
```ini
# In /etc/mumble/mumble-server.ini
[users]
admin=password123
user1=password456
user2=password789
```

### 2. User Types

#### Regular Users
- **Purpose**: Standard radio communication
- **Access**: `fgcom-mumble` channel only
- **Permissions**: Radio communication, voice, text
- **Restrictions**: Cannot access admin functions

#### Admin Users
- **Purpose**: Server administration and bot management
- **Access**: Both `fgcom-mumble` and `fgcom-mumble-admins` channels
- **Permissions**: Full server control, bot management, user administration
- **Restrictions**: None

#### Bot Users
- **Purpose**: Automated bot operations
- **Access**: Specific channels based on bot function
- **Permissions**: Bot-specific operations
- **Restrictions**: Limited to bot functions

### 3. User Management Commands

#### List Users
```bash
# List all registered users
murmur -ini /etc/mumble/mumble-server.ini -list

# List users with details
murmur -ini /etc/mumble/mumble-server.ini -list -v
```

#### Remove Users
```bash
# Remove specific user
murmur -ini /etc/mumble/mumble-server.ini -remove username

# Example:
murmur -ini /etc/mumble/mumble-server.ini -remove olduser
```

#### Change Passwords
```bash
# Change user password
murmur -ini /etc/mumble/mumble-server.ini -supw username newpassword

# Example:
murmur -ini /etc/mumble/mumble-server.ini -supw admin newadminpassword
```

## Admin User Setup Procedures

### 1. Create Admin User

#### Step 1: Register Admin User
```bash
# Register admin user
murmur -ini /etc/mumble/mumble-server.ini -supw admin myadminpassword
```

#### Step 2: Set Admin Permissions
```bash
# Set user as admin (if supported by your Mumble version)
murmur -ini /etc/mumble/mumble-server.ini -setadmin admin
```

#### Step 3: Configure Channel Access
```ini
# In /etc/mumble/mumble-server.ini
[acl]
# fgcom-mumble channel - Open to all users
12=@all:+enter,+traverse,+speak,+whisper,+textmessage

# fgcom-mumble-admins channel - Restricted to admins
13=@admin:+enter,+traverse,+speak,+whisper,+textmessage
```

### 2. Admin User Configuration

#### Admin User Profile
```ini
# Admin user configuration
[user_admin]
username=admin
password=myadminpassword
type=admin
channels=fgcom-mumble,fgcom-mumble-admins
permissions=bot_management,server_config,user_management
role=administrator
```

#### Admin Permissions
- **Bot Management**: Start/stop/restart bots
- **Server Configuration**: Modify server settings
- **User Management**: Add/remove users
- **Channel Management**: Create/modify channels
- **System Monitoring**: View system status

### 3. Multiple Admin Users

#### Create Additional Admins
```bash
# Create second admin
murmur -ini /etc/mumble/mumble-server.ini -supw admin2 admin2password

# Create third admin
murmur -ini /etc/mumble/mumble-server.ini -supw admin3 admin3password
```

#### Admin Group Configuration
```ini
# Admin group configuration
[groups]
admin_group=admin,admin2,admin3

[group_permissions]
admin_group=bot_management,server_config,user_management,channel_management
```

## Channel Access Control Documentation

### 1. Channel Structure

#### Main Channels
```
Root Channel
├── fgcom-mumble (Main radio communication)
└── fgcom-mumble-admins (Administrative functions)
```

#### Sub-channels (Optional)
```
fgcom-mumble
├── fgcom-mumble-nyc (New York airspace)
├── fgcom-mumble-london (London airspace)
└── fgcom-mumble-europe (European airspace)
```

### 2. Channel Access Control Lists (ACL)

#### Basic ACL Configuration
```ini
# In /etc/mumble/mumble-server.ini
[acl]
# fgcom-mumble channel (12) - Open to all users
12=@all:+enter,+traverse,+speak,+whisper,+textmessage

# fgcom-mumble-admins channel (13) - Restricted to admins
13=@admin:+enter,+traverse,+speak,+whisper,+textmessage
```

#### Advanced ACL Configuration
```ini
# Advanced ACL with specific permissions
[acl]
# fgcom-mumble channel - All users can enter and speak
12=@all:+enter,+traverse,+speak,+whisper,+textmessage

# fgcom-mumble-admins channel - Only admins can access
13=@admin:+enter,+traverse,+speak,+whisper,+textmessage
13=@all:-enter,-traverse,-speak,-whisper,-textmessage

# Sub-channels with specific access
14=@pilot:+enter,+traverse,+speak
14=@atc:+enter,+traverse,+speak,+whisper
14=@all:-enter,-traverse,-speak,-whisper
```

### 3. Channel Permissions

#### Permission Types
- **+enter**: Allow user to enter channel
- **+traverse**: Allow user to move through channel
- **+speak**: Allow user to speak in channel
- **+whisper**: Allow user to whisper in channel
- **+textmessage**: Allow user to send text messages
- **+mute**: Allow user to mute others
- **+deafen**: Allow user to deafen others
- **+kick**: Allow user to kick others
- **+ban**: Allow user to ban others

#### Permission Examples
```ini
# Pilot permissions
pilot_permissions=+enter,+traverse,+speak,+whisper,+textmessage

# ATC permissions
atc_permissions=+enter,+traverse,+speak,+whisper,+textmessage,+mute,+deafen

# Admin permissions
admin_permissions=+enter,+traverse,+speak,+whisper,+textmessage,+mute,+deafen,+kick,+ban
```

## Permission Management Guide

### 1. User Roles

#### Pilot Role
```ini
[role_pilot]
name=pilot
channels=fgcom-mumble
permissions=+enter,+traverse,+speak,+whisper,+textmessage
restrictions=-mute,-deafen,-kick,-ban
```

#### ATC Role
```ini
[role_atc]
name=atc
channels=fgcom-mumble
permissions=+enter,+traverse,+speak,+whisper,+textmessage,+mute,+deafen
restrictions=-kick,-ban
```

#### Admin Role
```ini
[role_admin]
name=admin
channels=fgcom-mumble,fgcom-mumble-admins
permissions=+enter,+traverse,+speak,+whisper,+textmessage,+mute,+deafen,+kick,+ban
restrictions=none
```

### 2. Permission Inheritance

#### Group-Based Permissions
```ini
# Define groups
[groups]
pilots=pilot1,pilot2,pilot3
atc_controllers=atc1,atc2,atc3
administrators=admin1,admin2,admin3

# Group permissions
[group_permissions]
pilots=+enter,+traverse,+speak,+whisper,+textmessage
atc_controllers=+enter,+traverse,+speak,+whisper,+textmessage,+mute,+deafen
administrators=+enter,+traverse,+speak,+whisper,+textmessage,+mute,+deafen,+kick,+ban
```

### 3. Dynamic Permission Management

#### Runtime Permission Changes
```bash
# Add user to group
murmur -ini /etc/mumble/mumble-server.ini -adduser username groupname

# Remove user from group
murmur -ini /etc/mumble/mumble-server.ini -removeuser username groupname

# Change user permissions
murmur -ini /etc/mumble/mumble-server.ini -setpermissions username permissions
```

## Authentication Setup Instructions

### 1. Server Authentication

#### Server Password Setup
```ini
# In /etc/mumble/mumble-server.ini
# Set server password (optional)
serverpassword=your_server_password

# Set SuperUser password (required for admin access)
superuser_password=your_superuser_password
```

#### Certificate-Based Authentication
```ini
# SSL certificate configuration
sslCert=/etc/mumble/server.crt
sslKey=/etc/mumble/server.key

# Client certificate verification
certificateRequired=true
```

### 2. User Authentication

#### Password-Based Authentication
```bash
# Set user password
murmur -ini /etc/mumble/mumble-server.ini -supw username password

# Example:
murmur -ini /etc/mumble/mumble-server.ini -supw admin myadminpassword
```

#### Certificate-Based Authentication
```bash
# Generate user certificate
openssl req -new -x509 -keyout user.key -out user.crt -days 365 -nodes

# Add certificate to user
murmur -ini /etc/mumble/mumble-server.ini -addcert username user.crt
```

### 3. Multi-Factor Authentication

#### API-Based Authentication
```bash
# Enable API authentication
curl -X POST http://localhost:16661/api/auth/enable \
  -H "Content-Type: application/json" \
  -d '{"type": "multi_factor", "enabled": true}'
```

#### LDAP Integration
```ini
# LDAP authentication configuration
[ldap]
enabled=true
server=ldap://your-ldap-server.com
base_dn=ou=users,dc=example,dc=com
bind_dn=cn=admin,dc=example,dc=com
bind_password=your_ldap_password
```

### 4. Session Management

#### Session Configuration
```ini
# Session timeout settings
session_timeout=3600
max_sessions_per_user=5
session_cleanup_interval=300
```

#### Session Monitoring
```bash
# View active sessions
curl http://localhost:16661/api/sessions

# Terminate user session
curl -X DELETE http://localhost:16661/api/sessions/{session_id}
```

## Troubleshooting

### 1. Common Issues

#### User Cannot Connect
```bash
# Check user registration
murmur -ini /etc/mumble/mumble-server.ini -list | grep username

# Check server status
systemctl status mumble-server

# Check server logs
journalctl -u mumble-server -f
```

#### Permission Denied
```bash
# Check user permissions
murmur -ini /etc/mumble/mumble-server.ini -list -v | grep username

# Check channel ACL
grep -A 10 "\[acl\]" /etc/mumble/mumble-server.ini
```

#### Channel Access Issues
```bash
# Check channel configuration
grep -A 20 "\[channels\]" /etc/mumble/mumble-server.ini

# Verify channel permissions
murmur -ini /etc/mumble/mumble-server.ini -list -v
```

### 2. Debug Commands

#### Server Status
```bash
# Check server status
systemctl status mumble-server

# Check server configuration
murmur -ini /etc/mumble/mumble-server.ini -check

# Test server connectivity
telnet localhost 64738
```

#### User Management
```bash
# List all users
murmur -ini /etc/mumble/mumble-server.ini -list

# Check specific user
murmur -ini /etc/mumble/mumble-server.ini -list -v | grep username

# Test user authentication
murmur -ini /etc/mumble/mumble-server.ini -test username password
```

### 3. Log Analysis

#### Server Logs
```bash
# View server logs
journalctl -u mumble-server -f

# View specific log entries
journalctl -u mumble-server --since "1 hour ago"

# View error logs only
journalctl -u mumble-server -p err
```

#### FGCom-mumble Logs
```bash
# View FGCom-mumble logs
journalctl -u fgcom-mumble -f

# View bot logs
tail -f /var/log/fgcom-mumble/bot-manager.log

# View channel creation logs
tail -f /var/log/fgcom-mumble/channel-creation.log
```

## Best Practices

### 1. Security
- Use strong passwords for all users
- Enable SSL/TLS encryption
- Regularly update user permissions
- Monitor user activity
- Use certificate-based authentication for admins

### 2. Performance
- Limit concurrent user sessions
- Monitor server resource usage
- Optimize channel structure
- Regular maintenance and cleanup

### 3. Backup
- Regular backup of user database
- Backup server configuration
- Document all changes
- Test restore procedures

## Support

For additional help:
- Check the [Troubleshooting Guide](TROUBLESHOOTING_GUIDE.md)
- Review the [Technical Setup Guide](TECHNICAL_SETUP_GUIDE.md)
- Contact the development team
- Check the project documentation
