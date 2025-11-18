# Mumble User Management - Complete Beginner's Guide

**Everything you need to know about Mumble user management, explained from scratch**

## Table of Contents

1. [What is Mumble?](#what-is-mumble)
2. [Understanding Mumble Concepts](#understanding-mumble-concepts)
3. [Installing and Setting Up Mumble](#installing-and-setting-up-mumble)
4. [Basic User Management](#basic-user-management)
5. [Admin User Setup - Step by Step](#admin-user-setup---step-by-step)
6. [Understanding Channels](#understanding-channels)
7. [How FGCom-mumble Channels Work](#how-fgcom-mumble-channels-work)
8. [Permission System Explained](#permission-system-explained)
9. [Authentication Methods](#authentication-methods)
10. [Common Tasks](#common-tasks)
11. [Troubleshooting](#troubleshooting)

## What is Mumble?

**Mumble** is a voice communication software (like Discord or Teamspeak) that provides:
- **Voice chat** between users
- **Text messaging** 
- **Channel organization** (like chat rooms)
- **User management** (who can access what)
- **Server administration** tools

**Think of it like this:**
- **Mumble Server** = The building where people meet
- **Channels** = Different rooms in the building
- **Users** = People who can enter the building
- **Permissions** = Who can enter which rooms

## Understanding Mumble Concepts

### 1. Server vs Client

**Mumble Server (Murmur)**
- Runs on your computer/server
- Manages all users and channels
- Stores user data and settings
- Listens for connections on port 64738

**Mumble Client**
- Software users install on their computers
- Connects to the server
- Provides voice/text interface
- Examples: Mumble client, Plumble (mobile)

### 2. Users and Registration

**Unregistered Users**
- Can connect to server
- Limited permissions
- Temporary access
- No password required

**Registered Users**
- Have username and password
- Permanent access
- Can have specific permissions
- Stored in server database

### 3. Channels

**Root Channel**
- Main channel everyone starts in
- Usually named after the server

**Sub-channels**
- Channels inside other channels
- Can have different permissions
- Organized in a tree structure

**Example Channel Structure:**
```
Root Channel
├── General Chat
├── Gaming
│   ├── Strategy Games
│   └── Action Games
└── FGCom-mumble
    ├── fgcom-mumble (main radio)
    └── fgcom-mumble-admins
```

## Installing and Setting Up Mumble

### 1. Install Mumble Server

**On Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install mumble-server
```

**On CentOS/RHEL:**
```bash
sudo yum install mumble-server
```

**On Arch Linux:**
```bash
sudo pacman -S mumble
```

### 2. Start Mumble Server

```bash
# Start server
sudo systemctl start mumble-server

# Enable auto-start on boot
sudo systemctl enable mumble-server

# Check if running
sudo systemctl status mumble-server
```

### 3. Configure Mumble Server

**Main configuration file:** `/etc/mumble/mumble-server.ini`

**Basic configuration:**
```ini
; Server settings
port=64738
host=
welcometext="Welcome to our Mumble server!"

; Database
database=/var/lib/mumble-server/mumble-server.sqlite

; Security
serverpassword=
superuser_password=your_admin_password

; Users
users=100
timeout=30
```

## Basic User Management

### 1. Understanding User Types

**SuperUser (Admin)**
- Highest level access
- Can manage all users and channels
- Can change server settings
- Only one per server

**Registered Users**
- Have username and password
- Can be given specific permissions
- Stored permanently in database

**Unregistered Users**
- Temporary access
- Limited permissions
- No password required

### 2. Registering Your First User

**Method 1: Using Mumble Client (Easiest)**

1. **Download Mumble Client**
   - Go to https://www.mumble.info/
   - Download for your operating system
   - Install the client

2. **Connect to Server**
   - Open Mumble client
   - Click "Add New..."
   - Enter server address: `localhost` (or your server IP)
   - Port: `64738`
   - Username: `admin` (or any name)
   - Click "Connect"

3. **Register User**
   - Right-click on server name in channel list
   - Select "Register"
   - Enter password
   - Click "OK"
   - You're now registered!

**Method 2: Using Command Line**

```bash
# Register user via command line
sudo murmur -ini /etc/mumble/mumble-server.ini -supw username password

# Example: Register user "admin" with password "mypassword"
sudo murmur -ini /etc/mumble/mumble-server.ini -supw admin mypassword
```

### 3. Managing Users

**List All Users:**
```bash
sudo murmur -ini /etc/mumble/mumble-server.ini -list
```

**Remove User:**
```bash
sudo murmur -ini /etc/mumble/mumble-server.ini -remove username
```

**Change User Password:**
```bash
sudo murmur -ini /etc/mumble/mumble-server.ini -supw username newpassword
```

## Admin User Setup - Step by Step

### Step 1: Create Your First Admin User

**Option A: Using Mumble Client (Recommended for beginners)**

1. **Connect to Server**
   - Open Mumble client
   - Connect to your server
   - Use any username (e.g., "admin")

2. **Register as Admin**
   - Right-click server name → "Register"
   - Enter password: `myadminpassword`
   - Click "OK"

3. **Set as SuperUser**
   - Right-click server name → "Server → Configure"
   - Go to "Users" tab
   - Find your user in the list
   - Check "SuperUser" checkbox
   - Click "OK"

**Option B: Using Command Line**

```bash
# Register admin user
sudo murmur -ini /etc/mumble/mumble-server.ini -supw admin myadminpassword

# Set as superuser (if supported by your version)
sudo murmur -ini /etc/mumble/mumble-server.ini -setadmin admin
```

### Step 2: Verify Admin Access

1. **Connect with Admin Account**
   - Open Mumble client
   - Connect with username: `admin`
   - Password: `myadminpassword`

2. **Check Admin Status**
   - Right-click server name
   - You should see "Server → Configure" option
   - This confirms you have admin access

### Step 3: Create Additional Admin Users

**Using Mumble Client:**
1. Connect as existing admin
2. Right-click server name → "Server → Configure"
3. Go to "Users" tab
4. Click "Add User"
5. Enter username and password
6. Check "SuperUser" checkbox
7. Click "OK"

**Using Command Line:**
```bash
# Create second admin
sudo murmur -ini /etc/mumble/mumble-server.ini -supw admin2 admin2password

# Create third admin
sudo murmur -ini /etc/mumble/mumble-server.ini -supw admin3 admin3password
```

## Understanding Channels

### 1. What Are Channels?

**Channels are like chat rooms:**
- Users can join channels
- Each channel can have different permissions
- Users can move between channels
- Channels can be organized in a tree structure

### 2. Channel Types

**Temporary Channels**
- Created by users
- Deleted when empty
- Good for temporary discussions

**Permanent Channels**
- Created by administrators
- Always exist
- Good for organized communication

### 3. Channel Permissions

**Basic Permissions:**
- **Enter**: Can join the channel
- **Traverse**: Can move through the channel
- **Speak**: Can talk in the channel
- **Whisper**: Can send private messages
- **Text Message**: Can send text messages

**Advanced Permissions:**
- **Mute**: Can mute other users
- **Deafen**: Can deafen other users
- **Kick**: Can kick users from server
- **Ban**: Can ban users from server

## How FGCom-mumble Channels Work

### 1. FGCom-mumble Channel Purpose

**The `fgcom-mumble` channel is special because:**
- It's where radio communication happens
- FGCom-mumble bots connect to this channel
- Users simulate radio communication
- Realistic radio propagation is simulated

### 2. How Radio Communication Works

**In FGCom-mumble:**
1. **Users join the channel** (like tuning to a radio frequency)
2. **Bots provide radio services** (recording, playback, status)
3. **Radio propagation is simulated** (distance, terrain, weather)
4. **Users can only hear nearby users** (realistic radio range)

### 3. Channel Structure for FGCom-mumble

```
Root Channel
├── fgcom-mumble (Main radio communication)
│   ├── Users communicate here
│   ├── Bots provide services
│   └── Radio propagation simulation
└── fgcom-mumble-admins (Administrative)
    ├── Server administrators
    ├── Bot management
    └── System monitoring
```

### 4. What Happens in fgcom-mumble Channel

**When users join:**
1. **Radio simulation starts** - Users can only hear nearby users
2. **Bots connect** - Recording, playback, and status bots join
3. **Communication begins** - Users can talk like on a radio
4. **Realistic behavior** - Distance, terrain, and weather affect communication

**Bot Services:**
- **Recording Bot**: Records radio communications
- **Playback Bot**: Plays back recorded communications
- **Status Bot**: Provides system status and information

### 5. Channel Access Control

**fgcom-mumble Channel:**
- **Open to all users** - Anyone can join
- **Radio communication** - Users can speak and listen
- **Bot services** - Recording and playback available

**fgcom-mumble-admins Channel:**
- **Restricted to admins** - Only administrators can join
- **Server management** - Administrative discussions
- **Bot control** - Start/stop/restart bots

## Permission System Explained

### 1. Understanding Permissions

**Permissions control what users can do:**
- **+permission** = Allow this permission
- **-permission** = Deny this permission
- **@group** = Apply to a group of users
- **@all** = Apply to all users

### 2. Basic Permission Examples

**Allow all users to enter and speak:**
```ini
@all:+enter,+traverse,+speak,+whisper,+textmessage
```

**Restrict channel to admins only:**
```ini
@admin:+enter,+traverse,+speak,+whisper,+textmessage
@all:-enter,-traverse,-speak,-whisper,-textmessage
```

**Allow users to enter but not speak:**
```ini
@all:+enter,+traverse,-speak,+whisper,+textmessage
```

### 3. Setting Up Channel Permissions

**Using Mumble Client:**
1. Right-click on channel
2. Select "Edit"
3. Go to "Permissions" tab
4. Add permission rules
5. Click "OK"

**Using Configuration File:**
```ini
# In /etc/mumble/mumble-server.ini
[acl]
# Channel 12 (fgcom-mumble) - Open to all
12=@all:+enter,+traverse,+speak,+whisper,+textmessage

# Channel 13 (fgcom-mumble-admins) - Admin only
13=@admin:+enter,+traverse,+speak,+whisper,+textmessage
13=@all:-enter,-traverse,-speak,-whisper,-textmessage
```

## Authentication Methods

### 1. Password Authentication

**How it works:**
- Users have username and password
- Server checks password when connecting
- Simple and secure

**Setting up:**
```bash
# Register user with password
sudo murmur -ini /etc/mumble/mumble-server.ini -supw username password
```

### 2. Certificate Authentication

**How it works:**
- Users have digital certificates
- More secure than passwords
- Can be used for automated systems

**Setting up:**
```bash
# Generate user certificate
openssl req -new -x509 -keyout user.key -out user.crt -days 365 -nodes

# Add certificate to user
sudo murmur -ini /etc/mumble/mumble-server.ini -addcert username user.crt
```

### 3. Server Password

**How it works:**
- Server has a password
- Users need this password to connect
- Additional security layer

**Setting up:**
```ini
# In /etc/mumble/mumble-server.ini
serverpassword=your_server_password
```

## Common Tasks

### 1. Adding a New User

**Step 1: Register User**
```bash
sudo murmur -ini /etc/mumble/mumble-server.ini -supw newuser newpassword
```

**Step 2: Set Permissions**
- Connect as admin
- Right-click user → "Edit"
- Set appropriate permissions
- Click "OK"

### 2. Creating a New Channel

**Using Mumble Client:**
1. Right-click in channel list
2. Select "Add Channel"
3. Enter channel name
4. Set permissions
5. Click "OK"

**Using Configuration:**
```ini
# In /etc/mumble/mumble-server.ini
[channels]
14=my_new_channel

[acl]
14=@all:+enter,+traverse,+speak,+whisper,+textmessage
```

### 3. Changing User Permissions

**Using Mumble Client:**
1. Right-click on user
2. Select "Edit"
3. Change permissions
4. Click "OK"

**Using Configuration:**
```ini
# In /etc/mumble/mumble-server.ini
[user_permissions]
username=+enter,+traverse,+speak
```

### 4. Backing Up User Data

**Backup database:**
```bash
sudo cp /var/lib/mumble-server/mumble-server.sqlite /backup/mumble-backup.sqlite
```

**Restore database:**
```bash
sudo cp /backup/mumble-backup.sqlite /var/lib/mumble-server/mumble-server.sqlite
sudo systemctl restart mumble-server
```

## Troubleshooting

### 1. User Cannot Connect

**Check server status:**
```bash
sudo systemctl status mumble-server
```

**Check server logs:**
```bash
sudo journalctl -u mumble-server -f
```

**Test connection:**
```bash
telnet localhost 64738
```

### 2. Permission Denied

**Check user registration:**
```bash
sudo murmur -ini /etc/mumble/mumble-server.ini -list | grep username
```

**Check channel permissions:**
- Right-click channel → "Edit"
- Check "Permissions" tab
- Verify user has correct permissions

### 3. Channel Not Working

**Check channel configuration:**
```bash
grep -A 10 "\[channels\]" /etc/mumble/mumble-server.ini
```

**Restart server:**
```bash
sudo systemctl restart mumble-server
```

### 4. Bot Connection Issues

**Check bot logs:**
```bash
sudo journalctl -u fgcom-mumble -f
```

**Check channel exists:**
- Connect to server
- Verify `fgcom-mumble` channel exists
- Check bot permissions

### 5. Common Error Messages

**"Connection refused"**
- Server not running
- Wrong port number
- Firewall blocking connection

**"Authentication failed"**
- Wrong username/password
- User not registered
- Server password required

**"Permission denied"**
- User lacks permissions
- Channel access restricted
- User not in correct group

## Getting Help

### 1. Check Logs
```bash
# Server logs
sudo journalctl -u mumble-server -f

# FGCom-mumble logs
sudo journalctl -u fgcom-mumble -f
```

### 2. Test Configuration
```bash
# Test server configuration
sudo murmur -ini /etc/mumble/mumble-server.ini -check
```

### 3. Verify Services
```bash
# Check if services are running
sudo systemctl status mumble-server
sudo systemctl status fgcom-mumble
```

### 4. Documentation
- Read this guide completely
- Check `/usr/share/fgcom-mumble/docs/MUMBLE_USER_MANAGEMENT_GUIDE.md`
- Review server configuration files

## Summary

**Mumble user management involves:**
1. **Understanding concepts** - Server, client, users, channels
2. **Setting up users** - Registration, passwords, permissions
3. **Managing channels** - Creation, permissions, organization
4. **Configuring permissions** - Who can do what
5. **Troubleshooting** - Common issues and solutions

**For FGCom-mumble specifically:**
- **fgcom-mumble channel** - Main radio communication
- **fgcom-mumble-admins channel** - Administrative functions
- **Automatic channel creation** - Channels created on server start
- **Bot integration** - Recording, playback, and status services

This guide should give you everything you need to manage Mumble users and channels effectively!
