# FGcom-mumble Installation Guide

This guide provides complete installation instructions for the FGcom-mumble system, including automatic channel creation and bot configuration.

## Prerequisites

- Ubuntu/Debian-based system
- Root access (sudo)
- Internet connection for package installation

## Quick Installation

### 1. Install Mumble Server

```bash
sudo apt update
sudo apt install mumble-server
```

### 2. Run the Installation Script

```bash
cd /path/to/fgcom-mumble
sudo ./scripts/install_fgcom_mumble.sh
```

The installation script will:
- Install required dependencies (luajit, sqlite3, openssl)
- Create system user and group (`fgcom-mumble`)
- Generate bot certificates
- Configure Mumble server
- Create required Mumble channels automatically
- Set up systemd services
- Start all services

## What Gets Installed

### System Components

1. **Mumble Server** - Voice communication server
2. **FGcom-mumble Bots** - Radio simulation bots
3. **Systemd Services** - Automatic startup and management
4. **Database** - SQLite database with channel configuration

### Created Channels

- **fgcom-mumble** (ID: 2) - Main radio communication channel
- **fgcom-mumble-admins** (ID: 1) - Administrative channel

### Generated Certificates

- `recbot.pem/key` - Recording bot certificate
- `playbot.pem/key` - Playback bot certificate  
- `statusbot.pem/key` - Status bot certificate

## Post-Installation

### Check System Status

```bash
sudo ./scripts/install_fgcom_mumble.sh status
```

### View Logs

```bash
# Mumble server logs
sudo journalctl -u mumble-server -f

# FGcom-mumble service logs
sudo journalctl -u fgcom-mumble -f

# Bot-specific logs
sudo tail -f /var/log/fgcom-mumble/*.log
```

### Connect to Mumble Server

1. **Server Address**: `your-server-ip:64738`
2. **Channel**: Join the `fgcom-mumble` channel
3. **No Password Required**: Server is configured for open access

## Manual Channel Creation (if needed)

If the automatic channel creation fails, you can create channels manually:

```bash
sudo python3 scripts/create_fgcom_channels_database.py
```

## Troubleshooting

### Common Issues

#### 1. Mumble Server Not Starting
```bash
sudo systemctl status mumble-server
sudo journalctl -u mumble-server -n 50
```

#### 2. Bots Not Connecting
```bash
sudo systemctl status fgcom-mumble
sudo journalctl -u fgcom-mumble -n 50
```

#### 3. Channel Creation Failed
```bash
# Check if channels exist
sudo sqlite3 /var/lib/mumble-server/fgcom-mumble.sqlite "SELECT * FROM channels;"

# Recreate channels
sudo python3 scripts/create_fgcom_channels_database.py
```

#### 4. Certificate Issues
```bash
# Regenerate certificates
cd /path/to/fgcom-mumble/server
sudo rm *.pem *.key
sudo ./scripts/install_fgcom_mumble.sh
```

### Service Management

```bash
# Start services
sudo systemctl start mumble-server
sudo systemctl start fgcom-mumble

# Stop services
sudo systemctl stop fgcom-mumble
sudo systemctl stop mumble-server

# Restart services
sudo systemctl restart mumble-server
sudo systemctl restart fgcom-mumble

# Enable/disable auto-start
sudo systemctl enable mumble-server
sudo systemctl enable fgcom-mumble
```

## File Locations

### Configuration Files
- Mumble server: `/etc/mumble/mumble-server.ini`
- Systemd service: `/etc/systemd/system/fgcom-mumble.service`

### Data Directories
- Logs: `/var/log/fgcom-mumble/`
- Recordings: `/var/lib/fgcom-mumble/recordings/`
- Database: `/var/lib/mumble-server/fgcom-mumble.sqlite`

### Bot Files
- Scripts: `/path/to/fgcom-mumble/server/`
- Certificates: `/path/to/fgcom-mumble/server/*.pem`

## Security Notes

- Bot certificates are generated with 2048-bit RSA keys
- Private keys are protected with 600 permissions
- Service runs as non-root user (`fgcom-mumble`)
- Systemd security restrictions are applied

## Uninstallation

To remove FGcom-mumble:

```bash
# Stop and disable services
sudo systemctl stop fgcom-mumble
sudo systemctl disable fgcom-mumble
sudo systemctl stop mumble-server
sudo systemctl disable mumble-server

# Remove files
sudo rm -rf /var/log/fgcom-mumble
sudo rm -rf /var/lib/fgcom-mumble
sudo rm -f /etc/systemd/system/fgcom-mumble.service
sudo rm -f /etc/mumble/mumble-server.ini

# Remove user and group
sudo userdel fgcom-mumble
sudo groupdel fgcom-mumble

# Reload systemd
sudo systemctl daemon-reload
```

## Support

For issues and support:
1. Check the logs first
2. Verify all services are running
3. Check network connectivity
4. Review the troubleshooting section above

## Technical Details

### Channel IDs
- Root: 0
- fgcom-mumble-admins: 1  
- fgcom-mumble: 2

### Bot Configuration
- All bots use channel ID 2 (fgcom-mumble)
- Bots connect via SSL with generated certificates
- Automatic reconnection on failure

### Database Schema
The system uses SQLite with the following key tables:
- `channels` - Channel definitions
- `acl` - Access control lists
- `users` - User accounts
- `bans` - Connection bans
