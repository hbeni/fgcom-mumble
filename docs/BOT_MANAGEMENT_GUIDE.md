# FGcom-mumble Bot Management Guide

This guide explains how to configure and manage the various bots in the FGcom-mumble system.

## Bot Overview

The FGcom-mumble system uses three types of bots:

1. **Recorder Bot** - Records radio traffic continuously
2. **Playback Bots** - Play back recorded radio samples on-demand
3. **Status Bot** - Provides system status and web interface

## Default Configuration

By default, only the recorder bot runs automatically. This is the most efficient configuration for most use cases.

- **Recorder Bot**: Always enabled (runs continuously)
- **Playback Bots**: Disabled by default (start on-demand when recordings are made)
- **Status Bot**: Disabled by default (optional for web interface)

## Enabling Additional Bots

### Enable Playback Bots

Playback bots are recommended for production environments as they improve performance by pre-spawning bots for recordings.

```bash
# Edit the systemd service
sudo systemctl edit fgcom-mumble

# Add the following content:
[Service]
Environment="FGCOM_RUN_PLAYBACK=1"

# Reload and restart the service
sudo systemctl daemon-reload
sudo systemctl restart fgcom-mumble
```

### Enable Status Bot

The status bot provides web interface functionality and system statistics.

```bash
# Edit the systemd service
sudo systemctl edit fgcom-mumble

# Add the following content:
[Service]
Environment="FGCOM_RUN_STATUS=1"

# Reload and restart the service
sudo systemctl daemon-reload
sudo systemctl restart fgcom-mumble
```

### Enable Both Playback and Status Bots

For full functionality, enable both bots:

```bash
# Edit the systemd service
sudo systemctl edit fgcom-mumble

# Add the following content:
[Service]
Environment="FGCOM_RUN_PLAYBACK=1"
Environment="FGCOM_RUN_STATUS=1"

# Reload and restart the service
sudo systemctl daemon-reload
sudo systemctl restart fgcom-mumble
```

## Bot Behavior Details

### Recorder Bot

**Purpose**: Records radio traffic continuously
**Default**: Always enabled
**Behavior**: 
- Runs 24/7
- Records all radio communications
- Sends notifications when recordings are complete
- Automatically reconnects on failure

**Configuration**:
- Log file: `/var/log/fgcom-mumble/radio-recorder.log`
- Recording path: `/var/lib/fgcom-mumble/recordings`
- Time limit: 120 seconds per recording
- TTL: 7200 seconds (2 hours)

### Playback Bots

**Purpose**: Plays back recorded radio samples
**Default**: Disabled (start on-demand)
**Behavior**:
- Start automatically when recordings are made
- Spawn new instances for each recording
- Automatically terminate when playback completes
- Prevent duplicate instances for same sample
- Support multiple concurrent playbacks

**Configuration**:
- Log file: `/var/log/fgcom-mumble/radio-playback.log`
- Sample path: `/var/lib/fgcom-mumble/recordings`
- Auto-termination after TTL expires

### Status Bot

**Purpose**: Provides web status page and statistics
**Default**: Disabled
**Behavior**:
- Provides system status information
- Can generate usage statistics
- Advertises status page URL in Mumble comment
- Maintains database of system statistics

**Configuration**:
- Log file: `/var/log/fgcom-mumble/status.log`
- Database: `/var/lib/fgcom-mumble/fgcom-web.db`
- Web interface: Optional URL advertisement

## Bot Management Commands

### Check Bot Status

```bash
# Check which bots are running
./scripts/status_fgcom_mumble.sh

# Check systemd service status
systemctl status fgcom-mumble

# Check individual bot processes
ps aux | grep fgcom-radio-recorder
ps aux | grep fgcom-radio-playback
ps aux | grep fgcom-status
```

### View Bot Logs

```bash
# View all bot logs
journalctl -u fgcom-mumble -f

# View specific bot logs
tail -f /var/log/fgcom-mumble/radio-recorder.log
tail -f /var/log/fgcom-mumble/radio-playback.log
tail -f /var/log/fgcom-mumble/status.log

# View recent log entries
journalctl -u fgcom-mumble -n 50
```

### Manual Bot Control

```bash
# Start bots manually (for testing)
cd /usr/share/fgcom-mumble/scripts/server
./fgcom-botmanager.sh --help

# Start with all bots enabled
./fgcom-botmanager.sh --host=localhost --port=64738 --channel=fgcom-mumble

# Start with specific bots
./fgcom-botmanager.sh --noplay --nostatus  # Recorder only
./fgcom-botmanager.sh --nostatus          # Recorder + Playback
./fgcom-botmanager.sh                     # All bots
```

## Production Recommendations

### Basic Setup (Default)
- Keep default configuration (recorder bot only)
- Playback bots will start automatically when needed
- Minimal resource usage
- Suitable for small to medium servers

### Production with Web Interface
- Enable status bot for web status page
- Consider enabling playback bots for better performance
- Monitor resource usage
- Suitable for servers with web interface requirements

### High-Traffic Servers
- Enable both playback and status bots
- Monitor bot performance and adjust as needed
- Consider running bots on separate servers for load distribution
- Implement monitoring and alerting
- Suitable for large-scale deployments

## Troubleshooting

### Bots Not Starting

```bash
# Check service status
systemctl status fgcom-mumble

# Check logs for errors
journalctl -u fgcom-mumble -n 50

# Verify certificates
ls -la /etc/fgcom-mumble/*.pem
ls -la /etc/fgcom-mumble/*.key

# Check environment variables
systemctl show fgcom-mumble | grep Environment
```

### Playback Bots Not Spawning

```bash
# Check FIFO file
ls -la /tmp/fgcom-fnotify-fifo

# Test notification manually
echo "test_sample.wav|12345" > /tmp/fgcom-fnotify-fifo

# Check playback bot configuration
grep -r "run_playbackbot" /usr/share/fgcom-mumble/scripts/
```

### Status Bot Not Working

```bash
# Check database permissions
ls -la /var/lib/fgcom-mumble/fgcom-web.db

# Check web interface configuration
grep -r "sweb" /usr/share/fgcom-mumble/scripts/

# Check status bot logs
tail -f /var/log/fgcom-mumble/status.log
```

### Performance Issues

```bash
# Monitor bot resource usage
top -p $(pgrep -f fgcom-radio)

# Check disk space
df -h /var/lib/fgcom-mumble/recordings

# Monitor network connections
netstat -tulpn | grep 64738
```

## Advanced Configuration

### Custom Bot Parameters

You can customize bot behavior by modifying the systemd service:

```bash
# Edit the service with custom parameters
sudo systemctl edit fgcom-mumble

# Add custom environment variables
[Service]
Environment="FGCOM_RUN_PLAYBACK=1"
Environment="FGCOM_RUN_STATUS=1"
Environment="FGCOM_DEBUG=1"
Environment="FGCOM_RECORDING_LIMIT=300"
Environment="FGCOM_TTL=10800"
```

### Load Balancing

For high-traffic servers, consider running bots on separate servers:

1. **Main Server**: Mumble server + Recorder bot
2. **Bot Server**: Playback bots + Status bot
3. **Web Server**: Status page + Database

### Monitoring and Alerting

Implement monitoring for bot health:

```bash
# Create monitoring script
cat > /usr/local/bin/fgcom-monitor.sh << 'EOF'
#!/bin/bash
# Check if bots are running
if ! pgrep -f fgcom-radio-recorder > /dev/null; then
    echo "ALERT: Recorder bot not running"
    systemctl restart fgcom-mumble
fi
EOF

chmod +x /usr/local/bin/fgcom-monitor.sh

# Add to crontab for regular monitoring
echo "*/5 * * * * /usr/local/bin/fgcom-monitor.sh" | crontab -
```

## Security Considerations

- Bot certificates are automatically generated and secured
- Bots run with limited privileges under `fgcom-mumble` user
- Database files are protected with appropriate permissions
- FIFO communication is restricted to local system
- Regular certificate rotation is recommended for production

## Maintenance

### Regular Maintenance Tasks

1. **Monitor disk space** for recordings directory
2. **Check bot logs** for errors or warnings
3. **Verify certificates** are valid and not expired
4. **Clean old recordings** based on TTL settings
5. **Update system** and restart services as needed

### Backup Recommendations

- Backup bot certificates: `/etc/fgcom-mumble/`
- Backup recordings: `/var/lib/fgcom-mumble/recordings`
- Backup database: `/var/lib/fgcom-mumble/fgcom-web.db`
- Backup configuration: `/etc/mumble/mumble-server.ini`

This guide provides comprehensive information for managing FGcom-mumble bots in production environments.
