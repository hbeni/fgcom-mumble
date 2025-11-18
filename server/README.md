# Server Components Documentation

This directory contains all server-side components for the FGcom-Mumble project, including the main server, API endpoints, bot management, and status monitoring.

## Server Components Overview

### Core Server Files

#### `fgcom-botmanager.sh`
**Purpose**: Bot management script for controlling FGcom-Mumble server bots.

**Features**:
- Bot lifecycle management
- Automatic bot startup/shutdown
- Bot health monitoring
- Configuration management
- Error handling and recovery

**Usage**:
```bash
# Start bot manager
./fgcom-botmanager.sh start

# Stop bot manager
./fgcom-botmanager.sh stop

# Check bot status
./fgcom-botmanager.sh status

# Restart bots
./fgcom-botmanager.sh restart
```

#### `fgcom-radio-playback.bot.lua`
**Purpose**: Mumble bot for radio playback functionality.

**Features**:
- Radio frequency playback
- Audio stream management
- Channel management
- User interaction
- Playback controls

**Configuration**:
```lua
-- Bot configuration
local config = {
    server = "localhost",
    port = 64738,
    username = "RadioPlaybackBot",
    password = "bot_password",
    channels = {
        "Radio Playback",
        "ATIS",
        "Weather"
    }
}
```

#### `fgcom-radio-recorder.bot.lua`
**Purpose**: Mumble bot for radio recording functionality.

**Features**:
- Radio frequency recording
- Audio stream capture
- File management
- Recording controls
- Quality settings

**Configuration**:
```lua
-- Recording configuration
local config = {
    server = "localhost",
    port = 64738,
    username = "RadioRecorderBot",
    password = "bot_password",
    recording_path = "/var/recordings/",
    quality = "high",
    format = "wav"
}
```

#### `fgcom-sharedFunctions.inc.lua`
**Purpose**: Shared utility functions for Mumble bots.

**Features**:
- Common bot functions
- Utility functions
- Error handling
- Logging functions
- Configuration helpers

**Usage**:
```lua
-- Include shared functions
require("fgcom-sharedFunctions.inc.lua")

-- Use shared functions
local result = sharedFunctions.validateUser(user)
local log = sharedFunctions.logMessage("Bot started")
```

### API Components

#### `api/fake_moon_api.lua`
**Purpose**: Fake Moon Placement API for satellite simulation.

**Features**:
- Moon placement and management
- Orbital mechanics simulation
- Communication effects
- Doppler shift calculations
- Real-time tracking

**API Endpoints**:
- `POST /api/v1/moon/add` - Add a fake moon
- `GET /api/v1/moon/position/{id}` - Get moon position
- `POST /api/v1/moon/simulate/{id}` - Simulate communication
- `GET /api/v1/moon/list` - List all moons
- `DELETE /api/v1/moon/remove/{id}` - Remove a moon

**Usage**:
```bash
# Start API server
luajit fake_moon_api.lua

# Test API endpoints
curl -X POST http://localhost:8081/api/v1/moon/add \
  -H "Content-Type: application/json" \
  -d '{"name": "Test Moon", "type": "COMMUNICATION"}'
```

### Status Page Components

#### `statuspage/`
**Purpose**: Status page implementation for system monitoring.

**Features**:
- System status monitoring
- Performance metrics
- User statistics
- Health checks
- Alert management

**Configuration**:
```ini
[status_page]
enabled = true
update_interval = 30
show_uptime = true
show_users = true
show_performance = true
alert_threshold = 80
```

### Recordings Management

#### `recordings/`
**Purpose**: Audio recordings storage and management.

**Features**:
- ATIS recordings
- Radio frequency recordings
- Playback management
- File organization
- Quality control

**Directory Structure**:
```
recordings/
├── atis/           # ATIS recordings
├── radio/          # Radio frequency recordings
├── weather/        # Weather recordings
└── archive/        # Archived recordings
```

## Server Configuration

### Main Configuration
```ini
[server]
host = 0.0.0.0
port = 64738
udp_port = 16661
max_users = 200
timeout = 30

[audio]
sample_rate = 48000
channels = 1
bitrate = 64000
quality = high

[security]
tls_enabled = true
certificate = /path/to/cert.pem
private_key = /path/to/key.pem
```

### Bot Configuration
```ini
[bot_manager]
enabled = true
auto_start = true
health_check_interval = 60
max_restart_attempts = 3

[radio_playback_bot]
enabled = true
username = RadioPlaybackBot
password = bot_password
channels = Radio Playback,ATIS,Weather

[radio_recorder_bot]
enabled = true
username = RadioRecorderBot
password = bot_password
recording_path = /var/recordings/
```

## API Documentation

### Fake Moon API

#### Add Moon
```bash
curl -X POST http://localhost:8081/api/v1/moon/add \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Test Moon",
    "type": "COMMUNICATION",
    "orbital_parameters": {
      "semi_major_axis": 384400,
      "eccentricity": 0.0549,
      "inclination": 5.145
    },
    "frequencies": {
      "uplink": 145.900,
      "downlink": 435.800
    }
  }'
```

#### Get Moon Position
```bash
curl -X GET http://localhost:8081/api/v1/moon/position/FAKE-MOON-1
```

#### Simulate Communication
```bash
curl -X POST http://localhost:8081/api/v1/moon/simulate/FAKE-MOON-1 \
  -H "Content-Type: application/json" \
  -d '{
    "ground_station": {
      "latitude": 40.7128,
      "longitude": -74.0060,
      "altitude": 0.0
    },
    "audio_data": "base64_encoded_audio",
    "effects": {
      "doppler_shift": true,
      "signal_degradation": true
    }
  }'
```

## Server Management

### Starting the Server
```bash
# Start main server
./fgcom-botmanager.sh start

# Start with specific configuration
./fgcom-botmanager.sh start --config custom.conf

# Start in background
./fgcom-botmanager.sh start --daemon
```

### Monitoring the Server
```bash
# Check server status
./fgcom-botmanager.sh status

# View server logs
tail -f logs/server.log

# Check bot status
./fgcom-botmanager.sh bot-status

# Monitor performance
./fgcom-botmanager.sh performance
```

### Stopping the Server
```bash
# Stop server gracefully
./fgcom-botmanager.sh stop

# Force stop
./fgcom-botmanager.sh stop --force

# Stop specific bots
./fgcom-botmanager.sh stop --bot radio-playback
```

## Bot Management

### Bot Lifecycle
1. **Initialization**: Bot configuration and setup
2. **Connection**: Connect to Mumble server
3. **Authentication**: Authenticate with server
4. **Operation**: Perform bot functions
5. **Monitoring**: Health checks and monitoring
6. **Shutdown**: Graceful shutdown

### Bot Configuration
```lua
-- Bot configuration example
local bot_config = {
    server = "localhost",
    port = 64738,
    username = "BotName",
    password = "bot_password",
    channels = {"Channel1", "Channel2"},
    functions = {
        playback = true,
        recording = true,
        atis = true
    }
}
```

### Bot Health Monitoring
```bash
# Check bot health
./fgcom-botmanager.sh health-check

# Restart unhealthy bots
./fgcom-botmanager.sh restart-unhealthy

# View bot logs
./fgcom-botmanager.sh logs --bot radio-playback
```

## Security

### Authentication
- Bot authentication with Mumble server
- API authentication for external access
- User authentication for admin functions
- Certificate-based authentication

### Authorization
- Role-based access control
- Permission management
- Resource access control
- API rate limiting

### Encryption
- TLS encryption for server communication
- Audio stream encryption
- API communication encryption
- Data storage encryption

## Performance

### Optimization
- Multi-threading support
- Memory management
- CPU optimization
- Network optimization
- Audio processing optimization

### Monitoring
- Performance metrics
- Resource usage monitoring
- Bottleneck identification
- Performance tuning
- Capacity planning

## Troubleshooting

### Common Issues

1. **Server won't start**
   ```bash
   # Check configuration
   ./fgcom-botmanager.sh validate-config
   # Check logs
   tail -f logs/server.log
   # Check permissions
   ls -la server/
   ```

2. **Bots not connecting**
   ```bash
   # Check bot configuration
   ./fgcom-botmanager.sh check-bots
   # Check network connectivity
   telnet localhost 64738
   # Check authentication
   ./fgcom-botmanager.sh test-auth
   ```

3. **API not responding**
   ```bash
   # Check API server
   curl http://localhost:8081/health
   # Check API logs
   tail -f logs/api.log
   # Check port availability
   netstat -tlnp | grep 8081
   ```

### Debugging

1. **Verbose logging**
   ```bash
   # Enable verbose logging
   export FGCOM_DEBUG=1
   ./fgcom-botmanager.sh start
   ```

2. **Debug mode**
   ```bash
   # Start in debug mode
   ./fgcom-botmanager.sh start --debug
   ```

3. **Log analysis**
   ```bash
   # Analyze server logs
   grep ERROR logs/server.log
   # Analyze bot logs
   grep ERROR logs/bot.log
   ```

## Best Practices

### Server Management
1. **Regular monitoring**: Monitor server health regularly
2. **Backup configuration**: Backup configuration files
3. **Update management**: Keep server components updated
4. **Security updates**: Apply security updates promptly
5. **Performance tuning**: Optimize server performance

### Bot Management
1. **Health checks**: Implement regular health checks
2. **Error handling**: Implement proper error handling
3. **Logging**: Maintain comprehensive logging
4. **Monitoring**: Monitor bot performance
5. **Recovery**: Implement automatic recovery

## Future Enhancements

- Advanced bot management
- Real-time monitoring
- Automated scaling
- Advanced security features
- Performance optimization

## Support

For server issues:
1. Check server logs in `logs/`
2. Review configuration files
3. Verify network connectivity
4. Check system resources
5. Review documentation
