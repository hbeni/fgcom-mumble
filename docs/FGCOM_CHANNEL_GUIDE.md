# FGCom-mumble Channel Guide

**Complete guide to understanding and using FGCom-mumble channels**

## Table of Contents

1. [What is FGCom-mumble?](#what-is-fgcom-mumble)
2. [How FGCom-mumble Channels Work](#how-fgcom-mumble-channels-work)
3. [Channel Structure and Organization](#channel-structure-and-organization)
4. [Radio Communication Simulation](#radio-communication-simulation)
5. [Bot Services and Integration](#bot-services-and-integration)
6. [User Experience](#user-experience)
7. [Administrative Functions](#administrative-functions)
8. [Troubleshooting](#troubleshooting)

## What is FGCom-mumble?

**FGCom-mumble** is a radio communication simulation system that:
- **Simulates realistic radio communication** between users
- **Models radio propagation** (distance, terrain, weather effects)
- **Provides radio services** (recording, playback, status)
- **Integrates with flight simulators** (FlightGear, X-Plane, etc.)
- **Supports amateur radio bands** (HF, VHF, UHF)
- **Includes Morse code training** capabilities

**Think of it as:**
- **Real radio communication** - Users can only hear nearby users
- **Flight simulation integration** - Works with flight simulators
- **Amateur radio support** - Supports ham radio frequencies
- **Training system** - Learn radio communication skills

## How FGCom-mumble Channels Work

### 1. Channel Purpose

**The `fgcom-mumble` channel is the heart of the system:**
- **Radio communication hub** - Where all radio traffic happens
- **Bot integration point** - Bots provide radio services
- **User interaction** - Users communicate like on real radio
- **Simulation engine** - Radio propagation is simulated

### 2. Channel Behavior

**When users join the channel:**
1. **Radio simulation starts** - Users can only hear nearby users
2. **Bots connect automatically** - Recording, playback, status bots join
3. **Communication begins** - Users can talk like on a radio
4. **Realistic behavior** - Distance, terrain, and weather affect communication

**Key Features:**
- **Distance-based communication** - Users can only hear nearby users
- **Terrain effects** - Mountains, buildings affect radio range
- **Weather simulation** - Atmospheric conditions affect communication
- **Frequency management** - Different frequencies for different purposes

### 3. Radio Propagation Simulation

**How it works:**
- **User positions** - Tracked from flight simulator or manual input
- **Distance calculation** - Radio range based on user positions
- **Terrain analysis** - Mountains, buildings block radio signals
- **Weather effects** - Atmospheric conditions affect propagation
- **Frequency characteristics** - Different bands have different ranges

**Example:**
- **User A** (New York) and **User B** (London) are too far apart
- **User A** can only hear users within 1000km
- **User B** can only hear users within 1000km
- **Users C and D** (both in Europe) can hear each other

## Channel Structure and Organization

### 1. Main Channel Structure

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

### 2. Sub-channel Organization (Optional)

```
fgcom-mumble
├── fgcom-mumble-nyc (New York airspace)
├── fgcom-mumble-london (London airspace)
├── fgcom-mumble-europe (European airspace)
└── fgcom-mumble-training (Training exercises)
```

### 3. Channel Access Control

**fgcom-mumble Channel:**
- **Open to all users** - Anyone can join
- **Radio communication** - Users can speak and listen
- **Bot services** - Recording and playback available
- **Simulation active** - Radio propagation is simulated

**fgcom-mumble-admins Channel:**
- **Restricted to admins** - Only administrators can join
- **Server management** - Administrative discussions
- **Bot control** - Start/stop/restart bots
- **System monitoring** - Server status and performance

## Radio Communication Simulation

### 1. How Radio Range Works

**Distance-based Communication:**
- **Users can only hear nearby users** - Realistic radio range
- **Range depends on frequency** - HF has longer range than VHF
- **Terrain affects range** - Mountains, buildings block signals
- **Weather affects range** - Atmospheric conditions matter

**Example Ranges:**
- **HF (3-30 MHz)**: 1000-3000km (long distance)
- **VHF (30-300 MHz)**: 100-500km (local/regional)
- **UHF (300-3000 MHz)**: 10-100km (local)

### 2. Terrain Effects

**How terrain affects radio:**
- **Mountains block signals** - Radio waves can't penetrate
- **Buildings block signals** - Urban areas have limited range
- **Water reflects signals** - Ocean can extend range
- **Valleys focus signals** - Radio waves can be channeled

### 3. Weather Effects

**How weather affects radio:**
- **Atmospheric conditions** - Temperature, humidity affect propagation
- **Ionospheric conditions** - Solar activity affects HF propagation
- **Tropospheric ducting** - Weather can extend VHF range
- **Precipitation** - Rain, snow can block signals

### 4. Frequency Management

**Different frequencies for different purposes:**
- **Emergency frequencies** - 121.5 MHz (emergency)
- **Air traffic control** - 118-137 MHz (ATC)
- **Amateur radio** - Various bands (HF, VHF, UHF)
- **Military frequencies** - Secure communications

## Bot Services and Integration

### 1. Recording Bot

**What it does:**
- **Records radio communications** - Saves all voice traffic
- **Time-stamped recordings** - Each recording has timestamp
- **Automatic cleanup** - Old recordings are deleted
- **Quality control** - Ensures good audio quality

**How it works:**
- **Connects to fgcom-mumble channel** - Listens to all traffic
- **Records all audio** - Saves voice communications
- **Stores recordings** - Saves to `/usr/share/fgcom-mumble/recordings/`
- **Manages storage** - Deletes old recordings automatically

### 2. Playback Bot

**What it does:**
- **Plays back recordings** - Users can hear past communications
- **On-demand playback** - Users can request specific recordings
- **Training support** - Helps users learn radio procedures
- **Historical analysis** - Review past communications

**How it works:**
- **Connects to fgcom-mumble channel** - Provides playback service
- **Receives playback requests** - Users can request recordings
- **Plays back audio** - Streams recordings to users
- **Manages requests** - Handles multiple playback requests

### 3. Status Bot

**What it does:**
- **Provides system status** - Server health, bot status
- **User statistics** - Number of users, activity levels
- **Performance monitoring** - Server performance metrics
- **Web interface** - Status page for administrators

**How it works:**
- **Connects to fgcom-mumble channel** - Monitors system
- **Collects statistics** - Tracks user activity, system performance
- **Provides status updates** - Regular status reports
- **Web interface** - Administrators can view status online

## User Experience

### 1. Joining the Channel

**What users experience:**
1. **Connect to Mumble server** - Standard Mumble connection
2. **Join fgcom-mumble channel** - Click on channel name
3. **Radio simulation starts** - Can only hear nearby users
4. **Bot services available** - Recording, playback, status

### 2. Radio Communication

**How users communicate:**
- **Push-to-talk** - Hold key to speak (like real radio)
- **Realistic range** - Can only hear nearby users
- **Terrain effects** - Mountains, buildings affect communication
- **Weather effects** - Atmospheric conditions matter

### 3. Bot Interaction

**How users interact with bots:**
- **Recording requests** - Ask for specific recordings
- **Playback requests** - Request playback of recordings
- **Status inquiries** - Ask about system status
- **Training support** - Get help with radio procedures

## Administrative Functions

### 1. Bot Management

**Administrators can:**
- **Start/stop bots** - Control bot services
- **Monitor bot status** - Check if bots are running
- **Configure bot settings** - Adjust bot behavior
- **View bot logs** - Troubleshoot bot issues

### 2. User Management

**Administrators can:**
- **Add/remove users** - Manage user accounts
- **Set permissions** - Control user access
- **Monitor activity** - Track user behavior
- **Manage channels** - Create/modify channels

### 3. System Monitoring

**Administrators can:**
- **View system status** - Server health, performance
- **Monitor user activity** - Number of users, activity levels
- **Check bot status** - Ensure bots are running
- **Review logs** - Troubleshoot issues

## Troubleshooting

### 1. Channel Not Working

**Check if channel exists:**
```bash
# Connect to server and check channels
mumble localhost 64738
```

**Check channel configuration:**
```bash
grep -A 10 "\[channels\]" /etc/mumble/mumble-server.ini
```

### 2. Bot Connection Issues

**Check bot status:**
```bash
sudo systemctl status fgcom-mumble
```

**Check bot logs:**
```bash
sudo journalctl -u fgcom-mumble -f
```

**Verify channel exists:**
- Connect to server
- Check if `fgcom-mumble` channel exists
- Verify bot permissions

### 3. Radio Simulation Not Working

**Check user positions:**
- Ensure users have valid positions
- Check if flight simulator is connected
- Verify position data is being received

**Check propagation settings:**
- Verify radio propagation is enabled
- Check terrain data is available
- Ensure weather data is current

### 4. Common Issues

**Users can't hear each other:**
- Check if users are within radio range
- Verify terrain isn't blocking signals
- Ensure weather conditions allow communication

**Bots not responding:**
- Check if bots are running
- Verify bot permissions
- Check bot logs for errors

**Channel access denied:**
- Verify user permissions
- Check channel access control
- Ensure user is registered

## Best Practices

### 1. Channel Management

**Organize channels logically:**
- Use clear, descriptive names
- Group related channels together
- Set appropriate permissions
- Regular maintenance and cleanup

### 2. User Experience

**Provide clear instructions:**
- Document how to use the system
- Provide training materials
- Offer support and help
- Regular updates and improvements

### 3. System Maintenance

**Regular monitoring:**
- Check system status regularly
- Monitor bot performance
- Review user activity
- Update system components

### 4. Security

**Protect system:**
- Use strong passwords
- Regular security updates
- Monitor for unauthorized access
- Backup important data

## Summary

**FGCom-mumble channels provide:**
- **Realistic radio communication** - Distance-based, terrain-affected
- **Bot services** - Recording, playback, status
- **User interaction** - Push-to-talk, realistic behavior
- **Administrative control** - Bot management, user control

**Key benefits:**
- **Realistic simulation** - Like real radio communication
- **Training support** - Learn radio procedures
- **Integration** - Works with flight simulators
- **Flexibility** - Supports various radio bands

This system provides a complete radio communication simulation environment that's both realistic and educational!
