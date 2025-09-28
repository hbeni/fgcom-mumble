# FGCom-mumble Technical Setup Guide

## Overview

This guide provides honest, comprehensive setup instructions for FGCom-mumble. **This system requires significant technical knowledge and server administration skills.**

## Prerequisites

### **Technical Requirements**
- **Server Administration**: Linux/Windows server management experience
- **Network Configuration**: Understanding of UDP/TCP ports and firewall configuration
- **Radio Knowledge**: Basic understanding of amateur radio frequencies and propagation
- **System Administration**: Command line interface and configuration file management

### **System Requirements**
- **Operating System**: Linux (recommended), Windows, or macOS
- **CPU**: Multi-core processor (4+ cores recommended)
- **Memory**: 4GB RAM minimum, 8GB+ recommended
- **Network**: Stable internet connection with configurable ports
- **Storage**: 2GB+ for installation and data

### **Software Dependencies**
- **Mumble Server**: >= v1.4.0 (Murmur)
- **Mumble Client**: Latest version
- **C++ Compiler**: GCC 7+ or Clang 5+ (for building from source)
- **OpenSSL**: 1.1.1+ for security features
- **CMake**: 3.10+ for building
- **LuaJIT**: 5.1 interpreter (for server bots)
- **Python**: 3.6+ (for client examples)

## Server Setup

### **Step 1: Install Mumble Server**

**Linux (Ubuntu/Debian):**
```bash
sudo apt-get update
sudo apt-get install mumble-server
sudo systemctl enable mumble-server
sudo systemctl start mumble-server
```

**Linux (CentOS/RHEL):**
```bash
sudo yum install mumble-server
sudo systemctl enable mumble-server
sudo systemctl start mumble-server
```

**Windows:**
- Download Mumble server from official website
- Install and configure as Windows service
- Configure firewall rules for ports 64738 (TCP/UDP)

### **Step 2: Configure Mumble Server**

**Edit server configuration:**
```bash
sudo nano /etc/mumble-server.ini
```

**Required settings:**
```ini
# Server settings
host=0.0.0.0
port=64738
users=100
maxbandwidth=72000000
welcometext="Welcome to FGCom-mumble server"

# Security settings
serverpassword=
allowping=true
opusthreshold=100
channelnestinglimit=10
defaultchannel=fgcom-mumble
rememberchannel=true
```

### **Step 3: Create FGCom-mumble Channels**

**Channel Structure:**
- Create channel: `fgcom-mumble`
- Create subchannels for different airspaces
- Set appropriate permissions for each channel

### **Step 4: Install Server Bots (Optional but Recommended)**

**Install LuaJIT:**
```bash
sudo apt-get install luajit lua5.1 lua-bitop
```

**Install Lua Mumble support:**
```bash
git clone https://github.com/bkacjios/lua-mumble.git
cd lua-mumble
make
sudo cp mumble.so /usr/lib/x86_64-linux-gnu/lua/5.1/
```

**Start bot manager:**
```bash
./fgcom-botmanager.sh
```

## Client Setup

### **Step 1: Install Mumble Client**

**Download and install Mumble client from official website**

### **Step 2: Install FGCom-mumble Plugin**

**Method 1: GUI Installation (Recommended)**
1. Start Mumble
2. Go to Configure → Settings → Plugins
3. Click "Install plugin"
4. Select the `.mumble_plugin` file
5. Activate the FGCom-mumble plugin

**Method 2: Manual Installation**
1. Extract the `.mumble_plugin` file (rename to .zip)
2. Copy the appropriate library to Mumble's plugins folder:
   - Linux: `fgcom-mumble.so`
   - Windows: `fgcom-mumble.dll`
   - macOS: `fgcom-mumble-macOS.bundle`

### **Step 3: Configure Plugin**

**Create configuration file:**
```bash
# Linux
nano ~/.fgcom-mumble.ini

# Windows
notepad %USERPROFILE%\fgcom-mumble.ini
```

**Basic configuration:**
```ini
[general]
# UDP port for communication
udp_port = 16661

# Channel name pattern (must start with fgcom-mumble)
channel_pattern = fgcom-mumble

# Audio effects
enable_audio_effects = true
enable_noise_reduction = true

# Debug settings
debug_level = 1
enable_udp_logging = true
```

### **Step 4: Connect to Server**

1. **Connect to Mumble server**
2. **Join channel starting with `fgcom-mumble`**
3. **Configure radio settings** (frequencies, power, location)
4. **Test communication** with other users

## Game Integration

### **FlightGear (Native Support)**

**Installation:**
1. Download FGCom-mumble addon
2. Add to FlightGear launcher
3. Activate addon
4. Configure radio settings in-game

**Usage:**
- Default keys: Space (COM1), Shift+Space (COM2), Alt+Space (COM3), Ctrl+Space (Intercom)
- Automatic frequency detection from aircraft radios
- Real-time position and altitude tracking

### **Microsoft Flight Simulator 2020 (RadioGUI)**

**Setup:**
1. Install RadioGUI (Java application)
2. Configure SimConnect connection
3. Set up SimConnect.xml file
4. Connect RadioGUI to Mumble server

**SimConnect Configuration:**
```xml
<SimConnect.Comm>
  <Descr>Global IP Port</Descr>
  <Disabled>False</Disabled>
  <Protocol>IPv4</Protocol>
  <Scope>global</Scope>
  <Address>127.0.0.1</Address>
  <MaxClients>64</MaxClients>
  <Port>7421</Port>
  <MaxRecvSize>4096</MaxRecvSize>
  <DisableNagle>False</DisableNagle>
</SimConnect.Comm>
```

### **Other Games (Manual Integration)**

**For games without native support:**
1. Run Mumble alongside your game
2. Manually set radio frequencies
3. Coordinate with other players
4. Use external voice chat for communication

## Advanced Configuration

### **Server Configuration (625+ Options)**

**Main configuration file:**
```bash
cp configs/fgcom-mumble.conf.example fgcom-mumble.conf
nano fgcom-mumble.conf
```

**Key configuration sections:**
- **Amateur Radio**: 60+ options for band plans, power limits, ITU regions
- **Terrain Elevation**: 40+ options for elevation data sources
- **Solar Data**: 20+ options for NOAA/SWPC integration
- **Propagation**: 30+ options for radio wave modeling
- **Antenna System**: 40+ options for antenna patterns
- **API Server**: 20+ options for RESTful API
- **Audio Processing**: 15+ options for audio effects
- **Logging**: 15+ options for debug and monitoring
- **Performance**: 20+ options for threading and caching
- **GPU Resource Limiting**: 25+ options for GPU management

### **Radio Configuration**

**Frequency Setup:**
- Manual frequency entry (MHz)
- Band compliance checking
- Power limit validation
- Mode validation (CW vs SSB)

**Location Setup:**
- Latitude/longitude coordinates
- Altitude above sea level
- Antenna height
- Ground system configuration

### **Network Configuration**

**UDP Ports:**
- Default: 16661 (configurable)
- Firewall configuration required
- Port forwarding for external access

**Channel Management:**
- Channel naming convention
- Permission settings
- User management

## Troubleshooting

### **Common Issues**

**Plugin not loading:**
- Check Mumble version compatibility
- Verify plugin file integrity
- Check file permissions

**Connection issues:**
- Verify server configuration
- Check firewall settings
- Test UDP port connectivity

**Audio problems:**
- Check audio device configuration
- Verify PTT settings
- Test microphone levels

**Game integration issues:**
- Verify game-specific setup
- Check SimConnect configuration (MSFS)
- Test FlightGear addon installation

### **Debug Information**

**Enable debug logging:**
```ini
[logging]
enable_file_logging = true
log_level = debug
enable_udp_logging = true
enable_propagation_logging = true
```

**Check logs:**
```bash
# Linux
tail -f /var/log/fgcom-mumble/fgcom-mumble.log

# Windows
type %USERPROFILE%\fgcom-mumble.log
```

## Security Considerations

### **Server Security**
- Use strong passwords
- Enable SSL/TLS encryption
- Configure firewall rules
- Regular security updates

### **Network Security**
- Use VPN for remote access
- Encrypt sensitive data
- Monitor for abuse
- Implement rate limiting

## Performance Optimization

### **Server Performance**
- Configure thread pools
- Enable caching
- Monitor resource usage
- Optimize database queries

### **Client Performance**
- Adjust audio quality settings
- Configure GPU acceleration
- Monitor memory usage
- Optimize network settings

## Support and Resources

### **Documentation**
- [API Reference](API_REFERENCE_COMPLETE.md)
- [Technical Documentation](TECHNICAL_DOCUMENTATION.md)
- [Amateur Radio Terminology](AMATEUR_RADIO_TERMINOLOGY.md)
- [GPU Resource Limiting Guide](GPU_RESOURCE_LIMITING_GUIDE.md)

### **Community Support**
- GitHub Issues: Report bugs and request features
- Documentation: Comprehensive technical guides
- Examples: Code samples and configuration templates

### **Professional Support**
- For enterprise deployments
- Custom configuration assistance
- Training and consulting services

---

**Important Note**: FGCom-mumble is a complex system requiring significant technical expertise. This is not a "plug and play" solution. Users should have server administration experience and understanding of radio communication principles before attempting installation.
