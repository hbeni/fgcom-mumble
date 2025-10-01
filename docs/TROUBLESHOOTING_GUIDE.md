# FGCom-mumble Troubleshooting Guide

**Comprehensive troubleshooting guide for FGCom-mumble installation, configuration, and usage issues**

## Installation Issues

### Plugin Not Loading

**Symptoms:**
- Plugin doesn't appear in Mumble's plugin list
- Mumble crashes when trying to load the plugin
- Plugin appears but doesn't function

**Solutions:**
- Ensure Mumble version is >= 1.4.0
- Check that OpenSSL is properly installed
- Verify the plugin file is not corrupted
- Check Mumble's plugin directory permissions
- Try reinstalling the plugin using the GUI method

**Linux-specific:**
```bash
# Check OpenSSL installation
dpkg -l | grep libssl
sudo apt-get install libssl-dev

# Check Mumble version
mumble --version

# Fix permissions
sudo chown -R $USER:$USER ~/.local/share/mumble/plugins/
```

**Windows-specific:**
- Ensure Visual C++ Redistributable is installed
- Check Windows Defender isn't blocking the plugin
- Run Mumble as administrator if needed

### v2.0+ Features Not Working

**Symptoms:**
- Advanced features not available
- Configuration options missing
- API endpoints not responding

**Solutions:**
- Verify Python 3 is installed and accessible: `python3 --version`
- Check bc calculator is available: `bc --version`
- For GPU acceleration, verify CUDA/OpenCL drivers are installed
- Check configuration files are in correct locations

**Dependency Installation:**

**Linux/Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install python3 bc libssl-dev
# Optional: For GPU acceleration
sudo apt-get install nvidia-cuda-toolkit opencl-headers
```

**Windows:**
- Install Python 3.x from python.org
- Install bc calculator (available via Chocolatey: `choco install bc`)
- Install Visual Studio Build Tools for C++ compilation
- Install CUDA Toolkit (optional, for GPU acceleration)

**macOS:**
```bash
brew install python3 bc openssl
# Optional: For GPU acceleration
brew install cuda
```

### Configuration Issues

**Symptoms:**
- Configuration not loading
- Default values not working
- Feature toggles not responding

**Solutions:**
- Ensure configuration files are in the correct directory (`configs/` not `config/`)
- Check file permissions allow reading configuration files
- Verify INI file syntax is correct (no missing brackets, proper key=value format)
- Check for typos in configuration keys
- Validate configuration using the built-in validator

**Configuration File Locations:**
- Linux: `/etc/mumble/fgcom-mumble.ini`, `<home>/.fgcom-mumble.ini`, `<home>/fgcom-mumble.ini`
- Windows: `<home>\fgcom-mumble.ini`, `<home>\Documents\fgcom-mumble.ini`

## Radio Communication Issues

### Cannot Hear Other Pilots

**Symptoms:**
- No audio from other pilots
- Intermittent audio
- Audio quality issues

**Troubleshooting Steps:**
1. **Check Mumble Connection:**
   - Ensure Mumble is operational (can talk with others in normal channels)
   - Check Mumble's client comment for callsign and radio frequencies
   - Verify you're in the correct channel (starts with `fgcom-mumble`)

2. **Check Radio Configuration:**
   - Verify radio frequencies are correctly tuned
   - Check radio volume and audio panel settings
   - Ensure radio is powered on and serviceable
   - Check that you're not transmitting when expecting incoming messages

3. **Check Range and Signal:**
   - Verify you're within range (low altitude severely limits range)
   - Check for terrain obstructions
   - Ensure proper altitude for the frequency band

4. **Check Plugin Status:**
   - Look at the status webpage to see if your entry is registered
   - Check plugin debug messages (start Mumble from terminal)
   - Verify UDP port configuration

### Cannot Transmit

**Symptoms:**
- PTT not working
- No transmission when pressing PTT
- Transmission not reaching other pilots

**Troubleshooting Steps:**
1. **Check PTT Configuration:**
   - Verify PTT key is correctly mapped
   - Check that PTT is mapped to the correct radio (default is COM1)
   - Test PTT in Mumble's normal voice activation

2. **Check Radio Status:**
   - Ensure radio is operable (powered, switched on, serviceable)
   - Verify radio is tuned to the correct frequency
   - Check that radio is not on `<del>` frequency

3. **Check Plugin Communication:**
   - Verify your flight simulator is sending data to the plugin UDP port
   - Check the port the plugin listens to (shown in Mumble chat window)
   - Ensure plugin is receiving position and radio data

4. **Check Server Status:**
   - Verify server is running and accessible
   - Check for server-side issues in logs
   - Ensure you're connected to the correct server

### Audio Quality Issues

**Symptoms:**
- Poor audio quality
- Static or noise
- Audio dropouts

**Solutions:**
1. **Check Audio Settings:**
   - Verify microphone and speaker settings in Mumble
   - Check audio quality settings
   - Ensure proper audio device selection

2. **Check Radio Effects:**
   - Verify radio audio effects are enabled
   - Check noise floor settings
   - Adjust audio processing parameters

3. **Check Network:**
   - Verify stable internet connection
   - Check for network latency issues
   - Ensure proper firewall configuration

## Server-Side Issues

### Plugin Messages Dropped

**Symptoms:**
- "Dropping plugin message" in server logs
- Out of sync state between clients
- Intermittent communication issues

**Solutions:**
1. **Check Server Configuration:**
   - Verify `pluginmessagelimit` in `murmur.ini` is not too restrictive
   - Check server resource limits
   - Ensure adequate server performance

2. **Check Plugin Issues:**
   - Look for plugin bugs in debug output
   - Verify plugin is working with default settings
   - Check for rapid message generation

3. **Check Network:**
   - Verify network stability
   - Check for packet loss
   - Ensure proper UDP configuration

### Bot Issues

**Symptoms:**
- ATIS bot not responding
- Echo bot not working
- Landline connections failing

**Solutions:**
1. **Check Bot Status:**
   - Verify bots are running on the server
   - Check bot configuration
   - Ensure proper bot permissions

2. **Check Bot Communication:**
   - Verify bot manager is running
   - Check bot authentication
   - Ensure proper bot channel configuration

## Performance Issues

### High CPU Usage

**Symptoms:**
- High CPU usage by Mumble or plugin
- System slowdown
- Audio dropouts

**Solutions:**
1. **Check Configuration:**
   - Disable unnecessary features
   - Adjust update intervals
   - Check threading configuration

2. **Check System Resources:**
   - Monitor system performance
   - Check for other resource-intensive applications
   - Verify adequate system resources

### Memory Issues

**Symptoms:**
- High memory usage
- Memory leaks
- System instability

**Solutions:**
1. **Check Plugin Configuration:**
   - Adjust caching settings
   - Check data retention policies
   - Verify memory limits

2. **Check System:**
   - Monitor memory usage
   - Check for memory leaks
   - Verify system stability

## Network Issues

### Connection Problems

**Symptoms:**
- Cannot connect to server
- Intermittent disconnections
- Connection timeouts

**Solutions:**
1. **Check Network Configuration:**
   - Verify server address and port
   - Check firewall settings
   - Ensure proper UDP port configuration

2. **Check Server Status:**
   - Verify server is running
   - Check server logs
   - Ensure server is accessible

### Port Issues

**Symptoms:**
- Plugin not listening on expected port
- Port conflicts
- Connection refused errors

**Solutions:**
1. **Check Port Configuration:**
   - Verify UDP port settings
   - Check for port conflicts
   - Ensure proper port forwarding

2. **Check Firewall:**
   - Verify firewall allows the port
   - Check for blocked connections
   - Ensure proper security settings

## Debugging

### Enable Debug Output

**Linux/macOS:**
```bash
# Start Mumble from terminal to see debug output
mumble
```

**Windows:**
- Run Mumble from command prompt
- Check Windows Event Viewer for errors

### Debug Information

**Plugin Debug Messages:**
- Start Mumble from terminal
- Look for plugin initialization messages
- Check for error messages
- Monitor UDP port status

**Server Logs:**
- Check Mumble server logs
- Look for "Dropping plugin message" entries
- Monitor server performance
- Check for authentication issues

### Common Debug Commands

**Check Plugin Status:**
```bash
# Check if plugin is loaded
mumble --list-plugins

# Check plugin configuration
cat ~/.fgcom-mumble.ini
```

**Check Network:**
```bash
# Test UDP port
nc -u <server> <port>

# Check network connectivity
ping <server>
```

## Known Issues

### Current Issues
- **None currently known.** All major issues have been resolved. The system is production-ready with comprehensive testing and quality assurance.

### Previously Resolved Issues
- Plugin loading issues on certain Linux distributions
- Configuration file parsing problems
- Audio quality issues with specific audio drivers
- Network connectivity problems with certain firewall configurations

## Getting Help

### Documentation
- [Installation Guide](docs/INSTALLATION_GUIDE.md) - Installation and setup
- [Client Usage Guide](docs/CLIENT_USAGE_GUIDE.md) - Client usage and compatibility
- [Special Frequencies Guide](docs/SPECIAL_FREQUENCIES_GUIDE.md) - Special features
- [Technical Documentation](docs/TECHNICAL_DOCUMENTATION.md) - Technical details

### Support Resources
- GitHub Issues: [https://github.com/hbeni/fgcom-mumble/issues](https://github.com/hbeni/fgcom-mumble/issues)
- Documentation: [https://github.com/hbeni/fgcom-mumble/tree/master/docs](https://github.com/hbeni/fgcom-mumble/tree/master/docs)
- Server Documentation: [server/Readme.server.md](server/Readme.server.md)

### Reporting Issues
When reporting issues, please include:
- Operating system and version
- Mumble version
- Plugin version
- Error messages or logs
- Steps to reproduce the issue
- System configuration details

## Prevention

### Best Practices
- Keep Mumble and the plugin updated
- Use stable network connections
- Follow proper configuration procedures
- Monitor system performance
- Regular backup of configuration files

### Maintenance
- Regular system updates
- Configuration file validation
- Performance monitoring
- Log file analysis
- System resource monitoring
