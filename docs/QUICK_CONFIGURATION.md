# Quick Configuration Guide

## Overview

This guide provides quick setup instructions for the FGCom-mumble radio communication simulation system. Follow these steps to get your system running in minutes.

## Basic Setup

### 1. Copy the Example Configuration

```bash
# Copy the example configuration to your home directory
cp configs/fgcom-mumble.ini ~/.fgcom-mumble.ini

# Edit the configuration file
nano ~/.fgcom-mumble.ini
```

### 2. Essential Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `radioAudioEffects` | `1` | Enable realistic radio static, noise, and propagation effects |
| `allowHearingNonPluginUsers` | `0` | Allow WebRTC browser clients to be heard by plugin users |
| `udpServerHost` | `127.0.0.1` | UDP server listening interface (`*` for all interfaces) |
| `udpServerPort` | `16661` | UDP server port for client communication |
| `autoJoinChannel` | `0` | Automatically join the default channel on startup |
| `enableWeatherEffects` | `1` | Enable frequency-dependent weather effects on radio propagation |
| `enableFrequencyManagement` | `1` | Enable frequency allocation and channel management |
| `enableInterferenceDetection` | `1` | Enable interference detection between channels |

## Configuration Examples

### For Pilots

```ini
# Pilot Configuration
radioAudioEffects=1
allowHearingNonPluginUsers=0
udpServerHost=127.0.0.1
udpServerPort=16661
autoJoinChannel=0
enableWeatherEffects=1
enableFrequencyManagement=1
enableInterferenceDetection=1

# Audio Settings
audioGain=0.8
squelchThreshold=-20.0
compressionRatio=2.0

# Radio Settings
defaultFrequency=118.5
frequencyStep=0.025
maxPower=25.0
antennaGain=3.0

# Weather Settings
weatherUpdateInterval=300
enableRainEffects=1
enableFogEffects=1
enableSnowEffects=1
```

### For ATC Controllers

```ini
# ATC Controller Configuration
radioAudioEffects=1
allowHearingNonPluginUsers=1
udpServerHost=127.0.0.1
udpServerPort=16661
autoJoinChannel=1
enableWeatherEffects=1
enableFrequencyManagement=1
enableInterferenceDetection=1

# Audio Settings
audioGain=1.0
squelchThreshold=-15.0
compressionRatio=1.5

# Radio Settings
defaultFrequency=118.5
frequencyStep=0.025
maxPower=25.0
antennaGain=6.0

# ATC Specific Settings
enableMultipleFrequencies=1
enableFrequencyScanning=1
enableEmergencyChannels=1
enableATIS=1
```

### For WebRTC Gateway

```ini
# WebRTC Gateway Configuration
radioAudioEffects=1
allowHearingNonPluginUsers=1
udpServerHost=*
udpServerPort=16661
autoJoinChannel=1
enableWeatherEffects=1
enableFrequencyManagement=1
enableInterferenceDetection=1

# WebRTC Settings
webrtcGatewayPort=8080
webrtcStunServers=stun:stun.l.google.com:19302
webrtcTurnServers=turn:turnserver.example.com:3478

# Audio Settings
audioGain=0.9
squelchThreshold=-18.0
compressionRatio=2.5

# Radio Settings
defaultFrequency=118.5
frequencyStep=0.025
maxPower=25.0
antennaGain=3.0
```

### For Flight Simulator Integration

```ini
# Flight Simulator Integration Configuration
radioAudioEffects=1
allowHearingNonPluginUsers=0
udpServerHost=127.0.0.1
udpServerPort=16661
autoJoinChannel=0
enableWeatherEffects=1
enableFrequencyManagement=1
enableInterferenceDetection=1

# Flight Simulator Settings
enableFlightSimulatorIntegration=1
flightSimulatorHost=127.0.0.1
flightSimulatorPort=16662
enableAircraftPosition=1
enableAircraftHeading=1
enableAircraftAltitude=1

# Audio Settings
audioGain=0.8
squelchThreshold=-20.0
compressionRatio=2.0

# Radio Settings
defaultFrequency=118.5
frequencyStep=0.025
maxPower=25.0
antennaGain=3.0
```

## Advanced Configuration

### Weather Effects Configuration

```ini
# Weather Effects Settings
enableWeatherEffects=1
weatherUpdateInterval=300
enableRainEffects=1
enableFogEffects=1
enableSnowEffects=1
enableTemperatureEffects=1
enableHumidityEffects=1

# Rain Effects
rainAttenuationFactor=1.0
rainNoiseLevel=0.5
rainScatterEnabled=1

# Fog Effects
fogAttenuationFactor=1.0
fogNoiseLevel=0.3
fogScatterEnabled=1

# Snow Effects
snowAttenuationFactor=1.0
snowNoiseLevel=0.4
snowScatterEnabled=1
```

### Frequency Management Configuration

```ini
# Frequency Management Settings
enableFrequencyManagement=1
enableChannelPlanning=1
enableFrequencyAllocation=1
enableInterferenceDetection=1

# Channel Planning
defaultChannelSpacing=0.025
enableAdjacentChannelProtection=1
enableCoChannelProtection=1
enableIntermodulationProtection=1

# Frequency Allocation
enableAutomaticAllocation=1
enableFrequencyReservation=1
enableEmergencyFrequencies=1
enableATISFrequencies=1
```

### Audio Processing Configuration

```ini
# Audio Processing Settings
audioGain=0.8
squelchThreshold=-20.0
compressionRatio=2.0
enableNoiseReduction=1
enableEchoCancellation=1
enableAutomaticGainControl=1

# Noise Reduction
noiseReductionLevel=0.5
enableSpectralSubtraction=1
enableWienerFiltering=1

# Echo Cancellation
echoCancellationLevel=0.8
enableAdaptiveFiltering=1
enableDoubleTalkDetection=1
```

### Network Configuration

```ini
# Network Settings
udpServerHost=127.0.0.1
udpServerPort=16661
enableUDPBroadcast=1
enableTCPFallback=1
enableWebRTCGateway=1

# WebRTC Gateway
webrtcGatewayPort=8080
webrtcStunServers=stun:stun.l.google.com:19302
webrtcTurnServers=turn:turnserver.example.com:3478
enableWebRTCAudio=1
enableWebRTCVideo=0

# Security
enableEncryption=1
enableAuthentication=1
enableAccessControl=1
```

## Quick Start Commands

### Start the Server

```bash
# Start the FGCom-mumble server
./server/fgcom-mumble-server

# Or with specific configuration
./server/fgcom-mumble-server --config ~/.fgcom-mumble.ini
```

### Start the Client

```bash
# Start the FGCom-mumble client
./client/mumble-plugin/fgcom-mumble

# Or with specific configuration
./client/mumble-plugin/fgcom-mumble --config ~/.fgcom-mumble.ini
```

### Start the WebRTC Gateway

```bash
# Start the WebRTC gateway
cd webrtc-gateway
npm start

# Or with specific configuration
npm start -- --config ~/.fgcom-mumble.ini
```

## Troubleshooting

### Common Issues

#### 1. Server Won't Start

```bash
# Check if port is already in use
netstat -tulpn | grep 16661

# Check server logs
tail -f /var/log/fgcom-mumble/server.log
```

#### 2. Client Can't Connect

```bash
# Check network connectivity
ping 127.0.0.1

# Check UDP port
nc -u 127.0.0.1 16661

# Check client logs
tail -f /var/log/fgcom-mumble/client.log
```

#### 3. Audio Issues

```bash
# Check audio devices
aplay -l
arecord -l

# Test audio output
speaker-test -c 2

# Test audio input
arecord -f cd -d 5 test.wav
```

#### 4. WebRTC Gateway Issues

```bash
# Check WebRTC gateway status
curl http://localhost:8080/status

# Check WebRTC logs
tail -f /var/log/fgcom-mumble/webrtc.log
```

### Configuration Validation

```bash
# Validate configuration file
./scripts/validate_config.sh ~/.fgcom-mumble.ini

# Test configuration
./scripts/test_config.sh ~/.fgcom-mumble.ini
```

## Performance Tuning

### Server Performance

```ini
# Server Performance Settings
maxConnections=1000
maxChannels=100
maxUsersPerChannel=50
enableConnectionPooling=1
enableMemoryOptimization=1

# Threading
workerThreads=4
ioThreads=2
audioThreads=2
```

### Client Performance

```ini
# Client Performance Settings
enableAudioBuffering=1
audioBufferSize=1024
enableAudioCompression=1
enableNetworkOptimization=1

# Audio Quality
audioSampleRate=44100
audioBitDepth=16
audioChannels=2
```

### WebRTC Performance

```ini
# WebRTC Performance Settings
enableAdaptiveBitrate=1
enableBandwidthOptimization=1
enableLatencyOptimization=1
enableQualityOptimization=1

# Bandwidth Settings
maxBandwidth=1000000
minBandwidth=64000
adaptiveBandwidth=1
```

## Security Configuration

### Basic Security

```ini
# Basic Security Settings
enableEncryption=1
enableAuthentication=1
enableAccessControl=1
enableRateLimiting=1

# Encryption
encryptionAlgorithm=AES-256
encryptionKeyLength=256
enableKeyRotation=1

# Authentication
authenticationMethod=password
enableTwoFactorAuth=0
enableCertificateAuth=0
```

### Advanced Security

```ini
# Advanced Security Settings
enableFirewall=1
enableIntrusionDetection=1
enableAuditLogging=1
enableSecurityMonitoring=1

# Firewall Rules
allowedIPs=127.0.0.1,192.168.1.0/24
blockedIPs=10.0.0.0/8
enableGeoBlocking=0

# Audit Logging
auditLogLevel=INFO
auditLogRetention=30
enableRealTimeMonitoring=1
```

## Monitoring and Logging

### Log Configuration

```ini
# Logging Settings
logLevel=INFO
logFile=/var/log/fgcom-mumble/fgcom-mumble.log
logRotation=1
logRetention=30

# Component Logging
enableServerLogging=1
enableClientLogging=1
enableWebRTCLogging=1
enableAudioLogging=1
enableNetworkLogging=1
```

### Monitoring

```bash
# Monitor server status
./scripts/monitor_server.sh

# Monitor client connections
./scripts/monitor_clients.sh

# Monitor audio quality
./scripts/monitor_audio.sh

# Monitor network performance
./scripts/monitor_network.sh
```

## Backup and Recovery

### Configuration Backup

```bash
# Backup configuration
cp ~/.fgcom-mumble.ini ~/.fgcom-mumble.ini.backup

# Backup all configurations
tar -czf fgcom-mumble-config-backup.tar.gz configs/
```

### System Recovery

```bash
# Restore configuration
cp ~/.fgcom-mumble.ini.backup ~/.fgcom-mumble.ini

# Restore from backup
tar -xzf fgcom-mumble-config-backup.tar.gz
```

## Support and Resources

### Documentation

- [Installation Guide](INSTALLATION.md)
- [User Manual](docs/USER_MANUAL.md)
- [API Documentation](docs/API_DOCUMENTATION.md)
- [Troubleshooting Guide](docs/TROUBLESHOOTING.md)

### Community

- [GitHub Issues](https://github.com/fgcom-mumble/fgcom-mumble/issues)
- [Discord Server](https://discord.gg/fgcom-mumble)
- [Forum](https://forum.fgcom-mumble.org)

### Professional Support

- [Enterprise Support](https://fgcom-mumble.org/support)
- [Training Services](https://fgcom-mumble.org/training)
- [Consulting Services](https://fgcom-mumble.org/consulting)

## Conclusion

This quick configuration guide provides everything needed to get FGCom-mumble running quickly and efficiently. For more detailed information, refer to the comprehensive documentation in the `docs/` directory.

Remember to:
1. **Start with basic configuration** and gradually add advanced features
2. **Test your setup** with a small group before deploying to production
3. **Monitor performance** and adjust settings as needed
4. **Keep configurations backed up** for easy recovery
5. **Stay updated** with the latest releases and security patches

Happy flying! ✈️📡
