# FGCom-mumble Documentation

## Overview

FGCom-mumble is a distributed radio propagation calculation system that enables realistic radio communication simulation across multiple clients. The system supports various antenna types, propagation models, and security features for distributed computing.

## Table of Contents

1. [Technical Setup Guide](TECHNICAL_SETUP_GUIDE.md) - Comprehensive setup instructions
2. [Game Developer Integration Guide](GAME_DEVELOPER_INTEGRATION_GUIDE.md) - Integration guide for game developers and modders
3. [API Reference](API_REFERENCE_COMPLETE.md) - Complete API documentation
4. [Work Unit Distribution](WORK_UNIT_DISTRIBUTION_API.md) - Distributed computing features
5. [Security Guide](SECURITY_API_DOCUMENTATION.md) - Security implementation
6. [Technical User Guide](TECHNICAL_USER_GUIDE.md) - Technical user documentation
7. [Noise Floor Distance Guide](NOISE_FLOOR_DISTANCE_GUIDE.md) - Distance-based noise falloff
8. [Environment Detection Guide](ENVIRONMENT_DETECTION_GUIDE.md) - Environment detection methods
9. [GPU Acceleration Guide](GPU_ACCELERATION_GUIDE.md) - GPU acceleration modes and configuration
10. [Technical Documentation](#technical-documentation) - Technical details

## Technical Setup

1. **Server Setup**: Follow the [Technical Setup Guide](TECHNICAL_SETUP_GUIDE.md)
2. **Client Registration**: Register clients with the security system
3. **Work Unit Processing**: Start processing distributed calculations
4. **Monitoring**: Monitor system performance and security

## Key Features

- **Distributed Computing**: Process propagation calculations across multiple clients with work unit distribution
- **Comprehensive Security**: Multi-layer security with authentication, encryption, and threat detection
- **GPU Acceleration**: CUDA, OpenCL, and Metal support with configurable modes
- **Real-time Monitoring**: System status, performance metrics, and security events
- **Multiple Antenna Types**: Yagi, dipole, loop, and custom antennas with 3D attitude support
- **Propagation Models**: ITU-R, free space, and atmospheric effects with solar data integration
- **Vehicle Geometry**: Complete guide for creating vehicle geometry and ground planes
- **Coding Standards**: Strict architectural and design standards with zero tolerance for violations

## API Endpoints

### Core APIs
- `GET /health` - Server health status
- `GET /api/info` - API information and features
- `GET /api/v1/config` - Server configuration

### Work Unit Distribution
- `GET /api/v1/work-units/status` - Work unit distributor status
- `GET /api/v1/work-units/queue` - Current queue state
- `GET /api/v1/work-units/clients` - Available clients
- `GET /api/v1/work-units/statistics` - Processing statistics
- `GET /api/v1/work-units/config` - Distribution configuration

### Security
- `GET /api/v1/security/status` - Security system status
- `GET /api/v1/security/events` - Security events
- `POST /api/v1/security/authenticate` - Client authentication
- `POST /api/v1/security/register` - Client registration

### Propagation
- `POST /api/v1/propagation` - Single propagation calculation
- `POST /api/v1/propagation/batch` - Batch propagation calculations

### Antenna Patterns
- `GET /api/v1/antennas` - List available antennas
- `GET /api/v1/antennas/{name}` - Get antenna pattern data

### Ground Systems
- `GET /api/v1/ground` - List ground systems
- `GET /api/v1/ground/{name}` - Get ground system details

## Technical Documentation

For detailed technical information, see [Technical Documentation](TECHNICAL_DOCUMENTATION.md).

### Vehicle Geometry Creation

For creating vehicle geometry and ground planes, see [Vehicle Geometry Creation Guide](VEHICLE_GEOMETRY_CREATION_GUIDE.md).

### Architecture
- **Work Unit Distribution**: Distributed processing across multiple clients
- **Security System**: Multi-layer security with authentication and encryption
- **GPU Acceleration**: Hardware acceleration for complex calculations
- **Threading**: Multi-threaded processing with load balancing

### Security Levels
- **LOW**: Development and testing environments
- **MEDIUM**: Production environments with moderate security
- **HIGH**: Production environments with high security requirements
- **CRITICAL**: Military or government environments

### Supported Work Unit Types
- **PROPAGATION_GRID**: Grid-based propagation calculations
- **ANTENNA_PATTERN**: Antenna pattern calculations
- **FREQUENCY_OFFSET**: Frequency offset processing
- **AUDIO_PROCESSING**: Audio signal processing
- **BATCH_QSO**: Batch QSO calculations
- **SOLAR_EFFECTS**: Solar effects processing
- **LIGHTNING_EFFECTS**: Lightning effects processing

## Getting Help

- **Documentation**: Check the relevant documentation files
- **API Reference**: Use the complete API reference for endpoint details
- **Examples**: See the Quick Start Guide for code examples
- **Troubleshooting**: Check the troubleshooting sections in the guides

## Contributing

- **Issues**: Report bugs and request features
- **Pull Requests**: Submit improvements and new features
- **Documentation**: Help improve documentation
- **Testing**: Test with different configurations and report issues
