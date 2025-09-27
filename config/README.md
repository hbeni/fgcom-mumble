# FGCom-mumble Configuration

This directory contains configuration files and documentation for the FGCom-mumble system.

## Configuration Files

### Main Configuration Files
- **`fgcom-mumble.conf.example`** - Complete configuration template with all available options
- **`fgcom-mumble.conf.minimal`** - Minimal configuration for basic operation
- **`fgcom-mumble.ini`** - Legacy configuration format (still supported)

### Documentation Files
- **`README.md`** - This file (configuration documentation)
- **`README-de_DE.md`** - German version of configuration documentation
- **`Readme.architecture.md`** - System architecture documentation
- **`SECURITY.md`** - Comprehensive security guide for TLS/SSL, authentication, and secure client connections
- **`BUILD_CONFIGURATION.md`** - Build system configuration documentation
- **`DOCUMENTATION_STATUS.md`** - Documentation status and organization

## Configuration Features

### v2.0+ Advanced Configuration
FGCom-mumble v2.0+ includes comprehensive configuration options:

- **Feature Toggles**: Runtime enable/disable of 107 features across 17 categories
- **GPU Acceleration**: Configure client/server/hybrid GPU acceleration modes
- **Threading**: Customize thread intervals and resource allocation
- **API Server**: Configure RESTful API endpoints and WebSocket settings
- **Debugging**: Set logging levels, output handlers, and performance monitoring
- **Power Management**: Configure transmit power limits and efficiency settings
- **Solar Data**: Set NOAA/SWPC data update intervals and fallback options
- **Lightning Data**: Configure atmospheric noise simulation parameters
- **Weather Data**: Set weather data sources and update frequencies

### Security Configuration
- **TLS/SSL**: Certificate-based authentication and encryption
- **API Keys**: Secure API key management and rotation
- **Client Authentication**: Certificate and token-based authentication
- **Rate Limiting**: Abuse detection and prevention
- **Access Control**: Role-based access control and permissions

### Performance Configuration
- **Multi-threading**: Configure thread pools and resource allocation
- **GPU Acceleration**: CUDA, OpenCL, and Metal support configuration
- **Memory Management**: Buffer sizes and caching strategies
- **Network Settings**: Connection limits and timeout configurations

## Configuration Examples

### Basic Configuration
```ini
[general]
server_host = localhost
server_port = 64738
plugin_enabled = true

[radio]
default_power = 25.0
max_power = 100.0
frequency_offset = 0.0

[audio]
volume = 1.0
squelch_threshold = 0.1
```

### Advanced Configuration
```ini
[general]
server_host = your-server.com
server_port = 64738
plugin_enabled = true
debug_level = 2

[features]
work_unit_distribution = true
gpu_acceleration = true
security_enabled = true
api_server = true

[gpu]
acceleration_mode = hybrid
cuda_enabled = true
opencl_enabled = true
memory_limit_mb = 2048

[security]
tls_enabled = true
certificate_path = /path/to/cert.pem
key_path = /path/to/key.pem
auth_token = your-secure-token
```

## Documentation Links

For detailed configuration information, see:
- [Main Documentation](../README.md) - Complete system documentation
- [API Reference](../docs/API_REFERENCE_COMPLETE.md) - Complete API documentation
- [Security Guide](SECURITY.md) - Security configuration and best practices
- [Architecture Guide](Readme.architecture.md) - System architecture details
- [User Guide](../docs/USER_GUIDE_SIMPLE.md) - User-friendly setup guide

## Support

For configuration help and support:
- **Issues**: Report configuration problems on GitHub
- **Documentation**: Check the relevant documentation files
- **Community**: Join the FGCom-mumble community for help
