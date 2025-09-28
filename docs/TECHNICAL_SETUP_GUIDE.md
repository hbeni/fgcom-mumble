# Technical Setup Guide

## Overview

This guide provides comprehensive setup instructions for the FGCom-mumble distributed work unit system. **This is a complex system requiring significant technical expertise.** You'll learn how to set up the server, register clients, and start processing work units.

**⚠️ Important**: This is NOT a "quick start" system. Setup requires 2-4 hours for experienced administrators and 1-2 days for full configuration.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Server Setup](#server-setup)
3. [Client Setup](#client-setup)
4. [Basic Usage](#basic-usage)
5. [Advanced Configuration](#advanced-configuration)
6. [Troubleshooting](#troubleshooting)

## Prerequisites

### System Requirements

- **Operating System**: Linux, macOS, or Windows
- **CPU**: Multi-core processor (4+ cores recommended)
- **Memory**: 4GB RAM minimum, 8GB+ recommended
- **GPU**: Optional but recommended for acceleration
- **Network**: Stable internet connection

### Software Dependencies

- **C++ Compiler**: GCC 7+ or Clang 5+
- **OpenSSL**: 1.1.1+ for security features
- **CMake**: 3.10+ for building
- **Python**: 3.6+ for client examples
- **Node.js**: 14+ for JavaScript examples

## Server Setup

### 1. Clone the Repository

```bash
git clone https://github.com/Supermagnum/fgcom-mumble.git
cd fgcom-mumble
```

### 2. Build the Server

```bash
# Install dependencies
sudo apt-get update
sudo apt-get install build-essential cmake libssl-dev

# Build the project
mkdir build
cd build
cmake ..
make -j$(nproc)
```

### 3. Configure the Server

Create a configuration file:

```bash
cp config/fgcom-mumble.conf.example fgcom-mumble.conf
```

Edit the configuration:

```ini
[server]
host = 0.0.0.0
port = 8080
ssl_enabled = true
certificate_path = /etc/ssl/certs/server.crt
private_key_path = /etc/ssl/private/server.key

[security]
level = medium
encryption_enabled = true
signature_validation_enabled = true
rate_limiting_enabled = true
monitoring_enabled = true

[work_units]
max_concurrent_units = 10
max_queue_size = 1000
unit_timeout_ms = 30000
enable_retry = true
max_retries = 3
```

### 4. Start the Server

```bash
# Start the server
./fgcom-mumble-server --config fgcom-mumble.conf

# Or run in background
nohup ./fgcom-mumble-server --config fgcom-mumble.conf > server.log 2>&1 &
```

### 5. Verify Server is Running

```bash
# Check server health
curl http://localhost:8080/health

# Expected response:
{
  "status": "healthy",
  "timestamp": 1703123456789,
  "uptime_seconds": 3600,
  "version": "1.4.1"
}
```

## Client Setup

### 1. Register a Client

```bash
# Register a new client
curl -X POST "http://localhost:8080/api/v1/security/register" \
     -H "Content-Type: application/json" \
     -d '{
       "client_id": "client_001",
       "auth_method": "api_key",
       "security_level": "medium",
       "capabilities": {
         "max_memory_mb": 2048,
         "supports_gpu": true,
         "network_bandwidth_mbps": 100.0,
         "processing_latency_ms": 50.0
       }
     }'
```

**Response:**
```json
{
  "success": true,
  "data": {
    "registered": true,
    "client_id": "client_001",
    "api_key": "ak_1234567890abcdef",
    "security_level": "medium",
    "auth_method": "api_key"
  }
}
```

### 2. Authenticate the Client

```bash
# Authenticate with the server
curl -X POST "http://localhost:8080/api/v1/security/authenticate" \
     -H "Content-Type: application/json" \
     -d '{
       "client_id": "client_001",
       "auth_data": "ak_1234567890abcdef",
       "auth_method": "api_key"
     }'
```

**Response:**
```json
{
  "success": true,
  "data": {
    "authenticated": true,
    "session_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "client_id": "client_001",
    "auth_method": "api_key"
  }
}
```

## Basic Usage

### 1. Check Server Status

```bash
# Get work unit status
curl "http://localhost:8080/api/v1/work-units/status"

# Get security status
curl "http://localhost:8080/api/v1/security/status"

# Get GPU status
curl "http://localhost:8080/api/v1/gpu-status"
```

### 2. Calculate Propagation

```bash
# Single propagation calculation
curl -X POST "http://localhost:8080/api/v1/propagation" \
     -H "Content-Type: application/json" \
     -d '{
       "lat1": 40.7128,
       "lon1": -74.0060,
       "alt1": 100.0,
       "lat2": 40.7589,
       "lon2": -73.9851,
       "alt2": 200.0,
       "frequency_mhz": 14.175,
       "tx_power_watts": 100.0,
       "include_solar_effects": true
     }'
```

**Response:**
```json
{
  "success": true,
  "data": {
    "signal_quality": 0.85,
    "signal_strength_db": -12.5,
    "distance_km": 8.2,
    "bearing_deg": 45.3,
    "elevation_angle_deg": 2.1,
    "propagation_mode": "skywave"
  }
}
```

### 3. Python Client Example

Create a simple Python client:

```python
import requests
import json
import time

class FGComClient:
    def __init__(self, server_url, client_id, api_key):
        self.server_url = server_url
        self.client_id = client_id
        self.api_key = api_key
        self.session_token = None
        
    def authenticate(self):
        """Authenticate with the server"""
        response = requests.post(f"{self.server_url}/api/v1/security/authenticate", 
                               json={
                                   "client_id": self.client_id,
                                   "auth_data": self.api_key,
                                   "auth_method": "api_key"
                               })
        
        if response.status_code == 200:
            data = response.json()
            if data["success"]:
                self.session_token = data["data"]["session_token"]
                return True
        return False
    
    def get_server_status(self):
        """Get server work unit status"""
        response = requests.get(f"{self.server_url}/api/v1/work-units/status")
        return response.json()
    
    def calculate_propagation(self, lat1, lon1, alt1, lat2, lon2, alt2, 
                            frequency_mhz, tx_power_watts):
        """Calculate propagation between two points"""
        data = {
            "lat1": lat1,
            "lon1": lon1,
            "alt1": alt1,
            "lat2": lat2,
            "lon2": lon2,
            "alt2": alt2,
            "frequency_mhz": frequency_mhz,
            "tx_power_watts": tx_power_watts,
            "include_solar_effects": True
        }
        
        response = requests.post(f"{self.server_url}/api/v1/propagation", 
                               json=data)
        return response.json()
    
    def run(self):
        """Main client loop"""
        print("FGCom Client Starting...")
        
        # Authenticate
        if not self.authenticate():
            print("Authentication failed!")
            return
        
        print("Authentication successful!")
        
        # Main loop
        while True:
            try:
                # Get server status
                status = self.get_server_status()
                print(f"Server status: {status['data']['pending_units']} pending, "
                      f"{status['data']['processing_units']} processing")
                
                # Calculate propagation
                result = self.calculate_propagation(
                    lat1=40.7128, lon1=-74.0060, alt1=100.0,
                    lat2=40.7589, lon2=-73.9851, alt2=200.0,
                    frequency_mhz=14.175, tx_power_watts=100.0
                )
                
                if result["success"]:
                    print(f"Signal quality: {result['data']['signal_quality']:.2f}")
                    print(f"Signal strength: {result['data']['signal_strength_db']:.1f} dB")
                    print(f"Distance: {result['data']['distance_km']:.1f} km")
                
                # Wait before next calculation
                time.sleep(5)
                
            except KeyboardInterrupt:
                print("\nStopping client...")
                break
            except Exception as e:
                print(f"Error: {e}")
                time.sleep(10)

# Usage
if __name__ == "__main__":
    client = FGComClient("http://localhost:8080", "client_001", "ak_1234567890abcdef")
    client.run()
```

### 4. C++ Client Example

Create a simple C++ client:

```cpp
#include "client_work_unit_coordinator.h"
#include <iostream>
#include <thread>
#include <chrono>

int main() {
    std::cout << "FGCom C++ Client Starting..." << std::endl;
    
    // Initialize client coordinator
    auto& coordinator = FGCom_ClientWorkUnitCoordinator::getInstance();
    
    if (!coordinator.initialize("http://localhost:8080", "client_001")) {
        std::cerr << "Failed to initialize client coordinator" << std::endl;
        return 1;
    }
    
    // Set client capabilities
    ClientWorkUnitCapability capability;
    capability.client_id = "client_001";
    capability.supported_types = {
        WorkUnitType::PROPAGATION_GRID,
        WorkUnitType::ANTENNA_PATTERN
    };
    capability.max_memory_mb = 2048;
    capability.supports_gpu = true;
    capability.supports_double_precision = true;
    capability.network_bandwidth_mbps = 100.0;
    capability.processing_latency_ms = 50.0;
    capability.is_online = true;
    
    coordinator.setClientCapability(capability);
    coordinator.enableAutoWorkUnitRequests(true);
    
    std::cout << "Client initialized successfully" << std::endl;
    
    // Main loop
    while (true) {
        try {
            // Get current status
            auto stats = coordinator.getStatistics();
            auto assigned_units = coordinator.getAssignedWorkUnits();
            auto processing_units = coordinator.getProcessingWorkUnits();
            
            std::cout << "Status: " << assigned_units.size() << " assigned, " 
                      << processing_units.size() << " processing" << std::endl;
            
            // Print statistics
            for (const auto& stat : stats) {
                std::cout << "  " << stat.first << ": " << stat.second << std::endl;
            }
            
            // Sleep for a bit
            std::this_thread::sleep_for(std::chrono::seconds(10));
            
        } catch (const std::exception& e) {
            std::cerr << "Error: " << e.what() << std::endl;
            std::this_thread::sleep_for(std::chrono::seconds(5));
        }
    }
    
    // Shutdown
    coordinator.shutdown();
    std::cout << "Client shutdown complete" << std::endl;
    
    return 0;
}
```

## Advanced Configuration

### 1. High Security Setup

For production environments with high security requirements:

```ini
[security]
level = high
encryption_enabled = true
signature_validation_enabled = true
rate_limiting_enabled = true
monitoring_enabled = true
multi_factor_auth = true

[work_units]
max_concurrent_units = 20
max_queue_size = 2000
unit_timeout_ms = 60000
enable_retry = true
max_retries = 5
retry_delay_ms = 2000
```

### 2. GPU Acceleration Setup

Enable GPU acceleration for better performance:

```ini
[gpu]
enabled = true
cuda_enabled = true
opencl_enabled = true
max_memory_mb = 8192
utilization_threshold = 80.0
temperature_threshold = 85.0
```

### 3. Load Balancing Setup

Configure load balancing for multiple clients:

```ini
[load_balancing]
enabled = true
algorithm = weighted_round_robin
health_check_interval = 30
failover_threshold = 3
```

### 4. Monitoring Setup

Enable comprehensive monitoring:

```ini
[monitoring]
enabled = true
log_level = INFO
metrics_enabled = true
alerting_enabled = true
dashboard_enabled = true
```

## Troubleshooting

### Common Issues

1. **Server won't start**
   - Check if port 8080 is available
   - Verify SSL certificates are valid
   - Check configuration file syntax

2. **Client authentication fails**
   - Verify API key is correct
   - Check client ID matches registration
   - Ensure server is running

3. **Work units not processing**
   - Check client capabilities
   - Verify network connectivity
   - Check server logs for errors

4. **Rate limit exceeded**
   - Reduce request frequency
   - Check rate limit configuration
   - Contact administrator for limit increases

### Debug Commands

```bash
# Check server health
curl http://localhost:8080/health

# Check API info
curl http://localhost:8080/api/info

# Check work unit status
curl http://localhost:8080/api/v1/work-units/status

# Check security status
curl http://localhost:8080/api/v1/security/status

# Check server logs
tail -f server.log

# Check system resources
htop
nvidia-smi  # If using GPU
```

### Log Analysis

```bash
# Check for errors
grep "ERROR" server.log

# Check for authentication issues
grep "AUTH" server.log

# Check for rate limiting
grep "RATE_LIMIT" server.log

# Check for security events
grep "SECURITY" server.log
```

### Performance Monitoring

```bash
# Monitor CPU usage
top -p $(pgrep fgcom-mumble-server)

# Monitor memory usage
ps aux | grep fgcom-mumble-server

# Monitor network connections
netstat -an | grep 8080

# Monitor disk I/O
iostat -x 1
```

## Next Steps

1. **Read the full documentation**:
   - [Work Unit Distribution API](WORK_UNIT_DISTRIBUTION_API.md)
   - [Security API Documentation](SECURITY_API_DOCUMENTATION.md)
   - [Complete API Reference](API_REFERENCE_COMPLETE.md)

2. **Explore advanced features**:
   - GPU acceleration
   - Load balancing
   - Security monitoring
   - Custom work unit types

3. **Join the community**:
   - GitHub Issues: https://github.com/Supermagnum/fgcom-mumble/issues
   - Discussions: https://github.com/Supermagnum/fgcom-mumble/discussions

4. **Contribute**:
   - Submit bug reports
   - Suggest new features
   - Submit pull requests

## Conclusion

You now have a working FGCom-mumble distributed work unit system! The system provides secure, scalable distributed computing for radio propagation calculations with comprehensive monitoring and management capabilities.
