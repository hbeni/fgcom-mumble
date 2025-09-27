# Work Unit Distribution API Documentation

## Overview

The Work Unit Distribution API enables distributed processing of propagation calculations across multiple clients. This system allows clients to participate in distributed computing by processing work units and contributing their computational resources.

## Table of Contents

1. [Authentication](#authentication)
2. [Work Unit Management](#work-unit-management)
3. [Client Coordination](#client-coordination)
4. [Security Features](#security-features)
5. [API Endpoints](#api-endpoints)
6. [Usage Examples](#usage-examples)
7. [Error Handling](#error-handling)
8. [Best Practices](#best-practices)

## Authentication

### Client Registration

Before participating in work unit distribution, clients must register with the server.

**Endpoint:** `POST /api/v1/security/register`

**Request Body:**
```json
{
  "client_id": "client_001",
  "auth_method": "api_key",
  "security_level": "medium",
  "capabilities": {
    "max_memory_mb": 2048,
    "supports_gpu": true,
    "network_bandwidth_mbps": 100.0,
    "processing_latency_ms": 50.0
  }
}
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

### Client Authentication

**Endpoint:** `POST /api/v1/security/authenticate`

**Request Body:**
```json
{
  "client_id": "client_001",
  "auth_data": "ak_1234567890abcdef",
  "auth_method": "api_key"
}
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

## Work Unit Management

### Work Unit Types

The system supports several types of work units:

- **PROPAGATION_GRID** - Grid-based propagation calculations
- **ANTENNA_PATTERN** - Antenna pattern calculations
- **FREQUENCY_OFFSET** - Frequency offset processing
- **AUDIO_PROCESSING** - Audio signal processing
- **BATCH_QSO** - Batch QSO calculations
- **SOLAR_EFFECTS** - Solar effects processing
- **LIGHTNING_EFFECTS** - Lightning effects processing

### Creating Work Units

Work units are created by the server and distributed to clients based on their capabilities and current load.

**Example Work Unit:**
```json
{
  "unit_id": "unit_1703123456789_abc123",
  "type": "PROPAGATION_GRID",
  "priority": "MEDIUM",
  "status": "PENDING",
  "input_data": [40.7128, -74.0060, 100.0, 40.7589, -73.9851, 200.0],
  "parameters": {
    "frequency_mhz": 14.175,
    "tx_power_watts": 100.0,
    "propagation_model": "ITU-R"
  },
  "max_processing_time_ms": 30000,
  "memory_requirement_mb": 512,
  "requires_gpu": true,
  "requires_double_precision": true
}
```

## Client Coordination

### Client Capabilities

Clients report their capabilities to the server:

```json
{
  "client_id": "client_001",
  "supported_types": ["PROPAGATION_GRID", "ANTENNA_PATTERN"],
  "max_concurrent_units": {
    "PROPAGATION_GRID": 2,
    "ANTENNA_PATTERN": 1
  },
  "processing_speed_multiplier": {
    "PROPAGATION_GRID": 1.0,
    "ANTENNA_PATTERN": 0.8
  },
  "max_memory_mb": 2048,
  "supports_gpu": true,
  "supports_double_precision": true,
  "network_bandwidth_mbps": 100.0,
  "processing_latency_ms": 50.0
}
```

### Work Unit Processing

Clients process work units using their local resources:

1. **Receive work unit** from server
2. **Validate work unit** integrity and authorization
3. **Process work unit** using local GPU/CPU
4. **Submit results** back to server
5. **Receive confirmation** and next work unit

## Security Features

### Digital Signatures

All work units are digitally signed to ensure integrity:

```json
{
  "work_unit": { /* work unit data */ },
  "digital_signature": "signature_abc123...",
  "integrity_hash": "sha256_hash_...",
  "signature_time": "2023-12-21T10:30:00Z",
  "signer_client_id": "client_001",
  "required_security_level": "MEDIUM"
}
```

### Encryption

Work units can be encrypted for sensitive data:

```json
{
  "work_unit": { /* work unit data */ },
  "is_encrypted": true,
  "encrypted_data": "encrypted_work_unit_data...",
  "encryption_key_id": "key_123"
}
```

### Rate Limiting

Clients are subject to rate limits to prevent abuse:

- **Work unit requests**: 10 per minute
- **Result submissions**: 20 per minute
- **Heartbeat**: 60 per minute

## API Endpoints

### Server Status

**GET /api/v1/work-units/status**

Returns overall work unit distributor status.

**Response:**
```json
{
  "success": true,
  "data": {
    "distributor_enabled": true,
    "pending_units": 5,
    "processing_units": 2,
    "completed_units": 1250,
    "failed_units": 12,
    "available_clients": 3,
    "status_report": "Work Unit Distributor Status:\n  Enabled: Yes\n  Workers Running: Yes\n  Pending Units: 5\n  Processing Units: 2\n  Completed Units: 1250\n  Failed Units: 12\n  Total Created: 1267\n  Total Completed: 1250\n  Total Failed: 12\n  Distribution Efficiency: 98.7%"
  }
}
```

### Queue Status

**GET /api/v1/work-units/queue**

Returns current queue state.

**Response:**
```json
{
  "success": true,
  "data": {
    "pending_units": ["unit_001", "unit_002"],
    "processing_units": ["unit_003"],
    "completed_units": ["unit_004", "unit_005"],
    "failed_units": ["unit_006"],
    "queue_sizes": {
      "pending": 2,
      "processing": 1,
      "completed": 2,
      "failed": 1
    }
  }
}
```

### Client Information

**GET /api/v1/work-units/clients**

Returns available clients and their capabilities.

**Response:**
```json
{
  "success": true,
  "data": {
    "available_clients": ["client_001", "client_002", "client_003"],
    "client_count": 3,
    "performance_metrics": {
      "client_001_efficiency": 95.5,
      "client_001_avg_processing_time": 1250.0,
      "client_001_active_units": 1,
      "client_001_memory_usage": 512,
      "client_001_cpu_utilization": 45.0,
      "client_001_gpu_utilization": 78.0
    }
  }
}
```

### Statistics

**GET /api/v1/work-units/statistics**

Returns detailed statistics about work unit processing.

**Response:**
```json
{
  "success": true,
  "total_units_created": 1267,
  "total_units_completed": 1250,
  "total_units_failed": 12,
  "total_units_timeout": 5,
  "average_processing_time_ms": 1250.0,
  "average_queue_wait_time_ms": 150.0,
  "distribution_efficiency_percent": 98.7,
  "current_queue_sizes": {
    "pending": 2,
    "processing": 1,
    "completed": 1250,
    "failed": 12
  },
  "work_unit_types": {
    "PROPAGATION_GRID": 800,
    "ANTENNA_PATTERN": 300,
    "FREQUENCY_OFFSET": 100,
    "AUDIO_PROCESSING": 67
  },
  "client_performance": {
    "client_001_efficiency": 95.5,
    "client_002_efficiency": 92.3,
    "client_003_efficiency": 88.7
  }
}
```

### Configuration

**GET /api/v1/work-units/config**

Returns server configuration and requirements.

**Response:**
```json
{
  "success": true,
  "data": {
    "distribution_enabled": true,
    "acceleration_mode": "hybrid",
    "max_concurrent_units": 10,
    "max_queue_size": 1000,
    "unit_timeout_ms": 30000,
    "enable_retry": true,
    "max_retries": 3,
    "retry_delay_ms": 1000,
    "supported_work_unit_types": [
      "PROPAGATION_GRID",
      "ANTENNA_PATTERN",
      "FREQUENCY_OFFSET",
      "AUDIO_PROCESSING",
      "BATCH_QSO",
      "SOLAR_EFFECTS",
      "LIGHTNING_EFFECTS"
    ],
    "client_requirements": {
      "min_memory_mb": 512,
      "min_network_bandwidth_mbps": 10.0,
      "max_processing_latency_ms": 5000.0,
      "supported_frameworks": ["CUDA", "OpenCL", "Metal"]
    }
  }
}
```

## Usage Examples

### Python Client Example

```python
import requests
import json
import time

class WorkUnitClient:
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
    
    def process_work_units(self):
        """Main processing loop"""
        while True:
            try:
                # Get server status
                status = self.get_server_status()
                print(f"Server status: {status['data']['pending_units']} pending, "
                      f"{status['data']['processing_units']} processing")
                
                # Simulate work unit processing
                time.sleep(5)
                
            except KeyboardInterrupt:
                print("Stopping client...")
                break
            except Exception as e:
                print(f"Error: {e}")
                time.sleep(10)

# Usage
client = WorkUnitClient("http://localhost:8080", "client_001", "ak_1234567890abcdef")
if client.authenticate():
    client.process_work_units()
```

### C++ Client Example

```cpp
#include "client_work_unit_coordinator.h"
#include <iostream>
#include <thread>
#include <chrono>

class ExampleWorkUnitClient {
private:
    FGCom_ClientWorkUnitCoordinator& coordinator;
    std::string server_url;
    std::string client_id;
    
public:
    ExampleWorkUnitClient(const std::string& server_url, const std::string& client_id)
        : coordinator(FGCom_ClientWorkUnitCoordinator::getInstance())
        , server_url(server_url)
        , client_id(client_id) {}
    
    bool initialize() {
        // Initialize the coordinator
        if (!coordinator.initialize(server_url, client_id)) {
            std::cerr << "Failed to initialize work unit coordinator" << std::endl;
            return false;
        }
        
        // Set client capabilities
        ClientWorkUnitCapability capability;
        capability.client_id = client_id;
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
        return true;
    }
    
    void run() {
        std::cout << "Client running - participating in distributed processing" << std::endl;
        
        while (true) {
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
        }
    }
    
    void shutdown() {
        coordinator.shutdown();
        std::cout << "Client shutdown complete" << std::endl;
    }
};

int main() {
    std::cout << "FGCom Work Unit Distribution Client Example" << std::endl;
    
    // Create client
    ExampleWorkUnitClient client("http://localhost:8080", "client_001");
    
    // Initialize
    if (!client.initialize()) {
        std::cerr << "Failed to initialize client" << std::endl;
        return 1;
    }
    
    // Run client
    try {
        client.run();
    } catch (const std::exception& e) {
        std::cerr << "Client error: " << e.what() << std::endl;
    }
    
    // Shutdown
    client.shutdown();
    
    return 0;
}
```

### JavaScript/Node.js Client Example

```javascript
const axios = require('axios');

class WorkUnitClient {
    constructor(serverUrl, clientId, apiKey) {
        this.serverUrl = serverUrl;
        this.clientId = clientId;
        this.apiKey = apiKey;
        this.sessionToken = null;
    }
    
    async authenticate() {
        try {
            const response = await axios.post(`${this.serverUrl}/api/v1/security/authenticate`, {
                client_id: this.clientId,
                auth_data: this.apiKey,
                auth_method: 'api_key'
            });
            
            if (response.data.success) {
                this.sessionToken = response.data.data.session_token;
                return true;
            }
        } catch (error) {
            console.error('Authentication failed:', error.message);
        }
        return false;
    }
    
    async getServerStatus() {
        try {
            const response = await axios.get(`${this.serverUrl}/api/v1/work-units/status`);
            return response.data;
        } catch (error) {
            console.error('Failed to get server status:', error.message);
            return null;
        }
    }
    
    async getWorkUnitConfig() {
        try {
            const response = await axios.get(`${this.serverUrl}/api/v1/work-units/config`);
            return response.data;
        } catch (error) {
            console.error('Failed to get work unit config:', error.message);
            return null;
        }
    }
    
    async processWorkUnits() {
        console.log('Starting work unit processing...');
        
        while (true) {
            try {
                const status = await this.getServerStatus();
                if (status) {
                    console.log(`Server status: ${status.data.pending_units} pending, ` +
                               `${status.data.processing_units} processing`);
                }
                
                // Simulate work unit processing
                await new Promise(resolve => setTimeout(resolve, 5000));
                
            } catch (error) {
                console.error('Error in processing loop:', error.message);
                await new Promise(resolve => setTimeout(resolve, 10000));
            }
        }
    }
}

// Usage
async function main() {
    const client = new WorkUnitClient('http://localhost:8080', 'client_001', 'ak_1234567890abcdef');
    
    if (await client.authenticate()) {
        console.log('Authentication successful');
        await client.processWorkUnits();
    } else {
        console.log('Authentication failed');
    }
}

main().catch(console.error);
```

## Error Handling

### Common Error Responses

**Rate Limit Exceeded (429):**
```json
{
  "success": false,
  "error": "Rate limit exceeded",
  "error_code": 429
}
```

**Authentication Failed (401):**
```json
{
  "success": false,
  "error": "Authentication failed",
  "error_code": 401
}
```

**Invalid Request (400):**
```json
{
  "success": false,
  "error": "Missing required fields: client_id, auth_data",
  "error_code": 400
}
```

**Server Error (500):**
```json
{
  "success": false,
  "error": "Internal server error",
  "error_code": 500
}
```

### Error Handling Best Practices

1. **Always check response status codes**
2. **Implement exponential backoff for retries**
3. **Log errors for debugging**
4. **Handle network timeouts gracefully**
5. **Validate all input data**

## Best Practices

### Client Implementation

1. **Resource Management**
   - Monitor CPU and memory usage
   - Implement proper cleanup
   - Use connection pooling

2. **Error Handling**
   - Implement retry logic with backoff
   - Handle network failures gracefully
   - Log errors for debugging

3. **Security**
   - Store API keys securely
   - Use HTTPS for all communications
   - Validate all server responses

4. **Performance**
   - Use asynchronous processing
   - Implement proper caching
   - Monitor processing times

### Server Configuration

1. **Rate Limiting**
   - Set appropriate limits for your use case
   - Monitor rate limit violations
   - Adjust limits based on client behavior

2. **Security**
   - Enable all security features
   - Monitor security events
   - Regularly update certificates

3. **Monitoring**
   - Monitor system performance
   - Track work unit processing times
   - Alert on security violations

### Deployment

1. **Production Setup**
   - Use Let's Encrypt certificates
   - Configure proper firewall rules
   - Set up monitoring and alerting

2. **Scaling**
   - Monitor client capacity
   - Add more clients as needed
   - Balance load across clients

3. **Maintenance**
   - Regular security updates
   - Monitor system health
   - Backup configuration data

## Conclusion

The Work Unit Distribution API provides a robust, secure, and scalable solution for distributed propagation calculations. By following the documentation and best practices, you can implement clients that effectively contribute to the distributed computing network while maintaining security and performance.
