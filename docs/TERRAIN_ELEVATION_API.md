# Terrain Elevation API Documentation

## Overview

The Terrain Elevation API provides comprehensive terrain awareness capabilities for FGCom-mumble, including ASTER GDEM integration, terrain obstruction detection, Fresnel zone calculations, and diffraction effects. This API enables realistic radio propagation simulation that accounts for mountains, buildings, and other terrain features.

## Features

- **ASTER GDEM Integration**: Global 30-meter resolution elevation data
- **Terrain Obstruction Detection**: Automatic detection of mountains and buildings blocking radio signals
- **Fresnel Zone Analysis**: Radio wave clearance calculations for optimal propagation
- **Diffraction Effects**: Signal bending around obstacles
- **Line-of-Sight Calculations**: Direct visibility determination between points
- **Terrain Profile Generation**: Elevation profiles along communication paths
- **Caching System**: Efficient tile and profile caching for performance

## API Endpoints

### 1. Terrain Elevation

**GET /api/v1/terrain/elevation**

Get elevation data and terrain analysis between two points.

**Parameters:**
- `lat1` (required): Starting latitude
- `lon1` (required): Starting longitude  
- `lat2` (required): Ending latitude
- `lon2` (required): Ending longitude
- `alt1` (optional): Starting altitude in meters (default: 0)
- `alt2` (optional): Ending altitude in meters (default: 0)
- `frequency_mhz` (optional): Radio frequency in MHz (default: 144.5)

**Example Request:**
```bash
curl "http://localhost:8080/api/v1/terrain/elevation?lat1=40.7128&lon1=-74.0060&lat2=40.7589&lon2=-73.9851&alt1=100&alt2=200&frequency_mhz=144.5"
```

**Response:**
```json
{
  "success": true,
  "data": {
    "elevation1": 100.0,
    "elevation2": 200.0,
    "terrain_profile": {
      "points": [
        {
          "latitude": 40.7128,
          "longitude": -74.0060,
          "elevation_m": 100.0,
          "distance_km": 0.0
        },
        {
          "latitude": 40.7358,
          "longitude": -73.9955,
          "elevation_m": 150.0,
          "distance_km": 5.2
        }
      ],
      "max_elevation_m": 500.0,
      "min_elevation_m": 50.0,
      "average_elevation_m": 150.0,
      "line_of_sight_clear": true
    },
    "obstruction_analysis": {
      "blocked": false,
      "obstruction_height_m": 0.0,
      "terrain_loss_db": 0.0,
      "diffraction_loss_db": 0.0,
      "fresnel_zone_clear": true
    }
  }
}
```

### 2. Terrain Obstruction Analysis

**GET /api/v1/terrain/obstruction**

Analyze terrain obstruction between two points.

**Parameters:**
- `lat1` (required): Starting latitude
- `lon1` (required): Starting longitude
- `lat2` (required): Ending latitude  
- `lon2` (required): Ending longitude
- `alt1` (required): Starting altitude in meters
- `alt2` (required): Ending altitude in meters
- `frequency_mhz` (optional): Radio frequency in MHz (default: 144.5)

**Example Request:**
```bash
curl "http://localhost:8080/api/v1/terrain/obstruction?lat1=40.7128&lon1=-74.0060&lat2=40.7589&lon2=-73.9851&alt1=100&alt2=200&frequency_mhz=144.5"
```

**Response:**
```json
{
  "success": true,
  "data": {
    "blocked": false,
    "obstruction_height_m": 0.0,
    "obstruction_distance_km": 0.0,
    "terrain_loss_db": 0.0,
    "diffraction_loss_db": 0.0,
    "fresnel_zone_clear": true,
    "fresnel_clearance_percent": 100.0,
    "obstruction_type": "none"
  }
}
```

### 3. Terrain Profile

**GET /api/v1/terrain/profile**

Get detailed terrain profile between two points.

**Parameters:**
- `lat1` (required): Starting latitude
- `lon1` (required): Starting longitude
- `lat2` (required): Ending latitude
- `lon2` (required): Ending longitude
- `resolution_m` (optional): Profile resolution in meters (default: 30)

**Example Request:**
```bash
curl "http://localhost:8080/api/v1/terrain/profile?lat1=40.7128&lon1=-74.0060&lat2=40.7589&lon2=-73.9851&resolution_m=30"
```

**Response:**
```json
{
  "success": true,
  "data": {
    "profile": {
      "points": [
        {
          "latitude": 40.7128,
          "longitude": -74.0060,
          "elevation_m": 100.0,
          "distance_km": 0.0
        }
      ],
      "max_elevation_m": 500.0,
      "min_elevation_m": 50.0,
      "average_elevation_m": 150.0,
      "line_of_sight_clear": true,
      "obstruction_height_m": 0.0,
      "obstruction_distance_km": 0.0
    },
    "statistics": {
      "total_points": 100,
      "distance_km": 10.5,
      "resolution_m": 30
    }
  }
}
```

### 4. ASTER GDEM Status

**GET /api/v1/terrain/aster-gdem/status**

Get ASTER GDEM system status and statistics.

**Example Request:**
```bash
curl "http://localhost:8080/api/v1/terrain/aster-gdem/status"
```

**Response:**
```json
{
  "success": true,
  "data": {
    "enabled": true,
    "data_path": "/usr/share/fgcom-mumble/aster_gdem",
    "tiles_loaded": 25,
    "cache_size_mb": 500,
    "auto_download": false,
    "download_url": "https://e4ftl01.cr.usgs.gov/ASTT/ASTGTM.003/2000.03.01/",
    "statistics": {
      "tiles_loaded": 25,
      "profiles_calculated": 150,
      "cache_hits": 1200,
      "cache_misses": 300,
      "cache_hit_rate": 0.8,
      "memory_usage_mb": 500
    }
  }
}
```

## Configuration

### Terrain Elevation Configuration

```ini
[terrain_elevation]
# Enable/disable terrain elevation functionality
enabled = false

# Elevation data source (aster_gdem, srtm, openelevation_api, google_elevation_api)
elevation_source = aster_gdem
```

### ASTER GDEM Configuration

```ini
[aster_gdem]
# Enable ASTER GDEM terrain data
enabled = false

# Path to ASTER GDEM data directory
data_path = /usr/share/fgcom-mumble/aster_gdem

# Enable automatic tile downloading
auto_download = false

# Download URL for ASTER GDEM tiles
download_url = https://e4ftl01.cr.usgs.gov/ASTT/ASTGTM.003/2000.03.01/

# Cache size in MB (0 = unlimited)
cache_size_mb = 1000

# Enable terrain obstruction detection
enable_obstruction_detection = true

# Terrain resolution in meters (30m for ASTER GDEM)
terrain_resolution_m = 30

# Enable Fresnel zone calculations
enable_fresnel_zone = true

# Fresnel zone clearance percentage (0.6 = 60% clearance)
fresnel_clearance_percent = 0.6

# Enable diffraction effects
enable_diffraction = true

# Maximum terrain profile distance in km
max_profile_distance_km = 100.0

# Enable terrain profile caching
enable_profile_caching = true

# Profile cache size in MB
profile_cache_size_mb = 500
```

## Usage Examples

### Python Integration

```python
import requests

class FGComTerrainClient:
    def __init__(self, server_url):
        self.server_url = server_url
    
    def get_elevation(self, lat1, lon1, lat2, lon2, alt1=0, alt2=0, frequency_mhz=144.5):
        """Get terrain elevation and analysis between two points"""
        params = {
            'lat1': lat1, 'lon1': lon1,
            'lat2': lat2, 'lon2': lon2,
            'alt1': alt1, 'alt2': alt2,
            'frequency_mhz': frequency_mhz
        }
        
        response = requests.get(f"{self.server_url}/api/v1/terrain/elevation", params=params)
        return response.json()
    
    def check_obstruction(self, lat1, lon1, lat2, lon2, alt1, alt2, frequency_mhz=144.5):
        """Check if terrain blocks communication"""
        params = {
            'lat1': lat1, 'lon1': lon1,
            'lat2': lat2, 'lon2': lon2,
            'alt1': alt1, 'alt2': alt2,
            'frequency_mhz': frequency_mhz
        }
        
        response = requests.get(f"{self.server_url}/api/v1/terrain/obstruction", params=params)
        return response.json()
    
    def get_terrain_profile(self, lat1, lon1, lat2, lon2, resolution_m=30):
        """Get terrain profile between two points"""
        params = {
            'lat1': lat1, 'lon1': lon1,
            'lat2': lat2, 'lon2': lon2,
            'resolution_m': resolution_m
        }
        
        response = requests.get(f"{self.server_url}/api/v1/terrain/profile", params=params)
        return response.json()

# Usage example
client = FGComTerrainClient("http://localhost:8080")

# Check if terrain blocks communication between two aircraft
result = client.check_obstruction(
    lat1=40.7128, lon1=-74.0060, alt1=1000,  # Aircraft 1
    lat2=40.7589, lon2=-73.9851, alt2=1200,  # Aircraft 2
    frequency_mhz=144.5
)

if result['success']:
    if result['data']['blocked']:
        print("Terrain blocks communication")
        print(f"Obstruction height: {result['data']['obstruction_height_m']}m")
        print(f"Terrain loss: {result['data']['terrain_loss_db']}dB")
    else:
        print("Communication path is clear")
```

### C++ Integration

```cpp
#include <httplib.h>
#include <json/json.h>

class FGComTerrainClient {
private:
    std::string server_url;
    httplib::Client client;
    
public:
    FGComTerrainClient(const std::string& url) : server_url(url), client(url) {}
    
    struct TerrainResult {
        bool blocked;
        double obstruction_height_m;
        double terrain_loss_db;
        double diffraction_loss_db;
        bool fresnel_zone_clear;
    };
    
    TerrainResult checkObstruction(double lat1, double lon1, double alt1,
                                 double lat2, double lon2, double alt2,
                                 double frequency_mhz = 144.5) {
        
        std::string path = "/api/v1/terrain/obstruction";
        path += "?lat1=" + std::to_string(lat1);
        path += "&lon1=" + std::to_string(lon1);
        path += "&lat2=" + std::to_string(lat2);
        path += "&lon2=" + std::to_string(lon2);
        path += "&alt1=" + std::to_string(alt1);
        path += "&alt2=" + std::to_string(alt2);
        path += "&frequency_mhz=" + std::to_string(frequency_mhz);
        
        auto response = client.Get(path.c_str());
        
        if (response && response->status == 200) {
            Json::Value json_response;
            Json::CharReaderBuilder reader;
            std::stringstream ss(response->body);
            Json::parseFromStream(reader, ss, &json_response, nullptr);
            
            TerrainResult result;
            if (json_response["success"].asBool()) {
                auto data = json_response["data"];
                result.blocked = data["blocked"].asBool();
                result.obstruction_height_m = data["obstruction_height_m"].asDouble();
                result.terrain_loss_db = data["terrain_loss_db"].asDouble();
                result.diffraction_loss_db = data["diffraction_loss_db"].asDouble();
                result.fresnel_zone_clear = data["fresnel_zone_clear"].asBool();
            }
            
            return result;
        }
        
        return TerrainResult{true, 0.0, 0.0, 0.0, false};
    }
};

// Usage example
FGComTerrainClient client("http://localhost:8080");

TerrainResult result = client.checkObstruction(
    40.7128, -74.0060, 1000,  // Aircraft 1
    40.7589, -73.9851, 1200,  // Aircraft 2
    144.5  // VHF frequency
);

if (result.blocked) {
    std::cout << "Terrain blocks communication" << std::endl;
    std::cout << "Obstruction height: " << result.obstruction_height_m << "m" << std::endl;
    std::cout << "Terrain loss: " << result.terrain_loss_db << "dB" << std::endl;
} else {
    std::cout << "Communication path is clear" << std::endl;
}
```

### JavaScript/Node.js Integration

```javascript
const axios = require('axios');

class FGComTerrainClient {
    constructor(serverUrl) {
        this.serverUrl = serverUrl;
    }
    
    async checkObstruction(lat1, lon1, alt1, lat2, lon2, alt2, frequencyMhz = 144.5) {
        try {
            const response = await axios.get(`${this.serverUrl}/api/v1/terrain/obstruction`, {
                params: {
                    lat1, lon1, alt1,
                    lat2, lon2, alt2,
                    frequency_mhz: frequencyMhz
                }
            });
            
            return response.data;
        } catch (error) {
            console.error('Terrain obstruction check failed:', error);
            return null;
        }
    }
    
    async getTerrainProfile(lat1, lon1, lat2, lon2, resolutionM = 30) {
        try {
            const response = await axios.get(`${this.serverUrl}/api/v1/terrain/profile`, {
                params: {
                    lat1, lon1, lat2, lon2,
                    resolution_m: resolutionM
                }
            });
            
            return response.data;
        } catch (error) {
            console.error('Terrain profile request failed:', error);
            return null;
        }
    }
}

// Usage example
const client = new FGComTerrainClient('http://localhost:8080');

async function checkCommunication() {
    const result = await client.checkObstruction(
        40.7128, -74.0060, 1000,  // Aircraft 1
        40.7589, -73.9851, 1200,  // Aircraft 2
        144.5  // VHF frequency
    );
    
    if (result && result.success) {
        if (result.data.blocked) {
            console.log('Terrain blocks communication');
            console.log(`Obstruction height: ${result.data.obstruction_height_m}m`);
            console.log(`Terrain loss: ${result.data.terrain_loss_db}dB`);
        } else {
            console.log('Communication path is clear');
        }
    }
}

checkCommunication();
```

## Error Handling

All API endpoints return standardized error responses:

```json
{
  "success": false,
  "error": "Error description",
  "error_code": 400
}
```

Common error codes:
- `400`: Bad Request (invalid parameters)
- `404`: Not Found (endpoint not available)
- `500`: Internal Server Error (server-side error)
- `503`: Service Unavailable (terrain service disabled)

## Performance Considerations

- **Tile Caching**: ASTER GDEM tiles are cached in memory for fast access
- **Profile Caching**: Terrain profiles are cached to avoid recalculation
- **Async Processing**: Terrain analysis runs in background threads
- **Memory Management**: Configurable cache sizes prevent memory overflow
- **Lazy Loading**: Tiles are loaded only when needed

## Security

- **Rate Limiting**: API calls are rate-limited to prevent abuse
- **Input Validation**: All parameters are validated before processing
- **Error Sanitization**: Error messages don't expose sensitive information
- **Access Control**: Terrain features can be disabled via configuration

## Troubleshooting

### Common Issues

1. **Terrain data not found**:
   - Check ASTER GDEM data directory exists
   - Verify tile files are present and readable
   - Enable auto-download if tiles are missing

2. **High memory usage**:
   - Reduce cache sizes in configuration
   - Clear terrain cache periodically
   - Use lower resolution for terrain profiles

3. **Slow performance**:
   - Enable profile caching
   - Increase cache sizes
   - Use async processing for large requests

### Debug Mode

Enable debug logging to troubleshoot terrain issues:

```ini
[debug]
terrain_elevation = true
aster_gdem = true
```

This will log detailed information about tile loading, cache operations, and terrain calculations.

## Future Enhancements

- **Real-time Updates**: Live terrain data from satellite sources
- **3D Visualization**: Terrain profile visualization tools
- **Machine Learning**: Predictive terrain obstruction modeling
- **Multi-source Data**: Integration with multiple elevation datasets
- **Cloud Processing**: Distributed terrain analysis
