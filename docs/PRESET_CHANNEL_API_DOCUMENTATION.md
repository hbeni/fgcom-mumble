# Preset Channel API Documentation

## Overview

The Preset Channel API provides **read-only access** to radio preset channel configurations that are defined in server-side configuration files. This API allows external applications to query and retrieve preset information for various radio models, including the AN/PRC-152's 99 presets and other radio models with preset capabilities. **Preset channels are only defined and managed on the server side** - external applications cannot create, modify, or delete preset channels.

## Table of Contents

1. [Quick Start](#quick-start)
2. [API Endpoints](#api-endpoints)
3. [Data Structures](#data-structures)
4. [Preset Management](#preset-management)
5. [Search and Filtering](#search-and-filtering)
6. [Export/Import](#exportimport)
7. [Statistics](#statistics)
8. [Examples](#examples)
9. [Error Handling](#error-handling)

## Quick Start

### Basic Usage

```cpp
#include "lib/preset_channel_api.h"

using namespace PresetChannelAPI;

// Initialize the preset channel system
PresetChannelManager::initialize();

// Create a preset for AN/PRC-152
PresetChannelInfo preset;
preset.presetNumber = 1;
preset.channelNumber = 100;
preset.frequency = 30.125;  // 30.125 MHz
preset.label = "Tactical 1";
preset.description = "Primary tactical frequency";
preset.isActive = true;

// Set the preset
PresetChannelManager::setPresetChannel("AN/PRC-152", 1, 100, "Tactical 1", "Primary tactical frequency");

// Get the preset
PresetChannelInfo retrieved = PresetChannelManager::getPresetChannel("AN/PRC-152", 1);
```

### Using the Builder Pattern

```cpp
// Use the builder pattern for easier preset creation
PresetChannelBuilder builder;
PresetChannelInfo preset = builder
    .setPresetNumber(1)
    .setChannelNumber(100)
    .setFrequency(30.125)
    .setLabel("Tactical 1")
    .setDescription("Primary tactical frequency")
    .setActive(true)
    .addCustomProperty("encryption", "AES-256")
    .addCustomProperty("power", "high")
    .build();

// Validate the preset
if (builder.validate()) {
    PresetChannelManager::setPresetChannel("AN/PRC-152", preset.presetNumber, preset.channelNumber, 
                                          preset.label, preset.description);
}
```

## API Endpoints

### Base URL
```
http://localhost:8080/api/v1/preset-channels
```

### Authentication
```http
Authorization: Bearer <api_key>
Content-Type: application/json
```

## Data Structures

### PresetChannelInfo
```json
{
  "presetNumber": 1,
  "channelNumber": 100,
  "frequency": 30.125,
  "label": "Tactical 1",
  "description": "Primary tactical frequency",
  "isActive": true,
  "customProperties": {
    "encryption": "AES-256",
    "power": "high"
  }
}
```

### PresetAPIResponse
```json
{
  "success": true,
  "message": "Operation completed successfully",
  "data": "...",
  "errorCode": 0
}
```

## Preset Management

### Create Preset
```http
POST /api/v1/preset-channels/{radioModel}
Content-Type: application/json

{
  "presetNumber": 1,
  "channelNumber": 100,
  "frequency": 30.125,
  "label": "Tactical 1",
  "description": "Primary tactical frequency",
  "isActive": true,
  "customProperties": {
    "encryption": "AES-256",
    "power": "high"
  }
}
```

**Response:**
```json
{
  "success": true,
  "message": "Preset created successfully",
  "data": {
    "radioModel": "AN/PRC-152",
    "presetNumber": 1,
    "channelNumber": 100,
    "frequency": 30.125,
    "label": "Tactical 1"
  }
}
```

### Get Preset
```http
GET /api/v1/preset-channels/{radioModel}/{presetNumber}
```

**Response:**
```json
{
  "success": true,
  "message": "Preset retrieved successfully",
  "data": {
    "presetNumber": 1,
    "channelNumber": 100,
    "frequency": 30.125,
    "label": "Tactical 1",
    "description": "Primary tactical frequency",
    "isActive": true,
    "customProperties": {
      "encryption": "AES-256",
      "power": "high"
    }
  }
}
```

### Update Preset
```http
PUT /api/v1/preset-channels/{radioModel}/{presetNumber}
Content-Type: application/json

{
  "label": "Updated Tactical 1",
  "description": "Updated primary tactical frequency",
  "isActive": true
}
```

**Response:**
```json
{
  "success": true,
  "message": "Preset updated successfully",
  "data": {
    "radioModel": "AN/PRC-152",
    "presetNumber": 1,
    "updatedFields": ["label", "description", "isActive"]
  }
}
```

### Delete Preset
```http
DELETE /api/v1/preset-channels/{radioModel}/{presetNumber}
```

**Response:**
```json
{
  "success": true,
  "message": "Preset deleted successfully",
  "data": {
    "radioModel": "AN/PRC-152",
    "presetNumber": 1
  }
}
```

### Get All Presets
```http
GET /api/v1/preset-channels/{radioModel}
```

**Response:**
```json
{
  "success": true,
  "message": "Presets retrieved successfully",
  "data": {
    "radioModel": "AN/PRC-152",
    "presets": [
      {
        "presetNumber": 1,
        "channelNumber": 100,
        "frequency": 30.125,
        "label": "Tactical 1",
        "description": "Primary tactical frequency",
        "isActive": true
      },
      {
        "presetNumber": 2,
        "channelNumber": 200,
        "frequency": 30.25,
        "label": "Tactical 2",
        "description": "Secondary tactical frequency",
        "isActive": true
      }
    ],
    "totalCount": 2
  }
}
```

## Preset Operations

### Select Preset
```http
POST /api/v1/preset-channels/{radioModel}/{presetNumber}/select
```

**Response:**
```json
{
  "success": true,
  "message": "Preset selected successfully",
  "data": {
    "radioModel": "AN/PRC-152",
    "presetNumber": 1,
    "channelNumber": 100,
    "frequency": 30.125
  }
}
```

### Set Preset Label
```http
PUT /api/v1/preset-channels/{radioModel}/{presetNumber}/label
Content-Type: application/json

{
  "label": "New Label"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Preset label updated successfully",
  "data": {
    "radioModel": "AN/PRC-152",
    "presetNumber": 1,
    "label": "New Label"
  }
}
```

### Set Preset Description
```http
PUT /api/v1/preset-channels/{radioModel}/{presetNumber}/description
Content-Type: application/json

{
  "description": "New description"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Preset description updated successfully",
  "data": {
    "radioModel": "AN/PRC-152",
    "presetNumber": 1,
    "description": "New description"
  }
}
```

### Set Preset Active
```http
PUT /api/v1/preset-channels/{radioModel}/{presetNumber}/active
Content-Type: application/json

{
  "active": true
}
```

**Response:**
```json
{
  "success": true,
  "message": "Preset active status updated successfully",
  "data": {
    "radioModel": "AN/PRC-152",
    "presetNumber": 1,
    "isActive": true
  }
}
```

### Set Preset Channel
```http
PUT /api/v1/preset-channels/{radioModel}/{presetNumber}/channel
Content-Type: application/json

{
  "channelNumber": 150
}
```

**Response:**
```json
{
  "success": true,
  "message": "Preset channel updated successfully",
  "data": {
    "radioModel": "AN/PRC-152",
    "presetNumber": 1,
    "channelNumber": 150,
    "frequency": 31.875
  }
}
```

### Set Preset Frequency
```http
PUT /api/v1/preset-channels/{radioModel}/{presetNumber}/frequency
Content-Type: application/json

{
  "frequency": 31.875
}
```

**Response:**
```json
{
  "success": true,
  "message": "Preset frequency updated successfully",
  "data": {
    "radioModel": "AN/PRC-152",
    "presetNumber": 1,
    "channelNumber": 150,
    "frequency": 31.875
  }
}
```

## Search and Filtering

### Search Presets
```http
GET /api/v1/preset-channels/{radioModel}/search?q={query}
```

**Response:**
```json
{
  "success": true,
  "message": "Search completed successfully",
  "data": {
    "query": "tactical",
    "results": [
      {
        "presetNumber": 1,
        "channelNumber": 100,
        "frequency": 30.125,
        "label": "Tactical 1",
        "description": "Primary tactical frequency"
      },
      {
        "presetNumber": 2,
        "channelNumber": 200,
        "frequency": 30.25,
        "label": "Tactical 2",
        "description": "Secondary tactical frequency"
      }
    ],
    "totalResults": 2
  }
}
```

### Get Presets by Frequency
```http
GET /api/v1/preset-channels/{radioModel}/frequency/{frequency}?tolerance={tolerance}
```

**Response:**
```json
{
  "success": true,
  "message": "Presets filtered by frequency",
  "data": {
    "frequency": 30.125,
    "tolerance": 0.001,
    "presets": [
      {
        "presetNumber": 1,
        "channelNumber": 100,
        "frequency": 30.125,
        "label": "Tactical 1"
      }
    ],
    "totalCount": 1
  }
}
```

### Get Presets by Channel
```http
GET /api/v1/preset-channels/{radioModel}/channel/{channelNumber}
```

**Response:**
```json
{
  "success": true,
  "message": "Presets filtered by channel",
  "data": {
    "channelNumber": 100,
    "presets": [
      {
        "presetNumber": 1,
        "channelNumber": 100,
        "frequency": 30.125,
        "label": "Tactical 1"
      }
    ],
    "totalCount": 1
  }
}
```

### Get Active Presets
```http
GET /api/v1/preset-channels/{radioModel}/active
```

**Response:**
```json
{
  "success": true,
  "message": "Active presets retrieved successfully",
  "data": {
    "radioModel": "AN/PRC-152",
    "presets": [
      {
        "presetNumber": 1,
        "channelNumber": 100,
        "frequency": 30.125,
        "label": "Tactical 1",
        "isActive": true
      },
      {
        "presetNumber": 2,
        "channelNumber": 200,
        "frequency": 30.25,
        "label": "Tactical 2",
        "isActive": true
      }
    ],
    "totalCount": 2
  }
}
```

### Get Inactive Presets
```http
GET /api/v1/preset-channels/{radioModel}/inactive
```

**Response:**
```json
{
  "success": true,
  "message": "Inactive presets retrieved successfully",
  "data": {
    "radioModel": "AN/PRC-152",
    "presets": [
      {
        "presetNumber": 3,
        "channelNumber": 300,
        "frequency": 30.375,
        "label": "Tactical 3",
        "isActive": false
      }
    ],
    "totalCount": 1
  }
}
```

## Statistics

### Get Preset Statistics
```http
GET /api/v1/preset-channels/{radioModel}/statistics
```

**Response:**
```json
{
  "success": true,
  "message": "Preset statistics retrieved successfully",
  "data": {
    "radioModel": "AN/PRC-152",
    "totalPresets": 15,
    "activePresets": 12,
    "inactivePresets": 3,
    "frequencyRange": {
      "min": 30.0,
      "max": 87.975
    },
    "channelDistribution": {
      "1-100": 5,
      "101-200": 4,
      "201-300": 3,
      "301-400": 2,
      "401-500": 1
    },
    "labelDistribution": {
      "Tactical": 8,
      "Emergency": 3,
      "Training": 2,
      "Test": 2
    }
  }
}
```

### Get Preset Count
```http
GET /api/v1/preset-channels/{radioModel}/count
```

**Response:**
```json
{
  "success": true,
  "message": "Preset count retrieved successfully",
  "data": {
    "radioModel": "AN/PRC-152",
    "totalPresets": 15
  }
}
```

### Get Active Preset Count
```http
GET /api/v1/preset-channels/{radioModel}/count/active
```

**Response:**
```json
{
  "success": true,
  "message": "Active preset count retrieved successfully",
  "data": {
    "radioModel": "AN/PRC-152",
    "activePresets": 12
  }
}
```

### Get Inactive Preset Count
```http
GET /api/v1/preset-channels/{radioModel}/count/inactive
```

**Response:**
```json
{
  "success": true,
  "message": "Inactive preset count retrieved successfully",
  "data": {
    "radioModel": "AN/PRC-152",
    "inactivePresets": 3
  }
}
```

### Get Preset Frequency Range
```http
GET /api/v1/preset-channels/{radioModel}/frequency-range
```

**Response:**
```json
{
  "success": true,
  "message": "Preset frequency range retrieved successfully",
  "data": {
    "radioModel": "AN/PRC-152",
    "frequencyRange": {
      "min": 30.0,
      "max": 87.975,
      "span": 57.975
    }
  }
}
```

### Get Preset Channel Distribution
```http
GET /api/v1/preset-channels/{radioModel}/channel-distribution
```

**Response:**
```json
{
  "success": true,
  "message": "Preset channel distribution retrieved successfully",
  "data": {
    "radioModel": "AN/PRC-152",
    "channelDistribution": {
      "1-100": 5,
      "101-200": 4,
      "201-300": 3,
      "301-400": 2,
      "401-500": 1
    }
  }
}
```

## Export/Import

### Export Presets
```http
POST /api/v1/preset-channels/{radioModel}/export
Content-Type: application/json

{
  "filePath": "exported_presets.json"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Presets exported successfully",
  "data": {
    "radioModel": "AN/PRC-152",
    "filePath": "exported_presets.json",
    "presetCount": 15,
    "exportSize": "8.5 KB"
  }
}
```

### Import Presets
```http
POST /api/v1/preset-channels/{radioModel}/import
Content-Type: application/json

{
  "filePath": "imported_presets.json",
  "overwrite": false
}
```

**Response:**
```json
{
  "success": true,
  "message": "Presets imported successfully",
  "data": {
    "radioModel": "AN/PRC-152",
    "filePath": "imported_presets.json",
    "importedCount": 10,
    "skippedCount": 0,
    "errorCount": 0
  }
}
```

### Export to JSON
```http
GET /api/v1/preset-channels/{radioModel}/export/json
```

**Response:**
```json
{
  "success": true,
  "message": "Presets exported to JSON successfully",
  "data": {
    "radioModel": "AN/PRC-152",
    "jsonData": "[{\"presetNumber\":1,\"channelNumber\":100,\"frequency\":30.125,\"label\":\"Tactical 1\",\"description\":\"Primary tactical frequency\",\"isActive\":true,\"customProperties\":{}}]",
    "presetCount": 1
  }
}
```

### Import from JSON
```http
POST /api/v1/preset-channels/{radioModel}/import/json
Content-Type: application/json

{
  "jsonData": "[{\"presetNumber\":1,\"channelNumber\":100,\"frequency\":30.125,\"label\":\"Tactical 1\",\"description\":\"Primary tactical frequency\",\"isActive\":true,\"customProperties\":{}}]",
  "overwrite": false
}
```

**Response:**
```json
{
  "success": true,
  "message": "Presets imported from JSON successfully",
  "data": {
    "radioModel": "AN/PRC-152",
    "importedCount": 1,
    "skippedCount": 0,
    "errorCount": 0
  }
}
```

## Examples

### Example 1: Create Tactical Presets for AN/PRC-152

```bash
# Create preset 1
curl -X POST http://localhost:8080/api/v1/preset-channels/AN/PRC-152 \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your_api_key" \
  -d '{
    "presetNumber": 1,
    "channelNumber": 100,
    "frequency": 30.125,
    "label": "Tactical 1",
    "description": "Primary tactical frequency",
    "isActive": true,
    "customProperties": {
      "encryption": "AES-256",
      "power": "high"
    }
  }'

# Create preset 2
curl -X POST http://localhost:8080/api/v1/preset-channels/AN/PRC-152 \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your_api_key" \
  -d '{
    "presetNumber": 2,
    "channelNumber": 200,
    "frequency": 30.25,
    "label": "Tactical 2",
    "description": "Secondary tactical frequency",
    "isActive": true,
    "customProperties": {
      "encryption": "AES-256",
      "power": "high"
    }
  }'
```

### Example 2: Get All Presets

```bash
curl -X GET http://localhost:8080/api/v1/preset-channels/AN/PRC-152 \
  -H "Authorization: Bearer your_api_key"
```

### Example 3: Search Presets

```bash
curl -X GET "http://localhost:8080/api/v1/preset-channels/AN/PRC-152/search?q=tactical" \
  -H "Authorization: Bearer your_api_key"
```

### Example 4: Export Presets

```bash
curl -X POST http://localhost:8080/api/v1/preset-channels/AN/PRC-152/export \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your_api_key" \
  -d '{
    "filePath": "an_prc152_presets.json"
  }'
```

### Example 5: Get Preset Statistics

```bash
curl -X GET http://localhost:8080/api/v1/preset-channels/AN/PRC-152/statistics \
  -H "Authorization: Bearer your_api_key"
```

## Error Handling

### Error Response Format
```json
{
  "success": false,
  "message": "Error description",
  "data": null,
  "errorCode": 400
}
```

### Common Error Codes

| Code | Description |
|------|-------------|
| 400 | Bad Request - Invalid input data |
| 401 | Unauthorized - Invalid API key |
| 404 | Not Found - Preset not found |
| 409 | Conflict - Preset already exists |
| 422 | Unprocessable Entity - Validation error |
| 500 | Internal Server Error - Server error |

### Error Examples

#### Preset Not Found
```json
{
  "success": false,
  "message": "Preset 999 not found for radio model AN/PRC-152",
  "data": null,
  "errorCode": 404
}
```

#### Validation Error
```json
{
  "success": false,
  "message": "Preset validation failed",
  "data": {
    "errors": [
      "Preset number must be between 1 and 99",
      "Channel number must be between 1 and 4638",
      "Frequency must be between 30.0 and 87.975 MHz"
    ]
  },
  "errorCode": 422
}
```

#### Conflict Error
```json
{
  "success": false,
  "message": "Preset 1 already exists for radio model AN/PRC-152",
  "data": {
    "radioModel": "AN/PRC-152",
    "presetNumber": 1
  },
  "errorCode": 409
}
```

## Rate Limiting

The API implements rate limiting to prevent abuse:

- **Rate Limit**: 1000 requests per hour per API key
- **Burst Limit**: 100 requests per minute
- **Headers**: 
  - `X-RateLimit-Limit`: Maximum requests per hour
  - `X-RateLimit-Remaining`: Remaining requests in current hour
  - `X-RateLimit-Reset`: Time when rate limit resets

## Authentication

The API uses Bearer token authentication:

```http
Authorization: Bearer <your_api_key>
```

API keys can be obtained from the system administrator and should be kept secure.

## Versioning

The API uses semantic versioning:

- **Current Version**: v1
- **Version Header**: `API-Version: v1`
- **Backward Compatibility**: Maintained for at least 2 major versions

## Support

For additional support and documentation:

- **API Documentation**: [PRESET_CHANNEL_API_DOCUMENTATION.md](PRESET_CHANNEL_API_DOCUMENTATION.md)
- **Configuration Guide**: [RADIO_MODEL_CONFIGURATION_GUIDE.md](RADIO_MODEL_CONFIGURATION_GUIDE.md)
- **Examples**: [PRESET_CHANNEL_EXAMPLES.md](PRESET_CHANNEL_EXAMPLES.md)
- **Troubleshooting**: [PRESET_CHANNEL_TROUBLESHOOTING.md](PRESET_CHANNEL_TROUBLESHOOTING.md)
