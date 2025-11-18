# Radio Model API Reference

## Overview

The Radio Model API provides **read-only** programmatic access to the FGCom-mumble radio model configuration system. This API allows external applications to **query and retrieve** radio equipment specifications that are defined on the server side. **Radio models are only defined and managed on the server side** - external applications cannot create, modify, or delete radio models.

## Table of Contents

1. [API Endpoints](#api-endpoints)
2. [Data Structures](#data-structures)
3. [Configuration Management](#configuration-management)
4. [Model Operations](#model-operations)
5. [Channel Operations](#channel-operations)
6. [Search and Filtering](#search-and-filtering)
7. [Export/Import](#exportimport)
8. [Statistics](#statistics)
9. [Error Handling](#error-handling)
10. [Examples](#examples)

## API Endpoints

### Base URL
```
http://localhost:8080/api/v1/radio-models
```

### Authentication
```http
Authorization: Bearer <api_key>
Content-Type: application/json
```

## Data Structures

### RadioModelInfo
```json
{
  "modelName": "AN/PRC-152",
  "manufacturer": "USA",
  "country": "USA",
  "alliance": "NATO",
  "era": "Modern",
  "usage": "Multiband Inter/Intra Team Radio II",
  "frequencyStartMHz": 30.0,
  "frequencyEndMHz": 87.975,
  "channelSpacingKHz": 12.5,
  "totalChannels": 4638,
  "portablePowerWatts": 2.0,
  "vehiclePowerWatts": 20.0,
  "encryptionCapable": true,
  "gpsCapable": true,
  "dataCapable": true,
  "networkCapable": true,
  "advancedEncryption": true,
  "supportedModes": ["FM", "AM", "CW", "Digital"],
  "presetChannels": ["1", "100", "500", "1000"],
  "customProperties": {
    "encryption_type": "AES-256",
    "network_protocol": "IP"
  }
}
```

### APIResponse
```json
{
  "success": true,
  "message": "Operation completed successfully",
  "data": "...",
  "errorCode": 0
}
```

## Configuration Management

### Initialize API
```http
POST /api/v1/radio-models/initialize
Content-Type: application/json

{
  "configPath": "radio_models.json"
}
```

**Response:**
```json
{
  "success": true,
  "message": "API initialized successfully",
  "data": {
    "configPath": "radio_models.json",
    "modelCount": 15
  }
}
```

### Get API Status
```http
GET /api/v1/radio-models/status
```

**Response:**
```json
{
  "success": true,
  "message": "API is running",
  "data": {
    "version": "1.0.0",
    "uptime": "2h 30m",
    "modelCount": 15,
    "lastUpdate": "2024-01-15T10:30:00Z"
  }
}
```

## Model Operations

### Get Model (READ-ONLY)
```http
GET /api/v1/radio-models/{modelName}
```

**Response:**
```json
{
  "success": true,
  "message": "Model retrieved successfully",
  "data": {
    "modelName": "AN/PRC-152",
    "manufacturer": "USA",
    "country": "USA",
    "alliance": "NATO",
    "era": "Modern",
    "usage": "Multiband Inter/Intra Team Radio II",
    "frequencyStartMHz": 30.0,
    "frequencyEndMHz": 87.975,
    "channelSpacingKHz": 12.5,
    "totalChannels": 4638,
    "presetChannels": 99,
    "portablePowerWatts": 2.0,
    "vehiclePowerWatts": 20.0,
    "encryptionCapable": true,
    "gpsCapable": true,
    "dataCapable": true,
    "networkCapable": true,
    "advancedEncryption": true,
    "supportedModes": ["FM", "AM", "CW", "Digital"],
    "presetChannels": ["1", "100", "500", "1000"]
  }
}
```

**Note:** Radio models are defined on the server side only. External applications cannot create, modify, or delete radio models.

### Get Model
```http
GET /api/v1/radio-models/{modelName}
```

**Response:**
```json
{
  "success": true,
  "message": "Model retrieved successfully",
  "data": {
    "modelName": "AN/PRC-152",
    "manufacturer": "USA",
    "country": "USA",
    "alliance": "NATO",
    "era": "Modern",
    "usage": "Multiband Inter/Intra Team Radio II",
    "frequencyStartMHz": 30.0,
    "frequencyEndMHz": 87.975,
    "channelSpacingKHz": 12.5,
    "totalChannels": 4638,
    "portablePowerWatts": 2.0,
    "vehiclePowerWatts": 20.0,
    "encryptionCapable": true,
    "gpsCapable": true,
    "dataCapable": true,
    "networkCapable": true,
    "advancedEncryption": true,
    "supportedModes": ["FM", "AM", "CW", "Digital"],
    "presetChannels": ["1", "100", "500", "1000"],
    "customProperties": {
      "encryption_type": "AES-256",
      "network_protocol": "IP"
    }
  }
}
```

### Get All Models (READ-ONLY)
```http
GET /api/v1/radio-models
```

**Response:**
```json
{
  "success": true,
  "message": "Models retrieved successfully",
  "data": {
    "models": [
      {
        "modelName": "AN/PRC-77",
        "manufacturer": "USA",
        "country": "USA",
        "alliance": "NATO",
        "era": "Cold War",
        "usage": "Legacy VHF Tactical Radio",
        "totalChannels": 2319
      },
      {
        "modelName": "AN/PRC-148",
        "manufacturer": "USA",
        "country": "USA",
        "alliance": "NATO",
        "era": "Modern",
        "usage": "Multiband Inter/Intra Team Radio",
        "totalChannels": 2319
      },
      {
        "modelName": "AN/PRC-152",
        "manufacturer": "USA",
        "country": "USA",
        "alliance": "NATO",
        "era": "Modern",
        "usage": "Multiband Inter/Intra Team Radio II",
        "totalChannels": 4638
      }
    ],
    "totalCount": 3
  }
}
```

**Note:** Radio models are defined on the server side only. External applications cannot create, modify, or delete radio models.

### Get All Models
```http
GET /api/v1/radio-models
```

**Response:**
```json
{
  "success": true,
  "message": "Models retrieved successfully",
  "data": {
    "models": [
      {
        "modelName": "AN/PRC-77",
        "manufacturer": "USA",
        "country": "USA",
        "alliance": "NATO",
        "era": "Cold War",
        "usage": "Legacy VHF Tactical Radio",
        "totalChannels": 2319
      },
      {
        "modelName": "AN/PRC-148",
        "manufacturer": "USA",
        "country": "USA",
        "alliance": "NATO",
        "era": "Modern",
        "usage": "Multiband Inter/Intra Team Radio",
        "totalChannels": 2319
      },
      {
        "modelName": "AN/PRC-152",
        "manufacturer": "USA",
        "country": "USA",
        "alliance": "NATO",
        "era": "Modern",
        "usage": "Multiband Inter/Intra Team Radio II",
        "totalChannels": 4638
      }
    ],
    "totalCount": 3
  }
}
```

## Channel Operations

### Get Channel Frequency
```http
GET /api/v1/radio-models/{modelName}/channels/{channel}/frequency
```

**Response:**
```json
{
  "success": true,
  "message": "Channel frequency retrieved successfully",
  "data": {
    "modelName": "AN/PRC-152",
    "channel": 1,
    "frequency": 30.0,
    "frequencyUnit": "MHz"
  }
}
```

### Get Frequency Channel
```http
GET /api/v1/radio-models/{modelName}/frequencies/{frequency}/channel
```

**Response:**
```json
{
  "success": true,
  "message": "Frequency channel retrieved successfully",
  "data": {
    "modelName": "AN/PRC-152",
    "frequency": 30.025,
    "channel": 3,
    "frequencyUnit": "MHz"
  }
}
```

### Get All Channels
```http
GET /api/v1/radio-models/{modelName}/channels
```

**Response:**
```json
{
  "success": true,
  "message": "Channels retrieved successfully",
  "data": {
    "modelName": "AN/PRC-152",
    "totalChannels": 4638,
    "channels": [
      {
        "channel": 1,
        "frequency": 30.0
      },
      {
        "channel": 2,
        "frequency": 30.0125
      },
      {
        "channel": 3,
        "frequency": 30.025
      }
    ]
  }
}
```

### Validate Channel
```http
GET /api/v1/radio-models/{modelName}/channels/{channel}/validate
```

**Response:**
```json
{
  "success": true,
  "message": "Channel validation completed",
  "data": {
    "modelName": "AN/PRC-152",
    "channel": 1,
    "valid": true,
    "frequency": 30.0
  }
}
```

### Validate Frequency
```http
GET /api/v1/radio-models/{modelName}/frequencies/{frequency}/validate
```

**Response:**
```json
{
  "success": true,
  "message": "Frequency validation completed",
  "data": {
    "modelName": "AN/PRC-152",
    "frequency": 30.025,
    "valid": true,
    "channel": 3
  }
}
```

## Search and Filtering

### Search Models
```http
GET /api/v1/radio-models/search?q={query}
```

**Response:**
```json
{
  "success": true,
  "message": "Search completed successfully",
  "data": {
    "query": "NATO",
    "results": [
      {
        "modelName": "AN/PRC-77",
        "manufacturer": "USA",
        "alliance": "NATO",
        "era": "Cold War"
      },
      {
        "modelName": "AN/PRC-148",
        "manufacturer": "USA",
        "alliance": "NATO",
        "era": "Modern"
      }
    ],
    "totalResults": 2
  }
}
```

### Filter by Country
```http
GET /api/v1/radio-models?country={country}
```

**Response:**
```json
{
  "success": true,
  "message": "Models filtered by country",
  "data": {
    "country": "USA",
    "models": [
      {
        "modelName": "AN/PRC-77",
        "manufacturer": "USA",
        "country": "USA",
        "alliance": "NATO"
      },
      {
        "modelName": "AN/PRC-148",
        "manufacturer": "USA",
        "country": "USA",
        "alliance": "NATO"
      }
    ],
    "totalCount": 2
  }
}
```

### Filter by Alliance
```http
GET /api/v1/radio-models?alliance={alliance}
```

**Response:**
```json
{
  "success": true,
  "message": "Models filtered by alliance",
  "data": {
    "alliance": "NATO",
    "models": [
      {
        "modelName": "AN/PRC-77",
        "manufacturer": "USA",
        "country": "USA",
        "alliance": "NATO"
      },
      {
        "modelName": "AN/PRC-148",
        "manufacturer": "USA",
        "country": "USA",
        "alliance": "NATO"
      }
    ],
    "totalCount": 2
  }
}
```

### Filter by Era
```http
GET /api/v1/radio-models?era={era}
```

**Response:**
```json
{
  "success": true,
  "message": "Models filtered by era",
  "data": {
    "era": "Modern",
    "models": [
      {
        "modelName": "AN/PRC-148",
        "manufacturer": "USA",
        "country": "USA",
        "alliance": "NATO",
        "era": "Modern"
      },
      {
        "modelName": "AN/PRC-152",
        "manufacturer": "USA",
        "country": "USA",
        "alliance": "NATO",
        "era": "Modern"
      }
    ],
    "totalCount": 2
  }
}
```

### Filter by Usage
```http
GET /api/v1/radio-models?usage={usage}
```

**Response:**
```json
{
  "success": true,
  "message": "Models filtered by usage",
  "data": {
    "usage": "Tactical VHF",
    "models": [
      {
        "modelName": "AN/PRC-77",
        "manufacturer": "USA",
        "country": "USA",
        "alliance": "NATO",
        "usage": "Legacy VHF Tactical Radio"
      },
      {
        "modelName": "AN/PRC-148",
        "manufacturer": "USA",
        "country": "USA",
        "alliance": "NATO",
        "usage": "Multiband Inter/Intra Team Radio"
      }
    ],
    "totalCount": 2
  }
}
```

### Filter by Frequency Range
```http
GET /api/v1/radio-models?frequencyStart={start}&frequencyEnd={end}
```

**Response:**
```json
{
  "success": true,
  "message": "Models filtered by frequency range",
  "data": {
    "frequencyRange": {
      "start": 30.0,
      "end": 87.975
    },
    "models": [
      {
        "modelName": "AN/PRC-77",
        "frequencyStartMHz": 30.0,
        "frequencyEndMHz": 87.975,
        "totalChannels": 2319
      },
      {
        "modelName": "AN/PRC-148",
        "frequencyStartMHz": 30.0,
        "frequencyEndMHz": 87.975,
        "totalChannels": 2319
      }
    ],
    "totalCount": 2
  }
}
```

### Filter by Channel Spacing
```http
GET /api/v1/radio-models?channelSpacing={spacing}
```

**Response:**
```json
{
  "success": true,
  "message": "Models filtered by channel spacing",
  "data": {
    "channelSpacing": 25.0,
    "models": [
      {
        "modelName": "AN/PRC-77",
        "channelSpacingKHz": 25.0,
        "totalChannels": 2319
      },
      {
        "modelName": "AN/PRC-148",
        "channelSpacingKHz": 25.0,
        "totalChannels": 2319
      }
    ],
    "totalCount": 2
  }
}
```

## Export/Import

### Export Models
```http
POST /api/v1/radio-models/export
Content-Type: application/json

{
  "filePath": "exported_models.json",
  "modelNames": ["AN/PRC-77", "AN/PRC-148", "AN/PRC-152"]
}
```

**Response:**
```json
{
  "success": true,
  "message": "Models exported successfully",
  "data": {
    "filePath": "exported_models.json",
    "modelCount": 3,
    "exportSize": "15.2 KB"
  }
}
```

### Import Models
```http
POST /api/v1/radio-models/import
Content-Type: application/json

{
  "filePath": "imported_models.json",
  "overwrite": false
}
```

**Response:**
```json
{
  "success": true,
  "message": "Models imported successfully",
  "data": {
    "filePath": "imported_models.json",
    "importedCount": 5,
    "skippedCount": 0,
    "errorCount": 0
  }
}
```

### Export to JSON
```http
GET /api/v1/radio-models/export/json
```

**Response:**
```json
{
  "success": true,
  "message": "Models exported to JSON successfully",
  "data": {
    "jsonData": "[{\"modelName\":\"AN/PRC-77\",\"manufacturer\":\"USA\",\"country\":\"USA\",\"alliance\":\"NATO\",\"era\":\"Cold War\",\"usage\":\"Legacy VHF Tactical Radio\",\"frequencyStartMHz\":30.0,\"frequencyEndMHz\":87.975,\"channelSpacingKHz\":25.0,\"totalChannels\":2319,\"portablePowerWatts\":2.0,\"vehiclePowerWatts\":20.0,\"encryptionCapable\":false,\"gpsCapable\":false,\"dataCapable\":false,\"networkCapable\":false,\"advancedEncryption\":false,\"supportedModes\":[\"FM\",\"AM\"],\"presetChannels\":[],\"customProperties\":{}}]",
    "modelCount": 1
  }
}
```

### Import from JSON
```http
POST /api/v1/radio-models/import/json
Content-Type: application/json

{
  "jsonData": "[{\"modelName\":\"Custom Radio\",\"manufacturer\":\"My Company\",\"country\":\"USA\",\"alliance\":\"NATO\",\"era\":\"Modern\",\"usage\":\"Tactical VHF\",\"frequencyStartMHz\":30.0,\"frequencyEndMHz\":87.975,\"channelSpacingKHz\":25.0,\"totalChannels\":2319,\"portablePowerWatts\":2.0,\"vehiclePowerWatts\":20.0,\"encryptionCapable\":true,\"gpsCapable\":true,\"dataCapable\":true,\"networkCapable\":false,\"advancedEncryption\":false,\"supportedModes\":[\"FM\",\"AM\",\"CW\"],\"presetChannels\":[\"1\",\"100\",\"500\",\"1000\"],\"customProperties\":{}}]",
  "overwrite": false
}
```

**Response:**
```json
{
  "success": true,
  "message": "Models imported from JSON successfully",
  "data": {
    "importedCount": 1,
    "skippedCount": 0,
    "errorCount": 0
  }
}
```

## Statistics

### Get Model Statistics
```http
GET /api/v1/radio-models/statistics
```

**Response:**
```json
{
  "success": true,
  "message": "Statistics retrieved successfully",
  "data": {
    "totalModels": 15,
    "averageChannelCount": 1856.7,
    "averageFrequencyRange": 45.2,
    "modelCountByCountry": {
      "USA": 8,
      "USSR": 4,
      "Germany": 2,
      "Japan": 1
    },
    "modelCountByAlliance": {
      "NATO": 10,
      "Warsaw Pact": 4,
      "Civilian": 1
    },
    "modelCountByEra": {
      "Cold War": 6,
      "Modern": 9
    },
    "modelCountByUsage": {
      "Tactical VHF": 8,
      "Operational VHF": 4,
      "Amateur Radio": 3
    }
  }
}
```

### Get Model Count by Country
```http
GET /api/v1/radio-models/statistics/country
```

**Response:**
```json
{
  "success": true,
  "message": "Country statistics retrieved successfully",
  "data": {
    "USA": 8,
    "USSR": 4,
    "Germany": 2,
    "Japan": 1
  }
}
```

### Get Model Count by Alliance
```http
GET /api/v1/radio-models/statistics/alliance
```

**Response:**
```json
{
  "success": true,
  "message": "Alliance statistics retrieved successfully",
  "data": {
    "NATO": 10,
    "Warsaw Pact": 4,
    "Civilian": 1
  }
}
```

### Get Model Count by Era
```http
GET /api/v1/radio-models/statistics/era
```

**Response:**
```json
{
  "success": true,
  "message": "Era statistics retrieved successfully",
  "data": {
    "Cold War": 6,
    "Modern": 9
  }
}
```

### Get Model Count by Usage
```http
GET /api/v1/radio-models/statistics/usage
```

**Response:**
```json
{
  "success": true,
  "message": "Usage statistics retrieved successfully",
  "data": {
    "Tactical VHF": 8,
    "Operational VHF": 4,
    "Amateur Radio": 3
  }
}
```

### Get Total Model Count
```http
GET /api/v1/radio-models/statistics/total
```

**Response:**
```json
{
  "success": true,
  "message": "Total model count retrieved successfully",
  "data": {
    "totalModels": 15
  }
}
```

### Get Average Channel Count
```http
GET /api/v1/radio-models/statistics/average-channels
```

**Response:**
```json
{
  "success": true,
  "message": "Average channel count retrieved successfully",
  "data": {
    "averageChannelCount": 1856.7
  }
}
```

### Get Average Frequency Range
```http
GET /api/v1/radio-models/statistics/average-frequency-range
```

**Response:**
```json
{
  "success": true,
  "message": "Average frequency range retrieved successfully",
  "data": {
    "averageFrequencyRange": 45.2
  }
}
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
| 404 | Not Found - Model not found |
| 409 | Conflict - Model already exists |
| 422 | Unprocessable Entity - Validation error |
| 500 | Internal Server Error - Server error |

### Error Examples

#### Model Not Found
```json
{
  "success": false,
  "message": "Model 'NonExistentRadio' not found",
  "data": null,
  "errorCode": 404
}
```

#### Validation Error
```json
{
  "success": false,
  "message": "Model validation failed",
  "data": {
    "errors": [
      "Model name is required",
      "Start frequency must be positive",
      "End frequency must be greater than start frequency"
    ]
  },
  "errorCode": 422
}
```

#### Conflict Error
```json
{
  "success": false,
  "message": "Model 'AN/PRC-77' already exists",
  "data": {
    "modelName": "AN/PRC-77"
  },
  "errorCode": 409
}
```

## Examples

### Example 1: Create a Custom Radio Model

```bash
curl -X POST http://localhost:8080/api/v1/radio-models \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your_api_key" \
  -d '{
    "modelName": "Custom VHF Radio",
    "manufacturer": "My Company",
    "country": "USA",
    "alliance": "NATO",
    "era": "Modern",
    "usage": "Tactical VHF",
    "frequencyStartMHz": 30.0,
    "frequencyEndMHz": 87.975,
    "channelSpacingKHz": 25.0,
    "portablePowerWatts": 2.0,
    "vehiclePowerWatts": 20.0,
    "encryptionCapable": true,
    "gpsCapable": true,
    "dataCapable": true,
    "supportedModes": ["FM", "AM", "CW"],
    "presetChannels": ["1", "100", "500", "1000"]
  }'
```

### Example 2: Get Channel Frequency

```bash
curl -X GET http://localhost:8080/api/v1/radio-models/AN/PRC-152/channels/1/frequency \
  -H "Authorization: Bearer your_api_key"
```

### Example 3: Search Models

```bash
curl -X GET "http://localhost:8080/api/v1/radio-models/search?q=NATO" \
  -H "Authorization: Bearer your_api_key"
```

### Example 4: Export Models

```bash
curl -X POST http://localhost:8080/api/v1/radio-models/export \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your_api_key" \
  -d '{
    "filePath": "exported_models.json",
    "modelNames": ["AN/PRC-77", "AN/PRC-148", "AN/PRC-152"]
  }'
```

### Example 5: Get Statistics

```bash
curl -X GET http://localhost:8080/api/v1/radio-models/statistics \
  -H "Authorization: Bearer your_api_key"
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

- **API Documentation**: [RADIO_MODEL_API_REFERENCE.md](RADIO_MODEL_API_REFERENCE.md)
- **Configuration Guide**: [RADIO_MODEL_CONFIGURATION_GUIDE.md](RADIO_MODEL_CONFIGURATION_GUIDE.md)
- **Examples**: [RADIO_MODEL_EXAMPLES.md](RADIO_MODEL_EXAMPLES.md)
- **Troubleshooting**: [RADIO_MODEL_TROUBLESHOOTING.md](RADIO_MODEL_TROUBLESHOOTING.md)
