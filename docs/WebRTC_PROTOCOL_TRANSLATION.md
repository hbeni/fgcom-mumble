# FGCom-mumble WebRTC Protocol Translation

## Overview

This document defines the protocol translation between WebRTC clients and the existing FGCom-mumble Mumble plugin system. The translation layer ensures seamless communication while preserving all existing functionality.

## Protocol Mapping

### 1. WebRTC Client → Mumble Plugin

#### 1.1 Radio Data Translation
**WebRTC Format (JSON over WebSocket)**:
```json
{
  "type": "radio_update",
  "clientId": "webrtc_client_123",
  "timestamp": 1640995200000,
  "data": {
    "callsign": "N123AB",
    "location": {
      "latitude": 40.7128,
      "longitude": -74.0060,
      "altitude": 1000
    },
    "radios": [
      {
        "id": "COM1",
        "frequency": 123.45,
        "ptt": true,
        "power": 100,
        "volume": 80,
        "squelch": 50,
        "operational": true
      }
    ]
  }
}
```

**Mumble Plugin Format (UDP field=value)**:
```
CALLSIGN=N123AB,LAT=40.7128,LON=-74.0060,ALT=1000,COM1_FRQ=123.45,COM1_PTT=1,COM1_PWR=100,COM1_VOL=80,COM1_SQL=50,COM1_OPR=1
```

#### 1.2 Audio Data Translation
**WebRTC Audio Stream**:
- **Format**: Opus codec, 48kHz sample rate
- **Channels**: Mono (1 channel)
- **Bitrate**: 64-128 kbps
- **Frame Size**: 20ms frames

**Mumble Audio Format**:
- **Format**: Opus codec, 48kHz sample rate
- **Channels**: Mono (1 channel)
- **Bitrate**: 64-128 kbps
- **Frame Size**: 20ms frames

**Translation Process**:
1. WebRTC Opus → Raw PCM → Mumble Opus
2. Handle sample rate conversion if needed
3. Apply audio processing (noise reduction, etc.)
4. Forward to Mumble server

### 2. Mumble Plugin → WebRTC Client

#### 2.1 Radio State Updates
**Mumble Plugin Format (UDP field=value)**:
```
CALLSIGN=N456CD,LAT=41.8781,LON=-87.6298,ALT=2000,COM1_FRQ=123.45,COM1_PTT=0,COM1_PWR=75,COM1_VOL=90,COM1_SQL=60,COM1_OPR=1
```

**WebRTC Format (JSON over WebSocket)**:
```json
{
  "type": "radio_state",
  "clientId": "mumble_client_456",
  "timestamp": 1640995201000,
  "data": {
    "callsign": "N456CD",
    "location": {
      "latitude": 41.8781,
      "longitude": -87.6298,
      "altitude": 2000
    },
    "radios": [
      {
        "id": "COM1",
        "frequency": 123.45,
        "ptt": false,
        "power": 75,
        "volume": 90,
        "squelch": 60,
        "operational": true
      }
    ]
  }
}
```

#### 2.2 Audio Stream Updates
**Mumble Audio Stream**:
- **Format**: Opus codec, 48kHz sample rate
- **Channels**: Mono (1 channel)
- **Bitrate**: 64-128 kbps
- **Frame Size**: 20ms frames

**WebRTC Audio Format**:
- **Format**: Opus codec, 48kHz sample rate
- **Channels**: Mono (1 channel)
- **Bitrate**: 64-128 kbps
- **Frame Size**: 20ms frames

**Translation Process**:
1. Mumble Opus → Raw PCM → WebRTC Opus
2. Handle sample rate conversion if needed
3. Apply audio processing (echo cancellation, etc.)
4. Forward to WebRTC client

## Field Mapping Reference

### Radio Data Fields

| WebRTC Field | Mumble Field | Description | Type | Example |
|--------------|--------------|-------------|------|---------|
| `callsign` | `CALLSIGN` | Aircraft callsign | String | "N123AB" |
| `location.latitude` | `LAT` | Latitude coordinate | Float | 40.7128 |
| `location.longitude` | `LON` | Longitude coordinate | Float | -74.0060 |
| `location.altitude` | `ALT` | Altitude in feet | Float | 1000 |
| `radios[].id` | `COM{1,2,3}` | Radio identifier | String | "COM1" |
| `radios[].frequency` | `COM{1,2,3}_FRQ` | Radio frequency | Float | 123.45 |
| `radios[].ptt` | `COM{1,2,3}_PTT` | Push-to-talk state | Boolean | 1/0 |
| `radios[].power` | `COM{1,2,3}_PWR` | Radio power level | Integer | 100 |
| `radios[].volume` | `COM{1,2,3}_VOL` | Radio volume | Integer | 80 |
| `radios[].squelch` | `COM{1,2,3}_SQL` | Squelch threshold | Integer | 50 |
| `radios[].operational` | `COM{1,2,3}_OPR` | Radio operational status | Boolean | 1/0 |

### Audio Data Fields

| WebRTC Field | Mumble Field | Description | Type | Example |
|--------------|--------------|-------------|------|---------|
| `audio.codec` | `CODEC` | Audio codec | String | "opus" |
| `audio.sampleRate` | `SAMPLE_RATE` | Sample rate | Integer | 48000 |
| `audio.channels` | `CHANNELS` | Number of channels | Integer | 1 |
| `audio.bitrate` | `BITRATE` | Audio bitrate | Integer | 64000 |
| `audio.frameSize` | `FRAME_SIZE` | Frame size in ms | Integer | 20 |

## Protocol Translation Implementation

### 1. WebRTC to Mumble Translation

```javascript
class WebRTCToMumbleTranslator {
    translateRadioData(webrtcData) {
        const mumbleData = [];
        
        // Add callsign
        if (webrtcData.callsign) {
            mumbleData.push(`CALLSIGN=${webrtcData.callsign}`);
        }
        
        // Add location
        if (webrtcData.location) {
            if (webrtcData.location.latitude !== undefined) {
                mumbleData.push(`LAT=${webrtcData.location.latitude}`);
            }
            if (webrtcData.location.longitude !== undefined) {
                mumbleData.push(`LON=${webrtcData.location.longitude}`);
            }
            if (webrtcData.location.altitude !== undefined) {
                mumbleData.push(`ALT=${webrtcData.location.altitude}`);
            }
        }
        
        // Add radio data
        if (webrtcData.radios) {
            webrtcData.radios.forEach((radio, index) => {
                const radioId = `COM${index + 1}`;
                
                if (radio.frequency !== undefined) {
                    mumbleData.push(`${radioId}_FRQ=${radio.frequency}`);
                }
                if (radio.ptt !== undefined) {
                    mumbleData.push(`${radioId}_PTT=${radio.ptt ? 1 : 0}`);
                }
                if (radio.power !== undefined) {
                    mumbleData.push(`${radioId}_PWR=${radio.power}`);
                }
                if (radio.volume !== undefined) {
                    mumbleData.push(`${radioId}_VOL=${radio.volume}`);
                }
                if (radio.squelch !== undefined) {
                    mumbleData.push(`${radioId}_SQL=${radio.squelch}`);
                }
                if (radio.operational !== undefined) {
                    mumbleData.push(`${radioId}_OPR=${radio.operational ? 1 : 0}`);
                }
            });
        }
        
        return mumbleData.join(',');
    }
    
    translateAudioData(webrtcAudio) {
        // Convert WebRTC Opus to Mumble Opus format
        // Handle any necessary audio processing
        return this.convertOpusFormat(webrtcAudio);
    }
}
```

### 2. Mumble to WebRTC Translation

```javascript
class MumbleToWebRTCTranslator {
    translateRadioData(mumbleData) {
        const fields = mumbleData.split(',');
        const webrtcData = {
            callsign: null,
            location: {
                latitude: null,
                longitude: null,
                altitude: null
            },
            radios: []
        };
        
        fields.forEach(field => {
            const [key, value] = field.split('=');
            if (!key || !value) return;
            
            switch (key) {
                case 'CALLSIGN':
                    webrtcData.callsign = value;
                    break;
                case 'LAT':
                    webrtcData.location.latitude = parseFloat(value);
                    break;
                case 'LON':
                    webrtcData.location.longitude = parseFloat(value);
                    break;
                case 'ALT':
                    webrtcData.location.altitude = parseFloat(value);
                    break;
                default:
                    // Handle radio fields (COM1_FRQ, COM1_PTT, etc.)
                    const radioMatch = key.match(/^COM(\d+)_(.+)$/);
                    if (radioMatch) {
                        const radioIndex = parseInt(radioMatch[1]) - 1;
                        const fieldName = radioMatch[2];
                        
                        if (!webrtcData.radios[radioIndex]) {
                            webrtcData.radios[radioIndex] = {};
                        }
                        
                        switch (fieldName) {
                            case 'FRQ':
                                webrtcData.radios[radioIndex].frequency = parseFloat(value);
                                break;
                            case 'PTT':
                                webrtcData.radios[radioIndex].ptt = value === '1';
                                break;
                            case 'PWR':
                                webrtcData.radios[radioIndex].power = parseInt(value);
                                break;
                            case 'VOL':
                                webrtcData.radios[radioIndex].volume = parseInt(value);
                                break;
                            case 'SQL':
                                webrtcData.radios[radioIndex].squelch = parseInt(value);
                                break;
                            case 'OPR':
                                webrtcData.radios[radioIndex].operational = value === '1';
                                break;
                        }
                    }
                    break;
            }
        });
        
        return webrtcData;
    }
    
    translateAudioData(mumbleAudio) {
        // Convert Mumble Opus to WebRTC Opus format
        // Handle any necessary audio processing
        return this.convertOpusFormat(mumbleAudio);
    }
}
```

## Data Validation

### 1. WebRTC Data Validation

```javascript
class WebRTCDataValidator {
    validateRadioData(data) {
        const errors = [];
        
        // Validate callsign
        if (data.callsign && !/^[A-Z0-9]{1,8}$/.test(data.callsign)) {
            errors.push('Invalid callsign format');
        }
        
        // Validate location
        if (data.location) {
            if (data.location.latitude !== undefined) {
                if (data.location.latitude < -90 || data.location.latitude > 90) {
                    errors.push('Latitude must be between -90 and 90');
                }
            }
            if (data.location.longitude !== undefined) {
                if (data.location.longitude < -180 || data.location.longitude > 180) {
                    errors.push('Longitude must be between -180 and 180');
                }
            }
            if (data.location.altitude !== undefined) {
                if (data.location.altitude < -1000 || data.location.altitude > 100000) {
                    errors.push('Altitude must be between -1000 and 100000 feet');
                }
            }
        }
        
        // Validate radios
        if (data.radios) {
            data.radios.forEach((radio, index) => {
                if (radio.frequency !== undefined) {
                    if (radio.frequency < 118.0 || radio.frequency > 137.0) {
                        errors.push(`Radio ${index + 1} frequency must be between 118.0 and 137.0 MHz`);
                    }
                }
                if (radio.power !== undefined) {
                    if (radio.power < 0 || radio.power > 100) {
                        errors.push(`Radio ${index + 1} power must be between 0 and 100`);
                    }
                }
                if (radio.volume !== undefined) {
                    if (radio.volume < 0 || radio.volume > 100) {
                        errors.push(`Radio ${index + 1} volume must be between 0 and 100`);
                    }
                }
                if (radio.squelch !== undefined) {
                    if (radio.squelch < 0 || radio.squelch > 100) {
                        errors.push(`Radio ${index + 1} squelch must be between 0 and 100`);
                    }
                }
            });
        }
        
        return errors;
    }
}
```

### 2. Mumble Data Validation

```javascript
class MumbleDataValidator {
    validateUDPData(data) {
        const errors = [];
        
        // Check packet length
        if (data.length > 1024) {
            errors.push('UDP packet too long (max 1024 bytes)');
        }
        
        // Validate field format
        const fields = data.split(',');
        fields.forEach(field => {
            if (!field.includes('=')) {
                errors.push(`Invalid field format: ${field}`);
            }
            
            const [key, value] = field.split('=');
            if (key.length > 32) {
                errors.push(`Field name too long: ${key}`);
            }
            
            // Check for forbidden characters
            if (value.includes(',')) {
                errors.push(`Field value contains comma: ${value}`);
            }
        });
        
        return errors;
    }
}
```

## Error Handling

### 1. Translation Errors

```javascript
class TranslationErrorHandler {
    handleTranslationError(error, context) {
        console.error('Translation error:', error);
        console.error('Context:', context);
        
        // Log error for debugging
        this.logError(error, context);
        
        // Send error response to client
        if (context.clientId) {
            this.sendErrorToClient(context.clientId, error);
        }
        
        // Attempt recovery
        this.attemptRecovery(error, context);
    }
    
    logError(error, context) {
        // Log to file or database
        const logEntry = {
            timestamp: new Date().toISOString(),
            error: error.message,
            context: context,
            stack: error.stack
        };
        
        // Write to log file
        fs.appendFileSync('translation-errors.log', JSON.stringify(logEntry) + '\n');
    }
    
    sendErrorToClient(clientId, error) {
        // Send error message to WebRTC client
        const errorMessage = {
            type: 'error',
            message: 'Translation error occurred',
            details: error.message
        };
        
        this.websocketServer.to(clientId).emit('translation-error', errorMessage);
    }
    
    attemptRecovery(error, context) {
        // Attempt to recover from translation errors
        if (error.code === 'INVALID_FORMAT') {
            // Try to fix format issues
            this.fixFormatIssues(context);
        } else if (error.code === 'MISSING_FIELD') {
            // Try to use default values
            this.useDefaultValues(context);
        }
    }
}
```

### 2. Connection Errors

```javascript
class ConnectionErrorHandler {
    handleConnectionError(error, clientId) {
        console.error('Connection error:', error);
        
        // Log connection error
        this.logConnectionError(error, clientId);
        
        // Attempt reconnection
        this.attemptReconnection(clientId);
        
        // Notify other clients
        this.notifyConnectionLoss(clientId);
    }
    
    logConnectionError(error, clientId) {
        const logEntry = {
            timestamp: new Date().toISOString(),
            clientId: clientId,
            error: error.message,
            code: error.code
        };
        
        fs.appendFileSync('connection-errors.log', JSON.stringify(logEntry) + '\n');
    }
    
    attemptReconnection(clientId) {
        // Attempt to reconnect WebRTC client
        setTimeout(() => {
            this.reconnectClient(clientId);
        }, 5000);
    }
    
    notifyConnectionLoss(clientId) {
        // Notify other clients about connection loss
        const notification = {
            type: 'client-disconnected',
            clientId: clientId,
            timestamp: new Date().toISOString()
        };
        
        this.broadcastToClients(notification);
    }
}
```

## Performance Optimization

### 1. Data Caching

```javascript
class DataCache {
    constructor() {
        this.cache = new Map();
        this.maxSize = 1000;
        this.ttl = 30000; // 30 seconds
    }
    
    set(key, value) {
        // Remove oldest entries if cache is full
        if (this.cache.size >= this.maxSize) {
            const firstKey = this.cache.keys().next().value;
            this.cache.delete(firstKey);
        }
        
        this.cache.set(key, {
            value: value,
            timestamp: Date.now()
        });
    }
    
    get(key) {
        const entry = this.cache.get(key);
        if (!entry) return null;
        
        // Check if entry has expired
        if (Date.now() - entry.timestamp > this.ttl) {
            this.cache.delete(key);
            return null;
        }
        
        return entry.value;
    }
}
```

### 2. Batch Processing

```javascript
class BatchProcessor {
    constructor() {
        this.batchSize = 10;
        this.batchTimeout = 100; // 100ms
        this.pendingData = [];
    }
    
    addData(data) {
        this.pendingData.push(data);
        
        if (this.pendingData.length >= this.batchSize) {
            this.processBatch();
        } else {
            this.scheduleBatch();
        }
    }
    
    scheduleBatch() {
        if (this.batchTimeoutId) {
            clearTimeout(this.batchTimeoutId);
        }
        
        this.batchTimeoutId = setTimeout(() => {
            this.processBatch();
        }, this.batchTimeout);
    }
    
    processBatch() {
        if (this.pendingData.length === 0) return;
        
        const batch = this.pendingData.splice(0, this.batchSize);
        this.processDataBatch(batch);
        
        if (this.pendingData.length > 0) {
            this.scheduleBatch();
        }
    }
}
```

## Conclusion

The WebRTC protocol translation layer provides seamless communication between web browser clients and the existing FGCom-mumble infrastructure. The translation ensures:

1. **Data Integrity**: Proper validation and error handling
2. **Performance**: Optimized data processing and caching
3. **Compatibility**: Full compatibility with existing Mumble plugin
4. **Reliability**: Robust error handling and recovery mechanisms
5. **Scalability**: Efficient batch processing and connection management

This protocol translation enables web browser clients to participate in FGCom-mumble radio communication while maintaining all existing functionality and performance characteristics.
