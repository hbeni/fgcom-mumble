# FGCom-mumble WebRTC Gateway Architecture

## Overview

This document details the technical architecture for the WebRTC Gateway that will enable web browser clients to connect to FGCom-mumble servers while preserving all existing connection methods.

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           FGCom-mumble WebRTC Gateway                          │
├─────────────────────────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────┐  │
│  │   Web Server    │  │  WebRTC Engine  │  │ Audio Processor │  │   Auth     │  │
│  │   (Express)     │  │   (SimplePeer)  │  │   (Node-Opus)  │  │  Service   │  │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘  └─────────────┘  │
│           │                     │                     │               │          │
│           ▼                     ▼                     ▼               ▼          │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────┐  │
│  │  Static Files   │  │  Signaling     │  │  Codec Convert │  │  User Mgmt │  │
│  │  (HTML/CSS/JS)  │  │  (Socket.io)   │  │  (WebRTC↔Mumble)│  │  (JWT)     │  │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘  └─────────────┘  │
│           │                     │                     │               │          │
│           ▼                     ▼                     ▼               ▼          │
│  ┌─────────────────────────────────────────────────────────────────────────────┐  │
│  │                    Protocol Translation Layer                              │  │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐  │  │
│  │  │ WebRTC Data │  │ Radio Data  │  │ Audio Data  │  │  Mumble Data  │  │  │
│  │  │ (JSON/WS)   │  │ Translation │  │ Translation │  │  Translation   │  │  │
│  │  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────────┘  │  │
│  └─────────────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           Existing FGCom-mumble Infrastructure                  │
├─────────────────────────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────┐  │
│  │  Mumble Server  │  │  Mumble Plugin │  │  Server Bots    │  │ Status Page │  │
│  │   (Murmur)      │  │   (UDP 16661)  │  │   (Lua)         │  │   (PHP)    │  │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘  └─────────────┘  │
└─────────────────────────────────────────────────────────────────────────────────┘
```

## Core Components

### 1. Web Server (Express.js)
**Purpose**: Serve web interface and handle HTTP requests

**Responsibilities**:
- Serve static web files (HTML, CSS, JavaScript)
- Handle authentication requests
- Provide REST API endpoints
- Manage user sessions

**Implementation**:
```javascript
const express = require('express');
const session = require('express-session');
const path = require('path');

const app = express();

// Static file serving
app.use(express.static(path.join(__dirname, 'public')));

// API routes
app.use('/api/auth', require('./routes/auth'));
app.use('/api/radio', require('./routes/radio'));
app.use('/api/status', require('./routes/status'));

// WebRTC signaling endpoint
app.get('/webrtc', (req, res) => {
    res.sendFile(path.join(__dirname, 'public/webrtc-client.html'));
});
```

### 2. WebRTC Engine (SimplePeer)
**Purpose**: Handle WebRTC peer connections and signaling

**Responsibilities**:
- Manage WebRTC peer connections
- Handle signaling (offer/answer/ICE candidates)
- Manage audio/video streams
- Handle connection state

**Implementation**:
```javascript
const { Server } = require('socket.io');
const SimplePeer = require('simple-peer');

class WebRTCEngine {
    constructor(server) {
        this.io = new Server(server);
        this.peers = new Map();
        this.setupSignaling();
    }
    
    setupSignaling() {
        this.io.on('connection', (socket) => {
            socket.on('webrtc-offer', (offer) => {
                this.handleOffer(socket, offer);
            });
            
            socket.on('webrtc-answer', (answer) => {
                this.handleAnswer(socket, answer);
            });
            
            socket.on('ice-candidate', (candidate) => {
                this.handleIceCandidate(socket, candidate);
            });
        });
    }
    
    handleOffer(socket, offer) {
        const peer = new SimplePeer({ initiator: false, trickle: false });
        this.peers.set(socket.id, peer);
        
        peer.signal(offer);
        peer.on('signal', (answer) => {
            socket.emit('webrtc-answer', answer);
        });
        
        peer.on('stream', (stream) => {
            this.handleAudioStream(socket.id, stream);
        });
    }
}
```

### 3. Audio Processor (Node-Opus)
**Purpose**: Convert audio between WebRTC and Mumble formats

**Responsibilities**:
- Convert WebRTC Opus to Mumble Opus
- Handle audio codec differences
- Manage audio quality settings
- Process real-time audio streams

**Implementation**:
```javascript
const opus = require('node-opus');
const { Transform } = require('stream');

class AudioProcessor {
    constructor() {
        this.opusEncoder = new opus.Encoder(48000, 1, opus.OPUS_APPLICATION_VOIP);
        this.opusDecoder = new opus.Decoder(48000, 1);
    }
    
    createAudioTransform() {
        return new Transform({
            transform: (chunk, encoding, callback) => {
                // Convert WebRTC audio to Mumble format
                const mumbleAudio = this.convertToMumbleFormat(chunk);
                callback(null, mumbleAudio);
            }
        });
    }
    
    convertToMumbleFormat(webrtcAudio) {
        // Convert WebRTC Opus to Mumble Opus format
        // Handle sample rate conversion if needed
        // Apply any necessary audio processing
        return this.opusEncoder.encode(webrtcAudio);
    }
}
```

### 4. Protocol Translation Layer
**Purpose**: Convert between WebRTC and Mumble protocols

**Responsibilities**:
- Convert JSON radio data to UDP field=value format
- Handle Mumble plugin communication
- Manage radio state synchronization
- Process incoming Mumble data

**Implementation**:
```javascript
const dgram = require('dgram');

class ProtocolTranslator {
    constructor() {
        this.udpClient = dgram.createSocket('udp4');
        this.radioStates = new Map();
    }
    
    // WebRTC → Mumble Plugin
    translateRadioData(clientId, radioData) {
        const udpMessage = this.buildUDPMessage(radioData);
        this.udpClient.send(udpMessage, 16661, 'localhost');
        
        // Store radio state
        this.radioStates.set(clientId, radioData);
    }
    
    buildUDPMessage(radioData) {
        let message = '';
        
        if (radioData.frequency) {
            message += `COM1_FRQ=${radioData.frequency},`;
        }
        if (radioData.ptt !== undefined) {
            message += `COM1_PTT=${radioData.ptt ? 1 : 0},`;
        }
        if (radioData.power !== undefined) {
            message += `COM1_PWR=${radioData.power},`;
        }
        if (radioData.callsign) {
            message += `CALLSIGN=${radioData.callsign},`;
        }
        if (radioData.latitude !== undefined) {
            message += `LAT=${radioData.latitude},`;
        }
        if (radioData.longitude !== undefined) {
            message += `LON=${radioData.longitude},`;
        }
        if (radioData.altitude !== undefined) {
            message += `ALT=${radioData.altitude},`;
        }
        
        return message;
    }
    
    // Mumble Plugin → WebRTC
    handleMumbleData(mumbleData) {
        // Parse Mumble plugin data and forward to WebRTC clients
        const parsedData = this.parseMumbleData(mumbleData);
        this.broadcastToWebRTCClients(parsedData);
    }
    
    parseMumbleData(data) {
        // Parse UDP field=value format
        const fields = data.split(',');
        const result = {};
        
        fields.forEach(field => {
            const [key, value] = field.split('=');
            if (key && value) {
                result[key] = value;
            }
        });
        
        return result;
    }
}
```

## Data Flow Architecture

### 1. WebRTC Client Connection Flow
```
Web Browser → HTTPS Request → Express Server → WebRTC Client Page
WebRTC Client → WebSocket → Socket.io → WebRTC Engine → Peer Connection
Peer Connection → Audio Stream → Audio Processor → Mumble Server
```

### 2. Radio Data Flow
```
WebRTC Client → JSON Data → WebSocket → Protocol Translator → UDP → Mumble Plugin
Mumble Plugin → UDP Data → Protocol Translator → WebSocket → WebRTC Client
```

### 3. Audio Stream Flow
```
WebRTC Client → Opus Audio → WebRTC Engine → Audio Processor → Mumble Server
Mumble Server → Opus Audio → Audio Processor → WebRTC Engine → WebRTC Client
```

## Integration Points

### 1. Mumble Plugin Integration
**No Changes Required**: The existing Mumble plugin continues to work unchanged
- Receives UDP data on port 16661
- Processes radio simulation as usual
- Sends audio to Mumble server

### 2. Server Bots Integration
**No Changes Required**: Existing Lua bots continue to work
- ATIS bot continues recording/playback
- Status bot continues monitoring
- All existing functionality preserved

### 3. Status Page Integration
**Enhanced**: Status page shows both Mumble and WebRTC clients
- WebRTC clients appear alongside Mumble clients
- Same monitoring and logging capabilities
- Unified client management interface

## Security Architecture

### 1. Authentication Flow
```
Web Client → Login Request → Auth Service → JWT Token → Session Management
WebRTC Connection → Token Validation → Mumble Certificate → Mumble Server
```

### 2. Data Encryption
- **HTTPS/WSS**: All web communication encrypted
- **WebRTC Native**: Audio streams encrypted by WebRTC
- **Mumble TLS**: Existing Mumble encryption preserved

### 3. Access Control
- **User Registration**: Web-based user accounts
- **Role-based Permissions**: Different access levels
- **Session Management**: Secure session handling
- **Rate Limiting**: Prevent abuse and DoS

## Deployment Architecture

### 1. Development Environment
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Web Browser   │◄──►│  WebRTC Gateway │◄──►│  Mumble Server  │
│   (localhost)   │    │   (Node.js)     │    │   (localhost)   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### 2. Production Environment
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Web Browser   │◄──►│  WebRTC Gateway │◄──►│  Mumble Server  │
│   (HTTPS)       │    │   (Load Balancer)│    │   (Cluster)    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                              │
                              ▼
                       ┌─────────────────┐
                       │   Database      │
                       │   (User Data)   │
                       └─────────────────┘
```

## Performance Considerations

### 1. Audio Processing
- **Low Latency**: Minimize audio processing delay
- **Quality Settings**: Configurable audio quality
- **Buffer Management**: Efficient audio buffering
- **Codec Optimization**: Optimize Opus encoding/decoding

### 2. WebRTC Optimization
- **ICE Candidate Optimization**: Efficient NAT traversal
- **Bandwidth Management**: Adaptive bitrate
- **Connection Pooling**: Efficient connection management
- **Error Recovery**: Robust error handling

### 3. Scalability
- **Horizontal Scaling**: Multiple gateway instances
- **Load Balancing**: Distribute WebRTC connections
- **Database Optimization**: Efficient user data storage
- **Caching**: Cache frequently accessed data

## Monitoring and Logging

### 1. Connection Monitoring
- **WebRTC Connections**: Track active WebRTC clients
- **Audio Quality**: Monitor audio stream quality
- **Latency Metrics**: Track audio/video latency
- **Error Rates**: Monitor connection errors

### 2. Performance Metrics
- **CPU Usage**: Monitor audio processing load
- **Memory Usage**: Track memory consumption
- **Network Usage**: Monitor bandwidth usage
- **Response Times**: Track API response times

### 3. Logging
- **Connection Logs**: Track client connections/disconnections
- **Audio Logs**: Log audio processing events
- **Error Logs**: Track and log errors
- **Security Logs**: Monitor authentication and access

## Conclusion

The WebRTC Gateway architecture provides a robust, scalable solution for enabling web browser clients to connect to FGCom-mumble servers while preserving all existing functionality. The modular design ensures:

1. **Minimal Impact**: No changes to existing Mumble infrastructure
2. **High Performance**: Optimized audio processing and WebRTC handling
3. **Scalability**: Horizontal scaling and load balancing support
4. **Security**: Comprehensive authentication and encryption
5. **Monitoring**: Full observability and logging capabilities

This architecture enables FGCom-mumble to reach a broader audience through web browsers while maintaining the high-quality radio simulation experience that existing users expect.
