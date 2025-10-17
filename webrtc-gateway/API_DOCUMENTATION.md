# WebRTC Gateway API Documentation

This document provides comprehensive API documentation for the FGcom-Mumble WebRTC Gateway, including RESTful APIs, WebSocket APIs, and integration examples.

## API Overview

The WebRTC Gateway provides multiple API interfaces for different use cases:

- **RESTful API**: HTTP-based API for configuration and management
- **WebSocket API**: Real-time communication for client connections
- **Authentication API**: User authentication and authorization
- **Status API**: System monitoring and health checks
- **Radio Data API**: Radio data transmission to Mumble server

## RESTful API

### Base URL
```
http://localhost:8081/api
```

### Authentication

#### Login
```http
POST /api/auth/login
Content-Type: application/json

{
  "username": "callsign",
  "password": "password"
}
```

**Response**:
```json
{
  "success": true,
  "token": "session_token_here",
  "user": {
    "username": "callsign",
    "id": "user_id"
  }
}
```

#### Register
```http
POST /api/auth/register
Content-Type: application/json

{
  "username": "callsign",
  "password": "password",
  "email": "user@example.com"
}
```

**Response**:
```json
{
  "success": true,
  "message": "Registration successful"
}
```

### Radio Data Transmission

#### Send Radio Data
```http
POST /api/radio/data
Content-Type: application/json

{
  "frequency": 121.500,
  "power": 100,
  "squelch": 50,
  "transmitting": false,
  "position": {
    "latitude": 40.7128,
    "longitude": -74.0060,
    "altitude": 1000
  }
}
```

**Response**:
```json
{
  "success": true,
  "message": "Radio data sent"
}
```

### Logout

#### Logout
```http
POST /api/auth/logout
Content-Type: application/json
```

**Response**:
```json
{
  "success": true,
  "message": "Logged out successfully"
}
```

### System Status

#### Health Check
```http
GET /health
```

**Response**:
```json
{
  "status": "healthy",
  "timestamp": "2025-01-16T10:30:00Z",
  "clients": 3,
  "uptime": 3600
}
```

#### System Status
```http
GET /api/status
```

**Response**:
```json
{
  "server": "FGCom-mumble WebRTC Gateway",
  "version": "1.0.0",
  "clients": 3,
  "mumble": {
    "connected": true,
    "host": "localhost",
    "port": 64738
  },
  "uptime": 3600
}
```

## WebSocket API

### Connection
```javascript
const ws = new WebSocket('ws://localhost:8081/ws');

ws.onopen = function() {
    console.log('WebSocket connected');
};

ws.onmessage = function(event) {
    const data = JSON.parse(event.data);
    console.log('Received:', data);
};

ws.onclose = function() {
    console.log('WebSocket disconnected');
};
```

### WebRTC Signaling
```javascript
// Send WebRTC offer
ws.send(JSON.stringify({
    type: 'webrtc-offer',
    sdp: 'offer_sdp_data'
}));

// Send WebRTC answer
ws.send(JSON.stringify({
    type: 'webrtc-answer',
    sdp: 'answer_sdp_data'
}));

// Send ICE candidate
ws.send(JSON.stringify({
    type: 'ice-candidate',
    candidate: 'ice_candidate_data'
}));
```

### Radio Data
```javascript
// Send radio data
ws.send(JSON.stringify({
    type: 'radio-data',
    frequency: 121.500,
    power: 100,
    squelch: 50,
    transmitting: false,
    position: {
        latitude: 40.7128,
        longitude: -74.0060,
        altitude: 1000
    }
}));
```

## Integration Examples

### JavaScript Client

#### Basic Connection
```javascript
class FGcomWebRTCClient {
    constructor(serverUrl) {
        this.serverUrl = serverUrl;
        this.ws = null;
        this.authenticated = false;
    }

    connect() {
        this.ws = new WebSocket(this.serverUrl + '/ws');
        
        this.ws.onopen = () => {
            console.log('Connected to FGcom WebRTC Gateway');
        };

        this.ws.onmessage = (event) => {
            const data = JSON.parse(event.data);
            this.handleMessage(data);
        };

        this.ws.onclose = () => {
            console.log('Disconnected from FGcom WebRTC Gateway');
        };
    }

    sendWebRTCOffer(sdp) {
        this.ws.send(JSON.stringify({
            type: 'webrtc-offer',
            sdp: sdp
        }));
    }

    sendWebRTCAnswer(sdp) {
        this.ws.send(JSON.stringify({
            type: 'webrtc-answer',
            sdp: sdp
        }));
    }

    sendIceCandidate(candidate) {
        this.ws.send(JSON.stringify({
            type: 'ice-candidate',
            candidate: candidate
        }));
    }

    sendRadioData(radioData) {
        this.ws.send(JSON.stringify({
            type: 'radio-data',
            ...radioData
        }));
    }

    handleMessage(data) {
        switch(data.type) {
            case 'webrtc-offer':
                this.handleWebRTCOffer(data);
                break;
            case 'webrtc-answer':
                this.handleWebRTCAnswer(data);
                break;
            case 'ice-candidate':
                this.handleIceCandidate(data);
                break;
            case 'radio-data':
                this.handleRadioData(data);
                break;
            case 'audio-data':
                this.handleAudioData(data);
                break;
        }
    }

    handleWebRTCOffer(data) {
        console.log('WebRTC offer received:', data);
    }

    handleWebRTCAnswer(data) {
        console.log('WebRTC answer received:', data);
    }

    handleIceCandidate(data) {
        console.log('ICE candidate received:', data);
    }

    handleRadioData(data) {
        console.log('Radio data received:', data);
    }

    handleAudioData(data) {
        console.log('Audio data received:', data);
    }
}

// Usage
const client = new FGcomWebRTCClient('ws://localhost:8081');
client.connect();

// Send WebRTC offer
client.sendWebRTCOffer('your_sdp_offer');

// Send radio data
client.sendRadioData({
    frequency: 121.500,
    power: 100,
    squelch: 50,
    transmitting: false,
    position: {
        latitude: 40.7128,
        longitude: -74.0060,
        altitude: 1000
    }
});
```

### Python Client

#### Basic Connection
```python
import websocket
import json
import threading

class FGcomWebRTCClient:
    def __init__(self, server_url):
        self.server_url = server_url
        self.ws = None
        self.authenticated = False

    def connect(self):
        self.ws = websocket.WebSocketApp(
            self.server_url + '/ws',
            on_open=self.on_open,
            on_message=self.on_message,
            on_close=self.on_close
        )
        
        # Run in separate thread
        wst = threading.Thread(target=self.ws.run_forever)
        wst.daemon = True
        wst.start()

    def on_open(self, ws):
        print('Connected to FGcom WebRTC Gateway')

    def on_message(self, ws, message):
        data = json.loads(message)
        self.handle_message(data)

    def on_close(self, ws):
        print('Disconnected from FGcom WebRTC Gateway')

    def send_webrtc_offer(self, sdp):
        self.ws.send(json.dumps({
            'type': 'webrtc-offer',
            'sdp': sdp
        }))

    def send_webrtc_answer(self, sdp):
        self.ws.send(json.dumps({
            'type': 'webrtc-answer',
            'sdp': sdp
        }))

    def send_ice_candidate(self, candidate):
        self.ws.send(json.dumps({
            'type': 'ice-candidate',
            'candidate': candidate
        }))

    def send_radio_data(self, radio_data):
        self.ws.send(json.dumps({
            'type': 'radio-data',
            **radio_data
        }))

    def handle_message(self, data):
        if data['type'] == 'webrtc-offer':
            self.handle_webrtc_offer(data)
        elif data['type'] == 'webrtc-answer':
            self.handle_webrtc_answer(data)
        elif data['type'] == 'ice-candidate':
            self.handle_ice_candidate(data)
        elif data['type'] == 'radio-data':
            self.handle_radio_data(data)
        elif data['type'] == 'audio-data':
            self.handle_audio_data(data)

    def handle_webrtc_offer(self, data):
        print('WebRTC offer received:', data)

    def handle_webrtc_answer(self, data):
        print('WebRTC answer received:', data)

    def handle_ice_candidate(self, data):
        print('ICE candidate received:', data)

    def handle_radio_data(self, data):
        print('Radio data received:', data)

    def handle_audio_data(self, data):
        print('Audio data received:', data)

# Usage
client = FGcomWebRTCClient('ws://localhost:8081')
client.connect()

# Send WebRTC offer
client.send_webrtc_offer('your_sdp_offer')

# Send radio data
client.send_radio_data({
    'frequency': 121.500,
    'power': 100,
    'squelch': 50,
    'transmitting': False,
    'position': {
        'latitude': 40.7128,
        'longitude': -74.0060,
        'altitude': 1000
    }
})
```

## Error Handling

### HTTP Error Responses
```json
{
  "success": false,
  "error": "Invalid frequency",
  "code": 400,
  "message": "Frequency must be between 118.000 and 137.000 MHz"
}
```

### WebSocket Error Messages
```json
{
  "type": "webrtc-error",
  "error": "Failed to handle offer",
  "message": "WebRTC connection failed"
}
```

### Common Error Codes
- **400**: Bad Request - Invalid parameters
- **401**: Unauthorized - Authentication required
- **403**: Forbidden - Insufficient permissions
- **404**: Not Found - Resource not found
- **500**: Internal Server Error - Server error

## Security

### Authentication
- Session-based authentication
- Secure session storage
- Session expiration handling
- User registration and login

### Authorization
- Session-based access control
- User permission management
- Resource access control

### Encryption
- TLS/SSL encryption for HTTPS
- WebSocket secure connections (WSS)
- Audio stream encryption via WebRTC
- Secure data transmission

## Performance

### Optimization
- WebRTC connection management
- Audio stream optimization
- Message compression
- Connection pooling
- Efficient data transmission

### Monitoring
- WebRTC connection metrics
- Audio stream performance
- Error tracking and logging
- Health check endpoints
- System status monitoring

## Troubleshooting

### Common Issues

1. **WebRTC Connection Failed**
   - Check server URL and port
   - Verify firewall settings
   - Check network connectivity
   - Verify SSL certificates

2. **Authentication Failed**
   - Check username and password
   - Verify user registration
   - Check session validity
   - Verify server authentication

3. **Audio Issues**
   - Check microphone permissions
   - Verify WebRTC audio settings
   - Check audio codec support
   - Verify network bandwidth

### Debug Mode
```javascript
// Enable debug logging
const client = new FGcomWebRTCClient('ws://localhost:8081');
client.debug = true;
client.connect();

// Check WebRTC connection status
console.log('WebRTC connection status:', client.webrtcConnection);
```

## Best Practices

### Client Development
1. **Error Handling**: Implement comprehensive error handling for WebRTC
2. **Reconnection**: Implement automatic WebSocket reconnection
3. **Authentication**: Handle session expiration
4. **Performance**: Optimize WebRTC audio handling
5. **Security**: Use secure HTTPS/WSS connections

### API Usage
1. **WebRTC Signaling**: Handle WebRTC offer/answer/ICE properly
2. **Error Handling**: Handle all WebRTC and WebSocket errors
3. **Validation**: Validate audio and radio data
4. **Monitoring**: Monitor WebRTC connection performance
5. **Documentation**: Keep API documentation updated

## Support

For API issues:
1. Check API documentation
2. Review WebRTC error messages
3. Verify authentication and session
4. Check network connectivity and SSL
5. Review server logs and WebRTC status
