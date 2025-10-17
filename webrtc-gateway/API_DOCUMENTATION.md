# WebRTC Gateway API Documentation

This document provides comprehensive API documentation for the FGcom-Mumble WebRTC Gateway, including RESTful APIs, WebSocket APIs, and integration examples.

## API Overview

The WebRTC Gateway provides multiple API interfaces for different use cases:

- **RESTful API**: HTTP-based API for configuration and management
- **WebSocket API**: Real-time communication for client connections
- **Authentication API**: User authentication and authorization
- **Status API**: System monitoring and health checks
- **Audio API**: Audio stream management and processing

## RESTful API

### Base URL
```
http://localhost:8081/api/v1
```

### Authentication

#### Login
```http
POST /api/v1/auth/login
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
  "token": "jwt_token_here",
  "user": {
    "username": "callsign",
    "callsign": "N123AB",
    "permissions": ["radio", "position"]
  }
}
```

#### Register
```http
POST /api/v1/auth/register
Content-Type: application/json

{
  "username": "callsign",
  "password": "password",
  "callsign": "N123AB",
  "email": "user@example.com"
}
```

**Response**:
```json
{
  "success": true,
  "message": "User registered successfully",
  "user": {
    "username": "callsign",
    "callsign": "N123AB"
  }
}
```

### Radio Configuration

#### Set Radio Frequency
```http
POST /api/v1/radio/frequency
Authorization: Bearer jwt_token_here
Content-Type: application/json

{
  "frequency": 121.500,
  "power": 100,
  "squelch": 50
}
```

**Response**:
```json
{
  "success": true,
  "radio": {
    "frequency": 121.500,
    "power": 100,
    "squelch": 50,
    "status": "active"
  }
}
```

#### Get Radio Status
```http
GET /api/v1/radio/status
Authorization: Bearer jwt_token_here
```

**Response**:
```json
{
  "success": true,
  "radio": {
    "frequency": 121.500,
    "power": 100,
    "squelch": 50,
    "status": "active",
    "transmitting": false,
    "receiving": true
  }
}
```

### Position Management

#### Set Position
```http
POST /api/v1/position
Authorization: Bearer jwt_token_here
Content-Type: application/json

{
  "latitude": 40.7128,
  "longitude": -74.0060,
  "altitude": 1000,
  "heading": 270
}
```

**Response**:
```json
{
  "success": true,
  "position": {
    "latitude": 40.7128,
    "longitude": -74.0060,
    "altitude": 1000,
    "heading": 270,
    "timestamp": "2025-01-16T10:30:00Z"
  }
}
```

#### Get Position
```http
GET /api/v1/position
Authorization: Bearer jwt_token_here
```

**Response**:
```json
{
  "success": true,
  "position": {
    "latitude": 40.7128,
    "longitude": -74.0060,
    "altitude": 1000,
    "heading": 270,
    "timestamp": "2025-01-16T10:30:00Z"
  }
}
```

### Audio Management

#### Start Audio Stream
```http
POST /api/v1/audio/start
Authorization: Bearer jwt_token_here
Content-Type: application/json

{
  "sampleRate": 48000,
  "channels": 1,
  "bitrate": 64000
}
```

**Response**:
```json
{
  "success": true,
  "audio": {
    "streamId": "stream_123",
    "sampleRate": 48000,
    "channels": 1,
    "bitrate": 64000,
    "status": "active"
  }
}
```

#### Stop Audio Stream
```http
POST /api/v1/audio/stop
Authorization: Bearer jwt_token_here
Content-Type: application/json

{
  "streamId": "stream_123"
}
```

**Response**:
```json
{
  "success": true,
  "message": "Audio stream stopped"
}
```

### System Status

#### Health Check
```http
GET /api/v1/health
```

**Response**:
```json
{
  "status": "healthy",
  "timestamp": "2025-01-16T10:30:00Z",
  "uptime": 3600,
  "version": "1.0.0",
  "services": {
    "mumble": "connected",
    "webrtc": "active",
    "audio": "processing"
  }
}
```

#### System Status
```http
GET /api/v1/status
Authorization: Bearer jwt_token_here
```

**Response**:
```json
{
  "success": true,
  "status": {
    "users": 5,
    "connections": 3,
    "audio_streams": 2,
    "performance": {
      "cpu_usage": 45.2,
      "memory_usage": 67.8,
      "network_usage": 12.3
    }
  }
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

### Authentication
```javascript
// Authenticate WebSocket connection
ws.send(JSON.stringify({
    type: 'auth',
    token: 'jwt_token_here'
}));
```

### Radio Control
```javascript
// Set radio frequency
ws.send(JSON.stringify({
    type: 'radio',
    action: 'set_frequency',
    frequency: 121.500,
    power: 100,
    squelch: 50
}));

// PTT (Push-to-Talk)
ws.send(JSON.stringify({
    type: 'radio',
    action: 'ptt',
    state: 'on'  // or 'off'
}));
```

### Position Updates
```javascript
// Send position update
ws.send(JSON.stringify({
    type: 'position',
    latitude: 40.7128,
    longitude: -74.0060,
    altitude: 1000,
    heading: 270
}));
```

### Audio Stream
```javascript
// Start audio stream
ws.send(JSON.stringify({
    type: 'audio',
    action: 'start',
    sampleRate: 48000,
    channels: 1,
    bitrate: 64000
}));

// Send audio data
ws.send(JSON.stringify({
    type: 'audio',
    action: 'data',
    data: 'base64_encoded_audio_data'
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

    authenticate(token) {
        this.ws.send(JSON.stringify({
            type: 'auth',
            token: token
        }));
    }

    setRadio(frequency, power, squelch) {
        this.ws.send(JSON.stringify({
            type: 'radio',
            action: 'set_frequency',
            frequency: frequency,
            power: power,
            squelch: squelch
        }));
    }

    setPosition(latitude, longitude, altitude, heading) {
        this.ws.send(JSON.stringify({
            type: 'position',
            latitude: latitude,
            longitude: longitude,
            altitude: altitude,
            heading: heading
        }));
    }

    ptt(state) {
        this.ws.send(JSON.stringify({
            type: 'radio',
            action: 'ptt',
            state: state
        }));
    }

    handleMessage(data) {
        switch(data.type) {
            case 'auth':
                this.authenticated = data.success;
                break;
            case 'radio':
                this.handleRadioMessage(data);
                break;
            case 'position':
                this.handlePositionMessage(data);
                break;
            case 'audio':
                this.handleAudioMessage(data);
                break;
        }
    }

    handleRadioMessage(data) {
        console.log('Radio status:', data);
    }

    handlePositionMessage(data) {
        console.log('Position update:', data);
    }

    handleAudioMessage(data) {
        console.log('Audio data:', data);
    }
}

// Usage
const client = new FGcomWebRTCClient('ws://localhost:8081');
client.connect();

// Authenticate
client.authenticate('your_jwt_token');

// Set radio
client.setRadio(121.500, 100, 50);

// Set position
client.setPosition(40.7128, -74.0060, 1000, 270);

// PTT
client.ptt('on');
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

    def authenticate(self, token):
        self.ws.send(json.dumps({
            'type': 'auth',
            'token': token
        }))

    def set_radio(self, frequency, power, squelch):
        self.ws.send(json.dumps({
            'type': 'radio',
            'action': 'set_frequency',
            'frequency': frequency,
            'power': power,
            'squelch': squelch
        }))

    def set_position(self, latitude, longitude, altitude, heading):
        self.ws.send(json.dumps({
            'type': 'position',
            'latitude': latitude,
            'longitude': longitude,
            'altitude': altitude,
            'heading': heading
        }))

    def ptt(self, state):
        self.ws.send(json.dumps({
            'type': 'radio',
            'action': 'ptt',
            'state': state
        }))

    def handle_message(self, data):
        if data['type'] == 'auth':
            self.authenticated = data['success']
        elif data['type'] == 'radio':
            self.handle_radio_message(data)
        elif data['type'] == 'position':
            self.handle_position_message(data)
        elif data['type'] == 'audio':
            self.handle_audio_message(data)

    def handle_radio_message(self, data):
        print('Radio status:', data)

    def handle_position_message(self, data):
        print('Position update:', data)

    def handle_audio_message(self, data):
        print('Audio data:', data)

# Usage
client = FGcomWebRTCClient('ws://localhost:8081')
client.connect()

# Authenticate
client.authenticate('your_jwt_token')

# Set radio
client.set_radio(121.500, 100, 50)

# Set position
client.set_position(40.7128, -74.0060, 1000, 270)

# PTT
client.ptt('on')
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
  "type": "error",
  "error": "Authentication failed",
  "code": 401,
  "message": "Invalid token"
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
- JWT token-based authentication
- Token expiration handling
- Secure token storage
- Session management

### Authorization
- Role-based access control
- Permission management
- Resource access control
- API rate limiting

### Encryption
- TLS/SSL encryption
- WebSocket secure connections
- Audio stream encryption
- Data transmission security

## Performance

### Optimization
- Connection pooling
- Message batching
- Compression
- Caching
- Load balancing

### Monitoring
- Connection metrics
- Performance monitoring
- Error tracking
- Usage analytics
- Health checks

## Troubleshooting

### Common Issues

1. **Connection Failed**
   - Check server URL
   - Verify firewall settings
   - Check network connectivity
   - Verify server status

2. **Authentication Failed**
   - Check token validity
   - Verify token expiration
   - Check user permissions
   - Verify credentials

3. **Audio Issues**
   - Check microphone permissions
   - Verify audio device selection
   - Check audio format settings
   - Verify network bandwidth

### Debug Mode
```javascript
// Enable debug logging
const client = new FGcomWebRTCClient('ws://localhost:8081');
client.debug = true;
client.connect();
```

## Best Practices

### Client Development
1. **Error Handling**: Implement comprehensive error handling
2. **Reconnection**: Implement automatic reconnection
3. **Authentication**: Handle token expiration
4. **Performance**: Optimize message handling
5. **Security**: Use secure connections

### API Usage
1. **Rate Limiting**: Respect API rate limits
2. **Error Handling**: Handle all error conditions
3. **Validation**: Validate input data
4. **Monitoring**: Monitor API performance
5. **Documentation**: Keep API documentation updated

## Support

For API issues:
1. Check API documentation
2. Review error messages
3. Verify authentication
4. Check network connectivity
5. Review server logs
