# WebRTC Gateway Integration Examples

This document provides comprehensive integration examples for the FGcom-Mumble WebRTC Gateway, including client implementations, server integration, and deployment scenarios.

## Client Integration Examples

### HTML5 Web Client

#### Basic HTML Structure
```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>FGcom WebRTC Client</title>
    <link rel="stylesheet" href="css/style.css">
</head>
<body>
    <div id="app">
        <header>
            <h1>FGcom WebRTC Client</h1>
            <div id="connection-status">Disconnected</div>
        </header>
        
        <main>
            <section id="login-section">
                <h2>Login</h2>
                <form id="login-form">
                    <input type="text" id="username" placeholder="Username" required>
                    <input type="password" id="password" placeholder="Password" required>
                    <button type="submit">Login</button>
                </form>
            </section>
            
            <section id="radio-section" style="display: none;">
                <h2>Radio Control</h2>
                <div class="radio-controls">
                    <label>Frequency: <input type="number" id="frequency" value="121.500" step="0.001"></label>
                    <label>Power: <input type="range" id="power" min="0" max="100" value="50"></label>
                    <label>Squelch: <input type="range" id="squelch" min="0" max="100" value="50"></label>
                    <button id="ptt-button">PTT</button>
                </div>
            </section>
            
            <section id="position-section" style="display: none;">
                <h2>Position</h2>
                <div class="position-controls">
                    <label>Latitude: <input type="number" id="latitude" value="40.7128" step="0.0001"></label>
                    <label>Longitude: <input type="number" id="longitude" value="-74.0060" step="0.0001"></label>
                    <label>Altitude: <input type="number" id="altitude" value="1000" step="1"></label>
                    <label>Heading: <input type="number" id="heading" value="270" step="1"></label>
                    <button id="update-position">Update Position</button>
                </div>
            </section>
            
            <section id="audio-section" style="display: none;">
                <h2>Audio</h2>
                <div class="audio-controls">
                    <label>Volume: <input type="range" id="volume" min="0" max="100" value="50"></label>
                    <div id="audio-levels">
                        <div class="level-meter">
                            <div class="level-bar" id="input-level"></div>
                        </div>
                        <div class="level-meter">
                            <div class="level-bar" id="output-level"></div>
                        </div>
                    </div>
                </div>
            </section>
        </main>
    </div>
    
    <script src="js/webrtc-client.js"></script>
    <script src="js/app.js"></script>
</body>
</html>
```

#### CSS Styling
```css
/* styles.css */
body {
    font-family: Arial, sans-serif;
    margin: 0;
    padding: 20px;
    background-color: #f0f0f0;
}

#app {
    max-width: 800px;
    margin: 0 auto;
    background: white;
    border-radius: 8px;
    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
    overflow: hidden;
}

header {
    background: #2c3e50;
    color: white;
    padding: 20px;
    display: flex;
    justify-content: space-between;
    align-items: center;
}

#connection-status {
    padding: 5px 10px;
    border-radius: 4px;
    background: #e74c3c;
    color: white;
}

#connection-status.connected {
    background: #27ae60;
}

main {
    padding: 20px;
}

section {
    margin-bottom: 30px;
    padding: 20px;
    border: 1px solid #ddd;
    border-radius: 4px;
}

.radio-controls, .position-controls, .audio-controls {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 15px;
    align-items: center;
}

label {
    display: flex;
    flex-direction: column;
    gap: 5px;
}

input[type="number"], input[type="text"], input[type="password"] {
    padding: 8px;
    border: 1px solid #ddd;
    border-radius: 4px;
}

input[type="range"] {
    width: 100%;
}

button {
    padding: 10px 20px;
    background: #3498db;
    color: white;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    font-size: 14px;
}

button:hover {
    background: #2980b9;
}

button:active {
    background: #21618c;
}

#ptt-button {
    background: #e74c3c;
    font-size: 18px;
    font-weight: bold;
}

#ptt-button:active {
    background: #c0392b;
}

.audio-controls {
    display: flex;
    flex-direction: column;
    gap: 15px;
}

.level-meter {
    width: 100%;
    height: 20px;
    background: #ecf0f1;
    border-radius: 10px;
    overflow: hidden;
    position: relative;
}

.level-bar {
    height: 100%;
    background: linear-gradient(to right, #27ae60, #f39c12, #e74c3c);
    width: 0%;
    transition: width 0.1s ease;
}

@media (max-width: 600px) {
    .radio-controls, .position-controls {
        grid-template-columns: 1fr;
    }
}
```

#### JavaScript Client Implementation
```javascript
// webrtc-client.js
class FGcomWebRTCClient {
    constructor(serverUrl) {
        this.serverUrl = serverUrl;
        this.ws = null;
        this.authenticated = false;
        this.audioContext = null;
        this.mediaStream = null;
        this.audioLevels = {
            input: 0,
            output: 0
        };
    }

    async connect() {
        try {
            this.ws = new WebSocket(this.serverUrl + '/ws');
            
            this.ws.onopen = () => {
                console.log('Connected to FGcom WebRTC Gateway');
                this.updateConnectionStatus('Connected', true);
            };

            this.ws.onmessage = (event) => {
                const data = JSON.parse(event.data);
                this.handleMessage(data);
            };

            this.ws.onclose = () => {
                console.log('Disconnected from FGcom WebRTC Gateway');
                this.updateConnectionStatus('Disconnected', false);
            };

            this.ws.onerror = (error) => {
                console.error('WebSocket error:', error);
                this.updateConnectionStatus('Error', false);
            };

        } catch (error) {
            console.error('Connection failed:', error);
            this.updateConnectionStatus('Connection Failed', false);
        }
    }

    async authenticate(username, password) {
        try {
            const response = await fetch(this.serverUrl + '/api/v1/auth/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    username: username,
                    password: password
                })
            });

            const data = await response.json();
            
            if (data.success) {
                this.authenticated = true;
                this.token = data.token;
                this.user = data.user;
                
                // Authenticate WebSocket connection
                this.ws.send(JSON.stringify({
                    type: 'auth',
                    token: this.token
                }));
                
                this.showRadioSection();
                return true;
            } else {
                throw new Error(data.message || 'Authentication failed');
            }
        } catch (error) {
            console.error('Authentication error:', error);
            alert('Authentication failed: ' + error.message);
            return false;
        }
    }

    async initializeAudio() {
        try {
            this.audioContext = new (window.AudioContext || window.webkitAudioContext)();
            this.mediaStream = await navigator.mediaDevices.getUserMedia({
                audio: {
                    sampleRate: 48000,
                    channelCount: 1,
                    echoCancellation: true,
                    noiseSuppression: true
                }
            });

            this.setupAudioProcessing();
            this.showAudioSection();
        } catch (error) {
            console.error('Audio initialization failed:', error);
            alert('Audio initialization failed: ' + error.message);
        }
    }

    setupAudioProcessing() {
        const source = this.audioContext.createMediaStreamSource(this.mediaStream);
        const analyser = this.audioContext.createAnalyser();
        analyser.fftSize = 256;
        
        source.connect(analyser);
        
        const dataArray = new Uint8Array(analyser.frequencyBinCount);
        
        const updateAudioLevels = () => {
            analyser.getByteFrequencyData(dataArray);
            const average = dataArray.reduce((a, b) => a + b) / dataArray.length;
            this.audioLevels.input = (average / 255) * 100;
            this.updateAudioLevelDisplay();
            requestAnimationFrame(updateAudioLevels);
        };
        
        updateAudioLevels();
    }

    setRadio(frequency, power, squelch) {
        if (!this.authenticated) return;
        
        this.ws.send(JSON.stringify({
            type: 'radio',
            action: 'set_frequency',
            frequency: parseFloat(frequency),
            power: parseInt(power),
            squelch: parseInt(squelch)
        }));
    }

    setPosition(latitude, longitude, altitude, heading) {
        if (!this.authenticated) return;
        
        this.ws.send(JSON.stringify({
            type: 'position',
            latitude: parseFloat(latitude),
            longitude: parseFloat(longitude),
            altitude: parseInt(altitude),
            heading: parseInt(heading)
        }));
    }

    ptt(state) {
        if (!this.authenticated) return;
        
        this.ws.send(JSON.stringify({
            type: 'radio',
            action: 'ptt',
            state: state
        }));
    }

    handleMessage(data) {
        switch(data.type) {
            case 'auth':
                if (data.success) {
                    console.log('WebSocket authenticated');
                } else {
                    console.error('WebSocket authentication failed:', data.message);
                }
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
            case 'error':
                console.error('Server error:', data.message);
                break;
        }
    }

    handleRadioMessage(data) {
        console.log('Radio status:', data);
        // Update UI with radio status
    }

    handlePositionMessage(data) {
        console.log('Position update:', data);
        // Update UI with position data
    }

    handleAudioMessage(data) {
        console.log('Audio data:', data);
        // Handle audio data
    }

    updateConnectionStatus(status, connected) {
        const statusElement = document.getElementById('connection-status');
        statusElement.textContent = status;
        statusElement.className = connected ? 'connected' : '';
    }

    showRadioSection() {
        document.getElementById('radio-section').style.display = 'block';
    }

    showAudioSection() {
        document.getElementById('audio-section').style.display = 'block';
    }

    updateAudioLevelDisplay() {
        const inputLevel = document.getElementById('input-level');
        const outputLevel = document.getElementById('output-level');
        
        if (inputLevel) {
            inputLevel.style.width = this.audioLevels.input + '%';
        }
        
        if (outputLevel) {
            outputLevel.style.width = this.audioLevels.output + '%';
        }
    }
}

// app.js
let client = null;

document.addEventListener('DOMContentLoaded', function() {
    client = new FGcomWebRTCClient('ws://localhost:8081');
    client.connect();
    
    // Login form
    document.getElementById('login-form').addEventListener('submit', async function(e) {
        e.preventDefault();
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;
        
        const success = await client.authenticate(username, password);
        if (success) {
            document.getElementById('login-section').style.display = 'none';
            await client.initializeAudio();
        }
    });
    
    // Radio controls
    document.getElementById('frequency').addEventListener('change', function() {
        const frequency = this.value;
        const power = document.getElementById('power').value;
        const squelch = document.getElementById('squelch').value;
        client.setRadio(frequency, power, squelch);
    });
    
    document.getElementById('power').addEventListener('input', function() {
        const frequency = document.getElementById('frequency').value;
        const power = this.value;
        const squelch = document.getElementById('squelch').value;
        client.setRadio(frequency, power, squelch);
    });
    
    document.getElementById('squelch').addEventListener('input', function() {
        const frequency = document.getElementById('frequency').value;
        const power = document.getElementById('power').value;
        const squelch = this.value;
        client.setRadio(frequency, power, squelch);
    });
    
    // PTT button
    const pttButton = document.getElementById('ptt-button');
    pttButton.addEventListener('mousedown', function() {
        client.ptt('on');
        this.style.background = '#c0392b';
    });
    
    pttButton.addEventListener('mouseup', function() {
        client.ptt('off');
        this.style.background = '#e74c3c';
    });
    
    // Position controls
    document.getElementById('update-position').addEventListener('click', function() {
        const latitude = document.getElementById('latitude').value;
        const longitude = document.getElementById('longitude').value;
        const altitude = document.getElementById('altitude').value;
        const heading = document.getElementById('heading').value;
        client.setPosition(latitude, longitude, altitude, heading);
    });
    
    // Volume control
    document.getElementById('volume').addEventListener('input', function() {
        // Handle volume control
        console.log('Volume:', this.value);
    });
});
```

### React Client

#### React Component
```jsx
// FGcomClient.jsx
import React, { useState, useEffect, useRef } from 'react';

const FGcomClient = () => {
    const [connected, setConnected] = useState(false);
    const [authenticated, setAuthenticated] = useState(false);
    const [radio, setRadio] = useState({
        frequency: 121.500,
        power: 50,
        squelch: 50
    });
    const [position, setPosition] = useState({
        latitude: 40.7128,
        longitude: -74.0060,
        altitude: 1000,
        heading: 270
    });
    const [ptt, setPtt] = useState(false);
    
    const wsRef = useRef(null);
    const audioContextRef = useRef(null);
    const mediaStreamRef = useRef(null);

    useEffect(() => {
        connect();
        return () => {
            if (wsRef.current) {
                wsRef.current.close();
            }
        };
    }, []);

    const connect = () => {
        const ws = new WebSocket('ws://localhost:8081/ws');
        wsRef.current = ws;

        ws.onopen = () => {
            setConnected(true);
            console.log('Connected to FGcom WebRTC Gateway');
        };

        ws.onmessage = (event) => {
            const data = JSON.parse(event.data);
            handleMessage(data);
        };

        ws.onclose = () => {
            setConnected(false);
            console.log('Disconnected from FGcom WebRTC Gateway');
        };

        ws.onerror = (error) => {
            console.error('WebSocket error:', error);
        };
    };

    const authenticate = async (username, password) => {
        try {
            const response = await fetch('http://localhost:8081/api/v1/auth/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ username, password })
            });

            const data = await response.json();
            
            if (data.success) {
                setAuthenticated(true);
                wsRef.current.send(JSON.stringify({
                    type: 'auth',
                    token: data.token
                }));
                return true;
            } else {
                throw new Error(data.message || 'Authentication failed');
            }
        } catch (error) {
            console.error('Authentication error:', error);
            return false;
        }
    };

    const setRadio = (frequency, power, squelch) => {
        if (!authenticated) return;
        
        wsRef.current.send(JSON.stringify({
            type: 'radio',
            action: 'set_frequency',
            frequency: parseFloat(frequency),
            power: parseInt(power),
            squelch: parseInt(squelch)
        }));
    };

    const setPosition = (latitude, longitude, altitude, heading) => {
        if (!authenticated) return;
        
        wsRef.current.send(JSON.stringify({
            type: 'position',
            latitude: parseFloat(latitude),
            longitude: parseFloat(longitude),
            altitude: parseInt(altitude),
            heading: parseInt(heading)
        }));
    };

    const ptt = (state) => {
        if (!authenticated) return;
        
        wsRef.current.send(JSON.stringify({
            type: 'radio',
            action: 'ptt',
            state: state
        }));
    };

    const handleMessage = (data) => {
        switch(data.type) {
            case 'auth':
                if (data.success) {
                    console.log('WebSocket authenticated');
                } else {
                    console.error('WebSocket authentication failed:', data.message);
                }
                break;
            case 'radio':
                console.log('Radio status:', data);
                break;
            case 'position':
                console.log('Position update:', data);
                break;
            case 'audio':
                console.log('Audio data:', data);
                break;
            case 'error':
                console.error('Server error:', data.message);
                break;
        }
    };

    return (
        <div className="fgcom-client">
            <header>
                <h1>FGcom WebRTC Client</h1>
                <div className={`connection-status ${connected ? 'connected' : 'disconnected'}`}>
                    {connected ? 'Connected' : 'Disconnected'}
                </div>
            </header>
            
            {!authenticated ? (
                <LoginForm onAuthenticate={authenticate} />
            ) : (
                <div className="main-content">
                    <RadioControls 
                        radio={radio} 
                        onRadioChange={setRadio}
                        onPtt={ptt}
                    />
                    <PositionControls 
                        position={position} 
                        onPositionChange={setPosition}
                    />
                    <AudioControls />
                </div>
            )}
        </div>
    );
};

const LoginForm = ({ onAuthenticate }) => {
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');

    const handleSubmit = async (e) => {
        e.preventDefault();
        await onAuthenticate(username, password);
    };

    return (
        <form onSubmit={handleSubmit} className="login-form">
            <h2>Login</h2>
            <input
                type="text"
                placeholder="Username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
            />
            <input
                type="password"
                placeholder="Password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
            />
            <button type="submit">Login</button>
        </form>
    );
};

const RadioControls = ({ radio, onRadioChange, onPtt }) => {
    const [ptt, setPtt] = useState(false);

    const handleRadioChange = (field, value) => {
        const newRadio = { ...radio, [field]: value };
        onRadioChange(newRadio);
    };

    const handlePtt = (state) => {
        setPtt(state);
        onPtt(state);
    };

    return (
        <div className="radio-controls">
            <h2>Radio Control</h2>
            <div className="control-group">
                <label>
                    Frequency:
                    <input
                        type="number"
                        value={radio.frequency}
                        onChange={(e) => handleRadioChange('frequency', e.target.value)}
                        step="0.001"
                    />
                </label>
                <label>
                    Power:
                    <input
                        type="range"
                        min="0"
                        max="100"
                        value={radio.power}
                        onChange={(e) => handleRadioChange('power', e.target.value)}
                    />
                    {radio.power}%
                </label>
                <label>
                    Squelch:
                    <input
                        type="range"
                        min="0"
                        max="100"
                        value={radio.squelch}
                        onChange={(e) => handleRadioChange('squelch', e.target.value)}
                    />
                    {radio.squelch}%
                </label>
            </div>
            <button
                className={`ptt-button ${ptt ? 'active' : ''}`}
                onMouseDown={() => handlePtt('on')}
                onMouseUp={() => handlePtt('off')}
            >
                PTT
            </button>
        </div>
    );
};

const PositionControls = ({ position, onPositionChange }) => {
    const handlePositionChange = (field, value) => {
        const newPosition = { ...position, [field]: value };
        onPositionChange(newPosition);
    };

    return (
        <div className="position-controls">
            <h2>Position</h2>
            <div className="control-group">
                <label>
                    Latitude:
                    <input
                        type="number"
                        value={position.latitude}
                        onChange={(e) => handlePositionChange('latitude', e.target.value)}
                        step="0.0001"
                    />
                </label>
                <label>
                    Longitude:
                    <input
                        type="number"
                        value={position.longitude}
                        onChange={(e) => handlePositionChange('longitude', e.target.value)}
                        step="0.0001"
                    />
                </label>
                <label>
                    Altitude:
                    <input
                        type="number"
                        value={position.altitude}
                        onChange={(e) => handlePositionChange('altitude', e.target.value)}
                        step="1"
                    />
                </label>
                <label>
                    Heading:
                    <input
                        type="number"
                        value={position.heading}
                        onChange={(e) => handlePositionChange('heading', e.target.value)}
                        step="1"
                    />
                </label>
            </div>
            <button onClick={() => onPositionChange(position)}>
                Update Position
            </button>
        </div>
    );
};

const AudioControls = () => {
    const [volume, setVolume] = useState(50);

    return (
        <div className="audio-controls">
            <h2>Audio</h2>
            <div className="control-group">
                <label>
                    Volume:
                    <input
                        type="range"
                        min="0"
                        max="100"
                        value={volume}
                        onChange={(e) => setVolume(e.target.value)}
                    />
                    {volume}%
                </label>
            </div>
            <div className="audio-levels">
                <div className="level-meter">
                    <div className="level-bar" style={{ width: '50%' }}></div>
                </div>
            </div>
        </div>
    );
};

export default FGcomClient;
```

## Server Integration Examples

### Node.js Server Integration

#### Express Server
```javascript
// server.js
const express = require('express');
const WebSocket = require('ws');
const http = require('http');
const path = require('path');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));

// API routes
app.use('/api/v1', require('./routes/api'));

// WebSocket handling
wss.on('connection', (ws) => {
    console.log('Client connected');
    
    ws.on('message', (message) => {
        try {
            const data = JSON.parse(message);
            handleWebSocketMessage(ws, data);
        } catch (error) {
            console.error('Invalid message:', error);
        }
    });
    
    ws.on('close', () => {
        console.log('Client disconnected');
    });
});

function handleWebSocketMessage(ws, data) {
    switch(data.type) {
        case 'auth':
            handleAuthentication(ws, data);
            break;
        case 'radio':
            handleRadioMessage(ws, data);
            break;
        case 'position':
            handlePositionMessage(ws, data);
            break;
        case 'audio':
            handleAudioMessage(ws, data);
            break;
    }
}

function handleAuthentication(ws, data) {
    // Validate JWT token
    if (validateToken(data.token)) {
        ws.authenticated = true;
        ws.send(JSON.stringify({
            type: 'auth',
            success: true
        }));
    } else {
        ws.send(JSON.stringify({
            type: 'auth',
            success: false,
            message: 'Invalid token'
        }));
    }
}

function handleRadioMessage(ws, data) {
    if (!ws.authenticated) return;
    
    // Handle radio control
    console.log('Radio message:', data);
    
    // Send response
    ws.send(JSON.stringify({
        type: 'radio',
        success: true,
        data: data
    }));
}

function handlePositionMessage(ws, data) {
    if (!ws.authenticated) return;
    
    // Handle position update
    console.log('Position message:', data);
    
    // Send response
    ws.send(JSON.stringify({
        type: 'position',
        success: true,
        data: data
    }));
}

function handleAudioMessage(ws, data) {
    if (!ws.authenticated) return;
    
    // Handle audio data
    console.log('Audio message:', data);
    
    // Send response
    ws.send(JSON.stringify({
        type: 'audio',
        success: true,
        data: data
    }));
}

function validateToken(token) {
    // Implement JWT token validation
    return true; // Simplified for example
}

const PORT = process.env.PORT || 8081;
server.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
```

#### API Routes
```javascript
// routes/api.js
const express = require('express');
const router = express.Router();

// Authentication routes
router.post('/auth/login', async (req, res) => {
    const { username, password } = req.body;
    
    try {
        // Validate credentials
        const user = await validateCredentials(username, password);
        
        if (user) {
            const token = generateJWTToken(user);
            res.json({
                success: true,
                token: token,
                user: user
            });
        } else {
            res.status(401).json({
                success: false,
                message: 'Invalid credentials'
            });
        }
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Authentication error'
        });
    }
});

router.post('/auth/register', async (req, res) => {
    const { username, password, callsign, email } = req.body;
    
    try {
        // Create user
        const user = await createUser(username, password, callsign, email);
        
        res.json({
            success: true,
            message: 'User registered successfully',
            user: user
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Registration error'
        });
    }
});

// Radio routes
router.post('/radio/frequency', (req, res) => {
    const { frequency, power, squelch } = req.body;
    
    // Validate frequency
    if (frequency < 118.000 || frequency > 137.000) {
        return res.status(400).json({
            success: false,
            message: 'Invalid frequency range'
        });
    }
    
    // Set radio frequency
    setRadioFrequency(frequency, power, squelch);
    
    res.json({
        success: true,
        radio: {
            frequency: frequency,
            power: power,
            squelch: squelch,
            status: 'active'
        }
    });
});

router.get('/radio/status', (req, res) => {
    const radioStatus = getRadioStatus();
    
    res.json({
        success: true,
        radio: radioStatus
    });
});

// Position routes
router.post('/position', (req, res) => {
    const { latitude, longitude, altitude, heading } = req.body;
    
    // Validate position
    if (latitude < -90 || latitude > 90 || longitude < -180 || longitude > 180) {
        return res.status(400).json({
            success: false,
            message: 'Invalid position coordinates'
        });
    }
    
    // Set position
    setPosition(latitude, longitude, altitude, heading);
    
    res.json({
        success: true,
        position: {
            latitude: latitude,
            longitude: longitude,
            altitude: altitude,
            heading: heading,
            timestamp: new Date().toISOString()
        }
    });
});

router.get('/position', (req, res) => {
    const position = getPosition();
    
    res.json({
        success: true,
        position: position
    });
});

// Audio routes
router.post('/audio/start', (req, res) => {
    const { sampleRate, channels, bitrate } = req.body;
    
    const streamId = startAudioStream(sampleRate, channels, bitrate);
    
    res.json({
        success: true,
        audio: {
            streamId: streamId,
            sampleRate: sampleRate,
            channels: channels,
            bitrate: bitrate,
            status: 'active'
        }
    });
});

router.post('/audio/stop', (req, res) => {
    const { streamId } = req.body;
    
    stopAudioStream(streamId);
    
    res.json({
        success: true,
        message: 'Audio stream stopped'
    });
});

// Health check
router.get('/health', (req, res) => {
    res.json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        version: '1.0.0',
        services: {
            mumble: 'connected',
            webrtc: 'active',
            audio: 'processing'
        }
    });
});

// Status
router.get('/status', (req, res) => {
    const status = getSystemStatus();
    
    res.json({
        success: true,
        status: status
    });
});

module.exports = router;
```

## Deployment Examples

### Docker Deployment

#### Dockerfile
```dockerfile
FROM node:18-alpine

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm install --production

# Copy application files
COPY . .

# Create non-root user
RUN addgroup -g 1001 -S nodejs
RUN adduser -S nextjs -u 1001

# Change ownership
RUN chown -R nextjs:nodejs /app
USER nextjs

# Expose port
EXPOSE 8081

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8081/api/v1/health || exit 1

# Start application
CMD ["node", "server/gateway.js"]
```

#### Docker Compose
```yaml
# docker-compose.yml
version: '3.8'

services:
  fgcom-webrtc-gateway:
    build: .
    ports:
      - "8081:8081"
    environment:
      - NODE_ENV=production
      - PORT=8081
      - MUMBLE_HOST=localhost
      - MUMBLE_PORT=64738
    volumes:
      - ./logs:/app/logs
      - ./data:/app/data
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8081/api/v1/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./ssl:/etc/nginx/ssl
    depends_on:
      - fgcom-webrtc-gateway
    restart: unless-stopped
```

### Kubernetes Deployment

#### Deployment YAML
```yaml
# k8s-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: fgcom-webrtc-gateway
  labels:
    app: fgcom-webrtc-gateway
spec:
  replicas: 3
  selector:
    matchLabels:
      app: fgcom-webrtc-gateway
  template:
    metadata:
      labels:
        app: fgcom-webrtc-gateway
    spec:
      containers:
      - name: fgcom-webrtc-gateway
        image: fgcom-webrtc-gateway:latest
        ports:
        - containerPort: 8081
        env:
        - name: NODE_ENV
          value: "production"
        - name: PORT
          value: "8081"
        - name: MUMBLE_HOST
          value: "mumble-server"
        - name: MUMBLE_PORT
          value: "64738"
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /api/v1/health
            port: 8081
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /api/v1/health
            port: 8081
          initialDelaySeconds: 5
          periodSeconds: 5
        volumeMounts:
        - name: logs
          mountPath: /app/logs
        - name: data
          mountPath: /app/data
      volumes:
      - name: logs
        emptyDir: {}
      - name: data
        emptyDir: {}
---
apiVersion: v1
kind: Service
metadata:
  name: fgcom-webrtc-gateway-service
spec:
  selector:
    app: fgcom-webrtc-gateway
  ports:
  - port: 8081
    targetPort: 8081
  type: LoadBalancer
```

## Best Practices

### Client Development
1. **Error Handling**: Implement comprehensive error handling
2. **Reconnection**: Implement automatic reconnection
3. **Authentication**: Handle token expiration
4. **Performance**: Optimize message handling
5. **Security**: Use secure connections

### Server Development
1. **Scalability**: Design for horizontal scaling
2. **Security**: Implement proper authentication
3. **Monitoring**: Add comprehensive monitoring
4. **Logging**: Implement structured logging
5. **Testing**: Write comprehensive tests

### Deployment
1. **Security**: Use secure configurations
2. **Monitoring**: Implement health checks
3. **Scaling**: Design for auto-scaling
4. **Backup**: Implement backup strategies
5. **Documentation**: Maintain deployment documentation

## Support

For integration issues:
1. Check API documentation
2. Review error messages
3. Verify authentication
4. Check network connectivity
5. Review server logs
