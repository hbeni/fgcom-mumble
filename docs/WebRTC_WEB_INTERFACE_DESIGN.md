# FGCom-mumble WebRTC Web Interface Design

## Overview

This document outlines the design for the web-based client interface that will enable users to connect to FGCom-mumble servers directly through their web browsers. The interface provides a complete radio communication experience with intuitive controls and real-time feedback.

## User Interface Architecture

### 1. Main Layout Structure

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           FGCom-mumble Web Client                               │
├─────────────────────────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────┐  │
│  │   Header Bar    │  │   Connection    │  │   User Info     │  │   Settings  │  │
│  │   (Logo/Title)  │  │   Status       │  │   (Callsign)    │  │   (Gear)    │  │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘  └─────────────┘  │
├─────────────────────────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────────────────────────────┐  │
│  │                           Main Content Area                                │  │
│  │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐  ┌─────────┐  │  │
│  │  │   Radio Panel   │  │   Map View      │  │   Status Panel  │  │  Chat  │  │  │
│  │  │   (Controls)    │  │   (Coverage)    │  │   (Info)        │  │  (Log) │  │  │
│  │  └─────────────────┘  └─────────────────┘  └─────────────────┘  └─────────┘  │  │
│  └─────────────────────────────────────────────────────────────────────────────┘  │
├─────────────────────────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────────────────────────────┐  │
│  │                           Status Bar                                       │  │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐  │  │
│  │  │ Connection │  │   Audio     │  │   Signal    │  │   Time/Date     │  │  │
│  │  │   Status   │  │   Quality   │  │   Strength  │  │                 │  │  │
│  │  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────────┘  │  │
│  └─────────────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### 2. Responsive Design Breakpoints

```css
/* Mobile First Design */
@media (max-width: 768px) {
    .main-content {
        flex-direction: column;
    }
    
    .radio-panel, .map-view, .status-panel {
        width: 100%;
        margin-bottom: 10px;
    }
}

@media (min-width: 769px) and (max-width: 1024px) {
    .main-content {
        grid-template-columns: 1fr 1fr;
    }
    
    .radio-panel {
        grid-column: 1;
    }
    
    .map-view {
        grid-column: 2;
    }
}

@media (min-width: 1025px) {
    .main-content {
        grid-template-columns: 300px 1fr 300px;
    }
}
```

## Core Components

### 1. Radio Panel Component

#### 1.1 Radio Stack Interface
```html
<div class="radio-panel">
    <div class="radio-stack">
        <div class="radio-unit" data-radio="COM1">
            <div class="radio-header">
                <h3>COM1</h3>
                <div class="radio-status">
                    <span class="status-indicator active"></span>
                    <span class="status-text">ON</span>
                </div>
            </div>
            
            <div class="radio-controls">
                <div class="frequency-display">
                    <input type="text" class="frequency-input" value="123.45" maxlength="6">
                    <span class="frequency-unit">MHz</span>
                </div>
                
                <div class="power-control">
                    <label>Power</label>
                    <input type="range" class="power-slider" min="0" max="100" value="100">
                    <span class="power-value">100%</span>
                </div>
                
                <div class="volume-control">
                    <label>Volume</label>
                    <input type="range" class="volume-slider" min="0" max="100" value="80">
                    <span class="volume-value">80%</span>
                </div>
                
                <div class="squelch-control">
                    <label>Squelch</label>
                    <input type="range" class="squelch-slider" min="0" max="100" value="50">
                    <span class="squelch-value">50%</span>
                </div>
                
                <div class="ptt-control">
                    <button class="ptt-button" data-radio="COM1">
                        <span class="ptt-text">PTT</span>
                        <span class="ptt-indicator"></span>
                    </button>
                </div>
            </div>
        </div>
        
        <!-- Additional radio units (COM2, COM3, etc.) -->
    </div>
</div>
```

#### 1.2 Radio Control JavaScript
```javascript
class RadioController {
    constructor() {
        this.radios = new Map();
        this.pttState = new Map();
        this.setupEventListeners();
    }
    
    setupEventListeners() {
        // PTT button handling
        document.querySelectorAll('.ptt-button').forEach(button => {
            button.addEventListener('mousedown', (e) => this.handlePTTDown(e));
            button.addEventListener('mouseup', (e) => this.handlePTTUp(e));
            button.addEventListener('mouseleave', (e) => this.handlePTTUp(e));
        });
        
        // Frequency input handling
        document.querySelectorAll('.frequency-input').forEach(input => {
            input.addEventListener('change', (e) => this.handleFrequencyChange(e));
            input.addEventListener('keypress', (e) => this.handleFrequencyKeypress(e));
        });
        
        // Slider controls
        document.querySelectorAll('.power-slider, .volume-slider, .squelch-slider').forEach(slider => {
            slider.addEventListener('input', (e) => this.handleSliderChange(e));
        });
    }
    
    handlePTTDown(event) {
        const radioId = event.target.dataset.radio;
        this.pttState.set(radioId, true);
        this.updatePTTDisplay(radioId, true);
        this.sendPTTState(radioId, true);
    }
    
    handlePTTUp(event) {
        const radioId = event.target.dataset.radio;
        this.pttState.set(radioId, false);
        this.updatePTTDisplay(radioId, false);
        this.sendPTTState(radioId, false);
    }
    
    updatePTTDisplay(radioId, pressed) {
        const button = document.querySelector(`[data-radio="${radioId}"] .ptt-button`);
        const indicator = button.querySelector('.ptt-indicator');
        
        if (pressed) {
            button.classList.add('ptt-active');
            indicator.classList.add('ptt-indicator-active');
        } else {
            button.classList.remove('ptt-active');
            indicator.classList.remove('ptt-indicator-active');
        }
    }
    
    sendPTTState(radioId, pressed) {
        const radioData = {
            type: 'radio_update',
            radioId: radioId,
            ptt: pressed,
            timestamp: Date.now()
        };
        
        this.websocket.send(JSON.stringify(radioData));
    }
}
```

### 2. Map View Component

#### 2.1 Interactive Map Interface
```html
<div class="map-view">
    <div class="map-container">
        <div id="map" class="map"></div>
        <div class="map-controls">
            <button class="map-control-btn" id="zoom-in">+</button>
            <button class="map-control-btn" id="zoom-out">-</button>
            <button class="map-control-btn" id="center-map">⌂</button>
        </div>
    </div>
    
    <div class="map-overlay">
        <div class="coverage-layer">
            <div class="coverage-circle" data-frequency="123.45"></div>
        </div>
        
        <div class="station-markers">
            <div class="station-marker" data-callsign="N123AB" data-frequency="123.45">
                <div class="marker-icon"></div>
                <div class="marker-label">N123AB</div>
            </div>
        </div>
    </div>
</div>
```

#### 2.2 Map Controller JavaScript
```javascript
class MapController {
    constructor() {
        this.map = null;
        this.stations = new Map();
        this.coverageLayers = new Map();
        this.initializeMap();
    }
    
    initializeMap() {
        // Initialize OpenStreetMap
        this.map = L.map('map').setView([40.7128, -74.0060], 10);
        
        L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
            attribution: '© OpenStreetMap contributors'
        }).addTo(this.map);
        
        // Add coverage visualization
        this.addCoverageLayer();
        
        // Add station markers
        this.addStationMarkers();
    }
    
    addCoverageLayer() {
        // Add radio coverage visualization
        const coverageLayer = L.layerGroup();
        this.coverageLayers.set('coverage', coverageLayer);
        coverageLayer.addTo(this.map);
    }
    
    updateStationPosition(callsign, lat, lon, frequency) {
        const station = this.stations.get(callsign);
        
        if (station) {
            station.setLatLng([lat, lon]);
        } else {
            const marker = L.marker([lat, lon])
                .bindPopup(`<b>${callsign}</b><br>Frequency: ${frequency} MHz`)
                .addTo(this.map);
            
            this.stations.set(callsign, marker);
        }
        
        // Update coverage circle
        this.updateCoverageCircle(lat, lon, frequency);
    }
    
    updateCoverageCircle(lat, lon, frequency) {
        const coverageLayer = this.coverageLayers.get('coverage');
        coverageLayer.clearLayers();
        
        // Calculate coverage radius based on frequency and power
        const radius = this.calculateCoverageRadius(frequency);
        
        const circle = L.circle([lat, lon], {
            color: '#3388ff',
            fillColor: '#3388ff',
            fillOpacity: 0.2,
            radius: radius
        }).addTo(coverageLayer);
    }
    
    calculateCoverageRadius(frequency) {
        // Simplified coverage calculation
        // In reality, this would use the full propagation model
        if (frequency >= 118 && frequency <= 137) {
            return 50000; // 50km for VHF
        } else if (frequency >= 2 && frequency <= 30) {
            return 200000; // 200km for HF
        } else {
            return 10000; // 10km for UHF
        }
    }
}
```

### 3. Status Panel Component

#### 3.1 Connection Status Display
```html
<div class="status-panel">
    <div class="connection-status">
        <h3>Connection Status</h3>
        <div class="status-item">
            <span class="status-label">Server:</span>
            <span class="status-value" id="server-status">Connected</span>
        </div>
        <div class="status-item">
            <span class="status-label">Audio:</span>
            <span class="status-value" id="audio-status">Active</span>
        </div>
        <div class="status-item">
            <span class="status-label">Latency:</span>
            <span class="status-value" id="latency-value">45ms</span>
        </div>
    </div>
    
    <div class="signal-quality">
        <h3>Signal Quality</h3>
        <div class="quality-meter">
            <div class="quality-bar">
                <div class="quality-fill" id="quality-fill"></div>
            </div>
            <span class="quality-text" id="quality-text">Excellent</span>
        </div>
    </div>
    
    <div class="active-stations">
        <h3>Active Stations</h3>
        <div class="station-list" id="station-list">
            <!-- Station list will be populated dynamically -->
        </div>
    </div>
</div>
```

#### 3.2 Status Controller JavaScript
```javascript
class StatusController {
    constructor() {
        this.connectionStatus = 'disconnected';
        this.audioQuality = 0;
        this.latency = 0;
        this.activeStations = new Map();
        this.updateInterval = null;
        this.startStatusUpdates();
    }
    
    startStatusUpdates() {
        this.updateInterval = setInterval(() => {
            this.updateConnectionStatus();
            this.updateAudioQuality();
            this.updateLatency();
            this.updateActiveStations();
        }, 1000);
    }
    
    updateConnectionStatus() {
        const statusElement = document.getElementById('server-status');
        const audioElement = document.getElementById('audio-status');
        
        if (this.connectionStatus === 'connected') {
            statusElement.textContent = 'Connected';
            statusElement.className = 'status-value connected';
        } else {
            statusElement.textContent = 'Disconnected';
            statusElement.className = 'status-value disconnected';
        }
        
        if (this.audioQuality > 0) {
            audioElement.textContent = 'Active';
            audioElement.className = 'status-value active';
        } else {
            audioElement.textContent = 'Inactive';
            audioElement.className = 'status-value inactive';
        }
    }
    
    updateAudioQuality() {
        const qualityFill = document.getElementById('quality-fill');
        const qualityText = document.getElementById('quality-text');
        
        const percentage = Math.min(100, Math.max(0, this.audioQuality));
        qualityFill.style.width = `${percentage}%`;
        
        if (percentage >= 80) {
            qualityText.textContent = 'Excellent';
            qualityFill.className = 'quality-fill excellent';
        } else if (percentage >= 60) {
            qualityText.textContent = 'Good';
            qualityFill.className = 'quality-fill good';
        } else if (percentage >= 40) {
            qualityText.textContent = 'Fair';
            qualityFill.className = 'quality-fill fair';
        } else {
            qualityText.textContent = 'Poor';
            qualityFill.className = 'quality-fill poor';
        }
    }
    
    updateActiveStations() {
        const stationList = document.getElementById('station-list');
        stationList.innerHTML = '';
        
        this.activeStations.forEach((station, callsign) => {
            const stationElement = document.createElement('div');
            stationElement.className = 'station-item';
            stationElement.innerHTML = `
                <div class="station-callsign">${callsign}</div>
                <div class="station-frequency">${station.frequency} MHz</div>
                <div class="station-signal">${station.signalStrength}%</div>
            `;
            stationList.appendChild(stationElement);
        });
    }
}
```

### 4. Chat/Log Component

#### 4.1 Communication Log Interface
```html
<div class="chat-panel">
    <div class="chat-header">
        <h3>Communication Log</h3>
        <div class="chat-controls">
            <button class="chat-btn" id="clear-log">Clear</button>
            <button class="chat-btn" id="export-log">Export</button>
        </div>
    </div>
    
    <div class="chat-messages" id="chat-messages">
        <!-- Messages will be populated dynamically -->
    </div>
    
    <div class="chat-input">
        <input type="text" id="chat-input" placeholder="Type message...">
        <button id="send-message">Send</button>
    </div>
</div>
```

#### 4.2 Chat Controller JavaScript
```javascript
class ChatController {
    constructor() {
        this.messages = [];
        this.setupEventListeners();
    }
    
    setupEventListeners() {
        const chatInput = document.getElementById('chat-input');
        const sendButton = document.getElementById('send-message');
        const clearButton = document.getElementById('clear-log');
        const exportButton = document.getElementById('export-log');
        
        sendButton.addEventListener('click', () => this.sendMessage());
        chatInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') this.sendMessage();
        });
        
        clearButton.addEventListener('click', () => this.clearLog());
        exportButton.addEventListener('click', () => this.exportLog());
    }
    
    addMessage(type, content, timestamp = null) {
        const message = {
            type: type,
            content: content,
            timestamp: timestamp || new Date()
        };
        
        this.messages.push(message);
        this.displayMessage(message);
    }
    
    displayMessage(message) {
        const chatMessages = document.getElementById('chat-messages');
        const messageElement = document.createElement('div');
        messageElement.className = `message ${message.type}`;
        
        const timeString = message.timestamp.toLocaleTimeString();
        messageElement.innerHTML = `
            <div class="message-time">${timeString}</div>
            <div class="message-content">${message.content}</div>
        `;
        
        chatMessages.appendChild(messageElement);
        chatMessages.scrollTop = chatMessages.scrollHeight;
    }
    
    sendMessage() {
        const chatInput = document.getElementById('chat-input');
        const content = chatInput.value.trim();
        
        if (content) {
            this.addMessage('outgoing', content);
            this.websocket.send(JSON.stringify({
                type: 'chat_message',
                content: content
            }));
            chatInput.value = '';
        }
    }
}
```

## Mobile Optimization

### 1. Touch Controls
```css
/* Mobile touch controls */
@media (max-width: 768px) {
    .ptt-button {
        width: 80px;
        height: 80px;
        border-radius: 50%;
        font-size: 16px;
        touch-action: manipulation;
    }
    
    .radio-controls {
        display: flex;
        flex-direction: column;
        gap: 15px;
    }
    
    .slider-control {
        display: flex;
        align-items: center;
        gap: 10px;
    }
    
    .slider-control input[type="range"] {
        flex: 1;
        height: 40px;
    }
}
```

### 2. Progressive Web App (PWA)
```javascript
// Service Worker for offline functionality
class FGComServiceWorker {
    constructor() {
        this.cacheName = 'fgcom-cache-v1';
        this.offlinePages = [
            '/',
            '/webrtc',
            '/offline'
        ];
    }
    
    install() {
        // Cache essential files for offline use
        caches.open(this.cacheName).then(cache => {
            return cache.addAll(this.offlinePages);
        });
    }
    
    fetch(event) {
        // Handle offline requests
        event.respondWith(
            caches.match(event.request).then(response => {
                return response || fetch(event.request);
            })
        );
    }
}
```

## Accessibility Features

### 1. Keyboard Navigation
```javascript
class AccessibilityController {
    constructor() {
        this.setupKeyboardNavigation();
        this.setupScreenReaderSupport();
    }
    
    setupKeyboardNavigation() {
        // Tab navigation for radio controls
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Tab') {
                this.handleTabNavigation(e);
            }
        });
        
        // Space bar for PTT
        document.addEventListener('keydown', (e) => {
            if (e.key === ' ' && e.target.classList.contains('ptt-button')) {
                e.preventDefault();
                this.handlePTTKeypress(e);
            }
        });
    }
    
    setupScreenReaderSupport() {
        // Add ARIA labels for screen readers
        document.querySelectorAll('.radio-control').forEach(control => {
            const label = control.querySelector('label');
            if (label) {
                control.setAttribute('aria-label', label.textContent);
            }
        });
    }
}
```

### 2. Visual Accessibility
```css
/* High contrast mode support */
@media (prefers-contrast: high) {
    .status-indicator {
        border: 2px solid;
    }
    
    .quality-fill {
        border: 1px solid;
    }
}

/* Reduced motion support */
@media (prefers-reduced-motion: reduce) {
    .status-indicator {
        transition: none;
    }
    
    .quality-fill {
        transition: none;
    }
}
```

## Performance Optimization

### 1. Lazy Loading
```javascript
class LazyLoader {
    constructor() {
        this.observers = new Map();
        this.setupIntersectionObserver();
    }
    
    setupIntersectionObserver() {
        const options = {
            root: null,
            rootMargin: '50px',
            threshold: 0.1
        };
        
        this.observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    this.loadComponent(entry.target);
                }
            });
        }, options);
    }
    
    observe(element) {
        this.observer.observe(element);
    }
    
    loadComponent(element) {
        const componentName = element.dataset.component;
        if (componentName) {
            import(`./components/${componentName}.js`).then(module => {
                module.default.initialize(element);
            });
        }
    }
}
```

### 2. Audio Processing Optimization
```javascript
class AudioOptimizer {
    constructor() {
        this.audioContext = new AudioContext();
        this.audioBuffer = null;
        this.setupAudioProcessing();
    }
    
    setupAudioProcessing() {
        // Use Web Audio API for efficient audio processing
        this.audioContext.createScriptProcessor(4096, 1, 1).onaudioprocess = (e) => {
            const inputBuffer = e.inputBuffer;
            const outputBuffer = e.outputBuffer;
            
            // Process audio with minimal latency
            this.processAudio(inputBuffer, outputBuffer);
        };
    }
    
    processAudio(input, output) {
        // Optimized audio processing
        const inputData = input.getChannelData(0);
        const outputData = output.getChannelData(0);
        
        // Apply audio processing (noise reduction, etc.)
        for (let i = 0; i < inputData.length; i++) {
            outputData[i] = this.applyAudioProcessing(inputData[i]);
        }
    }
}
```

## Conclusion

The WebRTC web interface design provides a comprehensive, user-friendly experience for accessing FGCom-mumble through web browsers. The design ensures:

1. **Intuitive Interface**: Easy-to-use radio controls and visual feedback
2. **Real-time Updates**: Live status information and communication logs
3. **Mobile Support**: Responsive design and touch controls
4. **Accessibility**: Full keyboard navigation and screen reader support
5. **Performance**: Optimized audio processing and lazy loading
6. **Offline Support**: Progressive Web App capabilities

This interface design enables users to access FGCom-mumble from any device with a web browser while maintaining the full functionality and user experience of native applications.
