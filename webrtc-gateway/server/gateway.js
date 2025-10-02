#!/usr/bin/env node

/**
 * FGCom-mumble WebRTC Gateway Server
 * 
 * This is the main WebRTC gateway server that enables web browser clients
 * to connect to FGCom-mumble servers while preserving all existing connection methods.
 * 
 * Architecture:
 * - WebRTC clients connect via web browser
 * - Gateway translates WebRTC audio/data to Mumble UDP protocol
 * - Gateway sends data to existing Mumble plugin (port 16661)
 * - Gateway receives audio from Mumble server and streams to WebRTC clients
 */

const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const path = require('path');
const dgram = require('dgram');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const morgan = require('morgan');

// Import our modules
const WebRTCEngine = require('./webrtc-engine');
const AudioProcessor = require('./audio-processor');
const ProtocolTranslator = require('./protocol-translator');
const AuthenticationService = require('./authentication-service');
const MumbleConnector = require('./mumble-connector');

class WebRTCGateway {
    constructor() {
        this.app = express();
        this.server = http.createServer(this.app);
        this.io = socketIo(this.server, {
            cors: {
                origin: "*",
                methods: ["GET", "POST"]
            }
        });
        
        // Configuration
        this.config = this.loadConfig();
        this.clients = new Map();
        this.audioProcessor = new AudioProcessor(this.config.audio);
        this.protocolTranslator = new ProtocolTranslator();
        this.authService = new AuthenticationService(this.config.auth);
        this.mumbleConnector = new MumbleConnector(this.config.mumble);
        
        // WebRTC Engine
        this.webrtcEngine = new WebRTCEngine(this.io, this.audioProcessor);
        
        this.setupMiddleware();
        this.setupRoutes();
        this.setupWebRTC();
        this.setupMumbleConnection();
    }
    
    loadConfig() {
        const defaultConfig = {
            port: process.env.PORT || 3000,
            mumble: {
                host: process.env.MUMBLE_HOST || 'localhost',
                port: process.env.MUMBLE_PORT || 64738,
                udpPort: 16661
            },
            audio: {
                sampleRate: 48000,
                channels: 1,
                bitrate: 64000,
                codec: 'opus'
            },
            auth: {
                secret: process.env.JWT_SECRET || 'fgcom-webrtc-secret-key',
                sessionSecret: process.env.SESSION_SECRET || 'fgcom-session-secret',
                tokenExpiry: '24h'
            },
            webrtc: {
                iceServers: [
                    { urls: 'stun:stun.l.google.com:19302' },
                    { urls: 'stun:stun1.l.google.com:19302' }
                ]
            }
        };
        
        // Try to load from config file
        try {
            const configFile = path.join(__dirname, '../config/gateway.json');
            if (fs.existsSync(configFile)) {
                const fileConfig = JSON.parse(fs.readFileSync(configFile, 'utf8'));
                return { ...defaultConfig, ...fileConfig };
            }
        } catch (error) {
            console.warn('Could not load config file, using defaults:', error.message);
        }
        
        return defaultConfig;
    }
    
    setupMiddleware() {
        // Security middleware
        this.app.use(helmet({
            contentSecurityPolicy: {
                directives: {
                    defaultSrc: ["'self'"],
                    scriptSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
                    styleSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
                    connectSrc: ["'self'", "ws:", "wss:"],
                    mediaSrc: ["'self'", "blob:"]
                }
            }
        }));
        
        this.app.use(cors({
            origin: process.env.CORS_ORIGIN || "*",
            credentials: true
        }));
        
        this.app.use(compression());
        this.app.use(morgan('combined'));
        
        // Session middleware
        this.app.use(session({
            secret: this.config.auth.sessionSecret,
            resave: false,
            saveUninitialized: false,
            cookie: { 
                secure: process.env.NODE_ENV === 'production',
                maxAge: 24 * 60 * 60 * 1000 // 24 hours
            }
        }));
        
        this.app.use(express.json({ limit: '10mb' }));
        this.app.use(express.urlencoded({ extended: true, limit: '10mb' }));
        
        // Static files
        this.app.use(express.static(path.join(__dirname, '../public')));
    }
    
    setupRoutes() {
        // Health check
        this.app.get('/health', (req, res) => {
            res.json({ 
                status: 'healthy', 
                timestamp: new Date().toISOString(),
                clients: this.clients.size,
                uptime: process.uptime()
            });
        });
        
        // Authentication routes
        this.app.post('/api/auth/login', async (req, res) => {
            try {
                const { username, password } = req.body;
                const result = await this.authService.authenticate(username, password);
                
                if (result.success) {
                    req.session.userId = result.user.id;
                    res.json({ 
                        success: true, 
                        token: result.token,
                        user: result.user 
                    });
                } else {
                    res.status(401).json({ success: false, message: result.message });
                }
            } catch (error) {
                console.error('Login error:', error);
                res.status(500).json({ success: false, message: 'Internal server error' });
            }
        });
        
        this.app.post('/api/auth/register', async (req, res) => {
            try {
                const { username, password, email } = req.body;
                const result = await this.authService.register(username, password, email);
                
                if (result.success) {
                    res.json({ success: true, message: 'Registration successful' });
                } else {
                    res.status(400).json({ success: false, message: result.message });
                }
            } catch (error) {
                console.error('Registration error:', error);
                res.status(500).json({ success: false, message: 'Internal server error' });
            }
        });
        
        this.app.post('/api/auth/logout', (req, res) => {
            req.session.destroy();
            res.json({ success: true, message: 'Logged out successfully' });
        });
        
        // Radio data API
        this.app.post('/api/radio/data', (req, res) => {
            try {
                const radioData = req.body;
                const udpData = this.protocolTranslator.jsonToUDP(radioData);
                
                // Send to Mumble plugin via UDP
                this.mumbleConnector.sendRadioData(udpData);
                
                res.json({ success: true, message: 'Radio data sent' });
            } catch (error) {
                console.error('Radio data error:', error);
                res.status(500).json({ success: false, message: 'Failed to send radio data' });
            }
        });
        
        // Status API
        this.app.get('/api/status', (req, res) => {
            res.json({
                server: 'FGCom-mumble WebRTC Gateway',
                version: '1.0.0',
                clients: this.clients.size,
                mumble: {
                    connected: this.mumbleConnector.isConnected(),
                    host: this.config.mumble.host,
                    port: this.config.mumble.port
                },
                uptime: process.uptime()
            });
        });
        
        // WebRTC client page
        this.app.get('/webrtc', (req, res) => {
            res.sendFile(path.join(__dirname, '../public/webrtc-client.html'));
        });
        
        // Main page
        this.app.get('/', (req, res) => {
            res.sendFile(path.join(__dirname, '../public/index.html'));
        });
    }
    
    setupWebRTC() {
        this.io.on('connection', (socket) => {
            console.log(`WebRTC client connected: ${socket.id}`);
            
            // Handle WebRTC signaling
            socket.on('webrtc-offer', async (data) => {
                try {
                    const result = await this.webrtcEngine.handleOffer(socket, data);
                    socket.emit('webrtc-answer', result);
                } catch (error) {
                    console.error('WebRTC offer error:', error);
                    socket.emit('webrtc-error', { message: 'Failed to handle offer' });
                }
            });
            
            socket.on('webrtc-answer', async (data) => {
                try {
                    await this.webrtcEngine.handleAnswer(socket, data);
                } catch (error) {
                    console.error('WebRTC answer error:', error);
                    socket.emit('webrtc-error', { message: 'Failed to handle answer' });
                }
            });
            
            socket.on('ice-candidate', (data) => {
                this.webrtcEngine.handleIceCandidate(socket, data);
            });
            
            socket.on('radio-data', (data) => {
                try {
                    const udpData = this.protocolTranslator.jsonToUDP(data);
                    this.mumbleConnector.sendRadioData(udpData);
                } catch (error) {
                    console.error('Radio data processing error:', error);
                    socket.emit('error', { message: 'Failed to process radio data' });
                }
            });
            
            socket.on('disconnect', () => {
                console.log(`WebRTC client disconnected: ${socket.id}`);
                this.webrtcEngine.handleDisconnect(socket);
                this.clients.delete(socket.id);
            });
        });
    }
    
    setupMumbleConnection() {
        this.mumbleConnector.on('audio', (audioData) => {
            // Broadcast audio to all connected WebRTC clients
            this.io.emit('audio-data', audioData);
        });
        
        this.mumbleConnector.on('radio-data', (radioData) => {
            // Broadcast radio data to all connected WebRTC clients
            this.io.emit('radio-data', radioData);
        });
        
        this.mumbleConnector.on('error', (error) => {
            console.error('Mumble connection error:', error);
        });
    }
    
    start() {
        this.server.listen(this.config.port, () => {
            console.log(`🚀 FGCom-mumble WebRTC Gateway running on port ${this.config.port}`);
            console.log(`📡 WebRTC client: http://localhost:${this.config.port}/webrtc`);
            console.log(`🌐 Main page: http://localhost:${this.config.port}/`);
            console.log(`📊 Status: http://localhost:${this.config.port}/health`);
        });
        
        // Graceful shutdown
        process.on('SIGTERM', () => this.shutdown());
        process.on('SIGINT', () => this.shutdown());
    }
    
    shutdown() {
        console.log('🛑 Shutting down WebRTC Gateway...');
        
        // Close all client connections
        this.io.close();
        
        // Close Mumble connection
        this.mumbleConnector.disconnect();
        
        // Close server
        this.server.close(() => {
            console.log('✅ WebRTC Gateway shutdown complete');
            process.exit(0);
        });
    }
}

// Start the gateway
if (require.main === module) {
    const gateway = new WebRTCGateway();
    gateway.start();
}

module.exports = WebRTCGateway;
