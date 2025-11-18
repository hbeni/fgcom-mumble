/**
 * Mumble Connector - Handles communication with Mumble server and UDP plugin
 */

const dgram = require('dgram');
const EventEmitter = require('events');

class MumbleConnector extends EventEmitter {
    constructor(config) {
        super();
        this.config = config;
        this.udpClient = null;
        this.connected = false;
        this.reconnectAttempts = 0;
        this.maxReconnectAttempts = 5;
        this.reconnectDelay = 1000; // 1 second
        
        this.initializeUDPClient();
    }
    
    initializeUDPClient() {
        try {
            this.udpClient = dgram.createSocket('udp4');
            
            this.udpClient.on('error', (error) => {
                console.error('UDP client error:', error);
                this.handleConnectionError();
            });
            
            this.udpClient.on('message', (message, rinfo) => {
                this.handleUDPMessage(message, rinfo);
            });
            
            this.udpClient.on('listening', () => {
                const address = this.udpClient.address();
                console.log(`UDP client listening on ${address.address}:${address.port}`);
                this.connected = true;
                this.reconnectAttempts = 0;
            });
            
            // Bind to a random port for receiving responses
            this.udpClient.bind(0, () => {
                console.log('UDP client bound to random port');
            });
            
        } catch (error) {
            console.error('Error initializing UDP client:', error);
            this.handleConnectionError();
        }
    }
    
    sendRadioData(udpData) {
        try {
            if (!this.connected) {
                console.warn('UDP client not connected, attempting to reconnect...');
                this.attemptReconnect();
                return;
            }
            
            const message = Buffer.from(udpData, 'utf8');
            const targetPort = this.config.udpPort || 16661;
            const targetHost = this.config.host || 'localhost';
            
            this.udpClient.send(message, targetPort, targetHost, (error) => {
                if (error) {
                    console.error('Error sending UDP data:', error);
                    this.handleConnectionError();
                } else {
                    console.log(`Radio data sent to ${targetHost}:${targetPort}`);
                }
            });
            
        } catch (error) {
            console.error('Error sending radio data:', error);
        }
    }
    
    handleUDPMessage(message, rinfo) {
        try {
            const messageString = message.toString('utf8');
            console.log(`Received UDP message from ${rinfo.address}:${rinfo.port}: ${messageString}`);
            
            // Parse the message and emit appropriate events
            this.parseUDPMessage(messageString);
            
        } catch (error) {
            console.error('Error handling UDP message:', error);
        }
    }
    
    parseUDPMessage(messageString) {
        try {
            // Parse field=value format
            const fields = messageString.split(' ');
            const data = {};
            
            for (const field of fields) {
                const [key, value] = field.split('=');
                if (key && value !== undefined) {
                    data[key] = this.parseValue(value);
                }
            }
            
            // Emit events based on message type
            if (data.type === 'audio') {
                this.emit('audio', data);
            } else if (data.type === 'radio') {
                this.emit('radio-data', data);
            } else if (data.type === 'status') {
                this.emit('status', data);
            } else {
                // Default to radio data
                this.emit('radio-data', data);
            }
            
        } catch (error) {
            console.error('Error parsing UDP message:', error);
        }
    }
    
    parseValue(value) {
        // Try to parse as number
        if (!isNaN(value)) {
            return parseFloat(value);
        }
        
        // Try to parse as boolean
        if (value === 'true' || value === '1') {
            return true;
        }
        if (value === 'false' || value === '0') {
            return false;
        }
        
        // Return as string
        return value;
    }
    
    handleConnectionError() {
        this.connected = false;
        this.reconnectAttempts++;
        
        if (this.reconnectAttempts <= this.maxReconnectAttempts) {
            console.log(`Connection error, attempting reconnect ${this.reconnectAttempts}/${this.maxReconnectAttempts}...`);
            setTimeout(() => {
                this.attemptReconnect();
            }, this.reconnectDelay * this.reconnectAttempts);
        } else {
            console.error('Max reconnection attempts reached');
            this.emit('error', new Error('Connection failed after maximum retry attempts'));
        }
    }
    
    attemptReconnect() {
        try {
            console.log('Attempting to reconnect UDP client...');
            
            if (this.udpClient) {
                this.udpClient.close();
            }
            
            this.initializeUDPClient();
            
        } catch (error) {
            console.error('Reconnection attempt failed:', error);
            this.handleConnectionError();
        }
    }
    
    isConnected() {
        return this.connected;
    }
    
    getConnectionInfo() {
        return {
            connected: this.connected,
            reconnectAttempts: this.reconnectAttempts,
            maxReconnectAttempts: this.maxReconnectAttempts,
            targetHost: this.config.host || 'localhost',
            targetPort: this.config.udpPort || 16661
        };
    }
    
    // Send heartbeat to keep connection alive
    sendHeartbeat() {
        try {
            const heartbeatData = 'type=heartbeat timestamp=' + Date.now();
            this.sendRadioData(heartbeatData);
        } catch (error) {
            console.error('Error sending heartbeat:', error);
        }
    }
    
    // Start heartbeat interval
    startHeartbeat(interval = 30000) { // 30 seconds
        this.heartbeatInterval = setInterval(() => {
            this.sendHeartbeat();
        }, interval);
        
        console.log(`Heartbeat started with ${interval}ms interval`);
    }
    
    // Stop heartbeat
    stopHeartbeat() {
        if (this.heartbeatInterval) {
            clearInterval(this.heartbeatInterval);
            this.heartbeatInterval = null;
            console.log('Heartbeat stopped');
        }
    }
    
    // Disconnect and cleanup
    disconnect() {
        try {
            console.log('Disconnecting Mumble connector...');
            
            this.stopHeartbeat();
            
            if (this.udpClient) {
                this.udpClient.close();
                this.udpClient = null;
            }
            
            this.connected = false;
            this.reconnectAttempts = 0;
            
            console.log('Mumble connector disconnected');
            
        } catch (error) {
            console.error('Error disconnecting Mumble connector:', error);
        }
    }
    
    // Get statistics
    getStats() {
        return {
            connected: this.connected,
            reconnectAttempts: this.reconnectAttempts,
            maxReconnectAttempts: this.maxReconnectAttempts,
            targetHost: this.config.host || 'localhost',
            targetPort: this.config.udpPort || 16661,
            heartbeatActive: !!this.heartbeatInterval
        };
    }
}

module.exports = MumbleConnector;
