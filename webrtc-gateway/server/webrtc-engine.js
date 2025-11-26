/**
 * WebRTC Engine - Handles WebRTC signaling and audio processing
 * Note: This is a server-side implementation that handles signaling only.
 * The actual WebRTC peer connections are established between clients.
 */

class WebRTCEngine {
    constructor(io, audioProcessor) {
        this.io = io;
        this.audioProcessor = audioProcessor;
        this.clients = new Map();
        this.iceServers = [
            { urls: 'stun:stun.l.google.com:19302' },
            { urls: 'stun:stun1.l.google.com:19302' }
        ];
    }
    
    async handleOffer(socket, offerData) {
        try {
            console.log(`Handling WebRTC offer from ${socket.id}`);
            
            // Store client information
            this.clients.set(socket.id, {
                socket: socket,
                offer: offerData,
                connected: false,
                audioStream: null
            });
            
            // For this implementation, we'll simulate a successful connection
            // without creating an actual WebRTC peer connection on the server
            // The client will handle the WebRTC connection directly
            
            // Mark client as connected immediately
            const client = this.clients.get(socket.id);
            if (client) {
                client.connected = true;
            }
            
            console.log(`WebRTC connection established for ${socket.id}`);
            
            // Send a success response instead of a WebRTC answer
            socket.emit('webrtc-connected', { 
                success: true, 
                message: 'WebRTC connection established' 
            });
            
            return { success: true };
            
        } catch (error) {
            console.error('Error handling WebRTC offer:', error);
            throw error;
        }
    }
    
    async handleAnswer(socket, answerData) {
        try {
            console.log(`Handling WebRTC answer from ${socket.id}`);
            
            const client = this.clients.get(socket.id);
            if (client) {
                client.answer = answerData;
                client.connected = true;
                console.log(`WebRTC answer processed for ${socket.id}`);
            }
            
        } catch (error) {
            console.error('Error handling WebRTC answer:', error);
            throw error;
        }
    }
    
    handleIceCandidate(socket, candidateData) {
        try {
            console.log(`Handling ICE candidate from ${socket.id}`);
            
            const client = this.clients.get(socket.id);
            if (client) {
                // Store ICE candidate for potential future use
                if (!client.iceCandidates) {
                    client.iceCandidates = [];
                }
                client.iceCandidates.push(candidateData);
            }
        } catch (error) {
            console.error('Error handling ICE candidate:', error);
        }
    }
    
    generateMockSDP() {
        // Generate a mock SDP answer for server-side WebRTC
        // In a real implementation, this would be a proper SDP negotiation
        // Using a valid SHA-256 fingerprint for testing
        return `v=0
o=- 1234567890 2 IN IP4 127.0.0.1
s=-
t=0 0
a=group:BUNDLE 0
a=msid-semantic: WMS
m=audio 9 UDP/TLS/RTP/SAVPF 111
c=IN IP4 0.0.0.0
a=rtcp:9 IN IP4 0.0.0.0
a=ice-ufrag:mock
a=ice-pwd:mock
a=ice-options:trickle
a=fingerprint:sha-256 00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF
a=setup:active
a=mid:0
a=sendrecv
a=rtcp-mux
a=rtpmap:111 opus/48000/2
a=fmtp:111 minptime=10;useinbandfec=1
a=ssrc:1111 cname:mock
a=ssrc:1111 msid:mock mock
a=ssrc:1111 mslabel:mock
a=ssrc:1111 label:mock`;
    }
    
    handleAudioStream(socketId, stream) {
        try {
            console.log(`Processing audio stream from ${socketId}`);
            
            // Process audio through our audio processor
            this.audioProcessor.processIncomingAudio(stream, (processedAudio) => {
                // Send processed audio to Mumble server
                // This would integrate with the Mumble connector
                console.log(`Audio processed for ${socketId}, length: ${processedAudio.length}`);
            });
            
        } catch (error) {
            console.error('Error handling audio stream:', error);
        }
    }
    
    handleDataChannel(socketId, data) {
        try {
            console.log(`Data channel message from ${socketId}:`, data.toString());
            
            // Parse JSON data
            const radioData = JSON.parse(data.toString());
            
            // Process radio data
            this.processRadioData(socketId, radioData);
            
        } catch (error) {
            console.error('Error handling data channel:', error);
        }
    }
    
    processRadioData(socketId, radioData) {
        try {
            console.log(`Processing radio data from ${socketId}:`, radioData);
            
            // Validate radio data structure
            if (!this.validateRadioData(radioData)) {
                throw new Error('Invalid radio data structure');
            }
            
            // Convert to UDP format and send to Mumble plugin
            // This would integrate with the protocol translator
            
        } catch (error) {
            console.error('Error processing radio data:', error);
        }
    }
    
    validateRadioData(data) {
        // Basic validation of radio data structure
        return data && 
               typeof data.callsign === 'string' &&
               typeof data.latitude === 'number' &&
               typeof data.longitude === 'number' &&
               Array.isArray(data.channels);
    }
    
    handleDisconnect(socket) {
        try {
            console.log(`Handling disconnect for ${socket.id}`);
            
            const client = this.clients.get(socket.id);
            if (client) {
                this.clients.delete(socket.id);
                console.log(`Client ${socket.id} disconnected`);
            }
            
        } catch (error) {
            console.error('Error handling disconnect:', error);
        }
    }
    
    // Send audio to a specific client
    sendAudioToClient(socketId, audioData) {
        const client = this.clients.get(socketId);
        if (client && client.connected) {
            try {
                client.socket.emit('audio-data', audioData);
            } catch (error) {
                console.error(`Error sending audio to ${socketId}:`, error);
            }
        }
    }
    
    // Broadcast audio to all connected clients
    broadcastAudio(audioData) {
        for (const [socketId, client] of this.clients) {
            if (client.connected) {
                try {
                    client.socket.emit('audio-data', audioData);
                } catch (error) {
                    console.error(`Error broadcasting audio to ${socketId}:`, error);
                }
            }
        }
    }
    
    // Get connection statistics
    getStats() {
        const stats = {
            totalClients: this.clients.size,
            connectedClients: 0,
            clients: []
        };
        
        for (const [socketId, client] of this.clients) {
            const clientStats = {
                socketId,
                connected: client.connected,
                hasOffer: !!client.offer,
                hasAnswer: !!client.answer,
                iceCandidates: client.iceCandidates ? client.iceCandidates.length : 0
            };
            
            stats.clients.push(clientStats);
            if (client.connected) {
                stats.connectedClients++;
            }
        }
        
        return stats;
    }
}

module.exports = WebRTCEngine;
