/**
 * WebRTC Engine - Handles WebRTC peer connections and signaling
 */

const SimplePeer = require('simple-peer');

class WebRTCEngine {
    constructor(io, audioProcessor) {
        this.io = io;
        this.audioProcessor = audioProcessor;
        this.peers = new Map();
        this.iceServers = [
            { urls: 'stun:stun.l.google.com:19302' },
            { urls: 'stun:stun1.l.google.com:19302' }
        ];
    }
    
    async handleOffer(socket, offerData) {
        try {
            console.log(`Handling WebRTC offer from ${socket.id}`);
            
            // Create peer connection
            const peer = new SimplePeer({
                initiator: false,
                trickle: false,
                config: {
                    iceServers: this.iceServers
                }
            });
            
            // Store peer reference
            this.peers.set(socket.id, peer);
            
            // Handle peer events
            peer.on('signal', (signal) => {
                socket.emit('webrtc-answer', signal);
            });
            
            peer.on('stream', (stream) => {
                console.log(`Audio stream received from ${socket.id}`);
                this.handleAudioStream(socket.id, stream);
            });
            
            peer.on('data', (data) => {
                console.log(`Data received from ${socket.id}:`, data.toString());
                this.handleDataChannel(socket.id, data);
            });
            
            peer.on('error', (error) => {
                console.error(`WebRTC peer error for ${socket.id}:`, error);
                socket.emit('webrtc-error', { message: 'Peer connection error' });
            });
            
            peer.on('close', () => {
                console.log(`WebRTC peer connection closed for ${socket.id}`);
                this.peers.delete(socket.id);
            });
            
            // Signal the offer
            peer.signal(offerData);
            
            return { success: true };
            
        } catch (error) {
            console.error('Error handling WebRTC offer:', error);
            throw error;
        }
    }
    
    async handleAnswer(socket, answerData) {
        try {
            console.log(`Handling WebRTC answer from ${socket.id}`);
            
            const peer = this.peers.get(socket.id);
            if (!peer) {
                throw new Error('No peer connection found');
            }
            
            peer.signal(answerData);
            
        } catch (error) {
            console.error('Error handling WebRTC answer:', error);
            throw error;
        }
    }
    
    handleIceCandidate(socket, candidateData) {
        try {
            console.log(`Handling ICE candidate from ${socket.id}`);
            
            const peer = this.peers.get(socket.id);
            if (peer) {
                peer.signal(candidateData);
            }
        } catch (error) {
            console.error('Error handling ICE candidate:', error);
        }
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
            
            const peer = this.peers.get(socket.id);
            if (peer) {
                peer.destroy();
                this.peers.delete(socket.id);
            }
            
        } catch (error) {
            console.error('Error handling disconnect:', error);
        }
    }
    
    // Send audio to a specific client
    sendAudioToClient(socketId, audioData) {
        const peer = this.peers.get(socketId);
        if (peer && peer.connected) {
            try {
                peer.send(audioData);
            } catch (error) {
                console.error(`Error sending audio to ${socketId}:`, error);
            }
        }
    }
    
    // Broadcast audio to all connected clients
    broadcastAudio(audioData) {
        for (const [socketId, peer] of this.peers) {
            if (peer.connected) {
                try {
                    peer.send(audioData);
                } catch (error) {
                    console.error(`Error broadcasting audio to ${socketId}:`, error);
                }
            }
        }
    }
    
    // Get connection statistics
    getStats() {
        const stats = {
            totalPeers: this.peers.size,
            connectedPeers: 0,
            peers: []
        };
        
        for (const [socketId, peer] of this.peers) {
            const peerStats = {
                socketId,
                connected: peer.connected,
                destroyed: peer.destroyed
            };
            
            stats.peers.push(peerStats);
            if (peer.connected) {
                stats.connectedPeers++;
            }
        }
        
        return stats;
    }
}

module.exports = WebRTCEngine;
