/**
 * WebRTC Client - Handles WebRTC connections and audio processing
 */

class WebRTCClient {
    constructor() {
        this.socket = null;
        this.peerConnection = null;
        this.localStream = null;
        this.remoteStream = null;
        this.dataChannel = null;
        this.isConnected = false;
        this.isPTTActive = false;
        this.audioContext = null;
        this.audioLevel = 0;
        
        this.iceServers = [
            { urls: 'stun:stun.l.google.com:19302' },
            { urls: 'stun:stun1.l.google.com:19302' }
        ];
        
        this.setupEventListeners();
    }
    
    setupEventListeners() {
        // PTT button events
        document.addEventListener('keydown', (e) => {
            if (e.code === 'Space' && !e.repeat) {
                e.preventDefault();
                this.startPTT();
            }
        });
        
        document.addEventListener('keyup', (e) => {
            if (e.code === 'Space') {
                e.preventDefault();
                this.stopPTT();
            }
        });
        
        // Audio level monitoring
        this.setupAudioLevelMonitoring();
    }
    
    async connect(serverUrl, username) {
        try {
            console.log(`Connecting to ${serverUrl} as ${username}`);
            this.updateConnectionStatus('connecting', 'Connecting...');
            
            // Initialize Socket.IO connection
            this.socket = io(serverUrl);
            
            this.socket.on('connect', () => {
                console.log('Socket connected');
                this.setupSocketListeners();
                this.initializeWebRTC();
            });
            
            this.socket.on('disconnect', () => {
                console.log('Socket disconnected');
                this.handleDisconnection();
            });
            
            this.socket.on('webrtc-answer', (answer) => {
                this.handleWebRTCAnswer(answer);
            });
            
            this.socket.on('webrtc-ice-candidate', (candidate) => {
                this.handleIceCandidate(candidate);
            });
            
            this.socket.on('audio-data', (audioData) => {
                this.handleIncomingAudio(audioData);
            });
            
            this.socket.on('radio-data', (radioData) => {
                this.handleIncomingRadioData(radioData);
            });
            
            this.socket.on('error', (error) => {
                console.error('Socket error:', error);
                this.updateConnectionStatus('error', 'Connection error');
            });
            
        } catch (error) {
            console.error('Connection error:', error);
            this.updateConnectionStatus('error', 'Connection failed');
        }
    }
    
    setupSocketListeners() {
        // Additional socket event listeners can be added here
    }
    
    async initializeWebRTC() {
        try {
            console.log('Initializing WebRTC...');
            
            // Get user media
            await this.getUserMedia();
            
            // Create peer connection
            this.peerConnection = new RTCPeerConnection({
                iceServers: this.iceServers
            });
            
            // Add local stream to peer connection
            if (this.localStream) {
                this.localStream.getTracks().forEach(track => {
                    this.peerConnection.addTrack(track, this.localStream);
                });
            }
            
            // Handle remote stream
            this.peerConnection.ontrack = (event) => {
                console.log('Remote stream received');
                this.remoteStream = event.streams[0];
                this.playRemoteAudio(this.remoteStream);
            };
            
            // Handle ICE candidates
            this.peerConnection.onicecandidate = (event) => {
                if (event.candidate) {
                    this.socket.emit('ice-candidate', event.candidate);
                }
            };
            
            // Handle connection state changes
            this.peerConnection.onconnectionstatechange = () => {
                console.log('Connection state:', this.peerConnection.connectionState);
                this.updateConnectionStatus(
                    this.peerConnection.connectionState,
                    this.peerConnection.connectionState
                );
            };
            
            // Create data channel
            this.dataChannel = this.peerConnection.createDataChannel('radio-data', {
                ordered: true
            });
            
            this.dataChannel.onopen = () => {
                console.log('Data channel opened');
            };
            
            this.dataChannel.onmessage = (event) => {
                this.handleDataChannelMessage(event.data);
            };
            
            // Create and send offer
            await this.createOffer();
            
        } catch (error) {
            console.error('WebRTC initialization error:', error);
            this.updateConnectionStatus('error', 'WebRTC initialization failed');
        }
    }
    
    async getUserMedia() {
        try {
            console.log('Requesting user media...');
            
            this.localStream = await navigator.mediaDevices.getUserMedia({
                audio: {
                    echoCancellation: true,
                    noiseSuppression: true,
                    autoGainControl: true,
                    sampleRate: 48000
                },
                video: false
            });
            
            console.log('User media obtained');
            this.setupAudioContext();
            
        } catch (error) {
            console.error('Error getting user media:', error);
            throw error;
        }
    }
    
    setupAudioContext() {
        try {
            this.audioContext = new (window.AudioContext || window.webkitAudioContext)();
            const source = this.audioContext.createMediaStreamSource(this.localStream);
            
            // Create analyser for audio level monitoring
            const analyser = this.audioContext.createAnalyser();
            analyser.fftSize = 256;
            source.connect(analyser);
            
            this.audioLevelAnalyser = analyser;
            
        } catch (error) {
            console.error('Error setting up audio context:', error);
        }
    }
    
    setupAudioLevelMonitoring() {
        const updateAudioLevel = () => {
            if (this.audioLevelAnalyser) {
                const dataArray = new Uint8Array(this.audioLevelAnalyser.frequencyBinCount);
                this.audioLevelAnalyser.getByteFrequencyData(dataArray);
                
                const average = dataArray.reduce((a, b) => a + b) / dataArray.length;
                this.audioLevel = (average / 255) * 100;
                
                this.updateAudioLevelDisplay();
            }
            
            requestAnimationFrame(updateAudioLevel);
        };
        
        updateAudioLevel();
    }
    
    updateAudioLevelDisplay() {
        const inputLevelBar = document.getElementById('inputLevelBar');
        const outputLevelBar = document.getElementById('outputLevelBar');
        
        if (inputLevelBar) {
            inputLevelBar.style.width = `${this.audioLevel}%`;
        }
        
        if (outputLevelBar) {
            outputLevelBar.style.width = `${this.audioLevel}%`;
        }
    }
    
    async createOffer() {
        try {
            console.log('Creating WebRTC offer...');
            
            const offer = await this.peerConnection.createOffer({
                offerToReceiveAudio: true,
                offerToReceiveVideo: false
            });
            
            await this.peerConnection.setLocalDescription(offer);
            
            this.socket.emit('webrtc-offer', offer);
            
        } catch (error) {
            console.error('Error creating offer:', error);
        }
    }
    
    async handleWebRTCAnswer(answer) {
        try {
            console.log('Handling WebRTC answer...');
            await this.peerConnection.setRemoteDescription(answer);
        } catch (error) {
            console.error('Error handling answer:', error);
        }
    }
    
    handleIceCandidate(candidate) {
        try {
            this.peerConnection.addIceCandidate(candidate);
        } catch (error) {
            console.error('Error adding ICE candidate:', error);
        }
    }
    
    playRemoteAudio(stream) {
        try {
            const audio = new Audio();
            audio.srcObject = stream;
            audio.autoplay = true;
            audio.volume = 0.8;
            
            audio.onloadedmetadata = () => {
                console.log('Remote audio loaded');
            };
            
        } catch (error) {
            console.error('Error playing remote audio:', error);
        }
    }
    
    handleIncomingAudio(audioData) {
        // Handle incoming audio data from server
        console.log('Received audio data:', audioData);
    }
    
    handleIncomingRadioData(radioData) {
        // Handle incoming radio data from server
        console.log('Received radio data:', radioData);
        this.updateRadioStatus(radioData);
    }
    
    handleDataChannelMessage(data) {
        try {
            const message = JSON.parse(data);
            console.log('Data channel message:', message);
        } catch (error) {
            console.error('Error parsing data channel message:', error);
        }
    }
    
    startPTT() {
        if (!this.isConnected || this.isPTTActive) return;
        
        try {
            console.log('PTT activated');
            this.isPTTActive = true;
            this.updatePTTStatus('Transmitting');
            
            // Enable microphone
            if (this.localStream) {
                this.localStream.getAudioTracks().forEach(track => {
                    track.enabled = true;
                });
            }
            
            // Send PTT status to server
            this.sendRadioData({ ptt: true });
            
        } catch (error) {
            console.error('Error starting PTT:', error);
        }
    }
    
    stopPTT() {
        if (!this.isPTTActive) return;
        
        try {
            console.log('PTT released');
            this.isPTTActive = false;
            this.updatePTTStatus('Released');
            
            // Disable microphone
            if (this.localStream) {
                this.localStream.getAudioTracks().forEach(track => {
                    track.enabled = false;
                });
            }
            
            // Send PTT status to server
            this.sendRadioData({ ptt: false });
            
        } catch (error) {
            console.error('Error stopping PTT:', error);
        }
    }
    
    sendRadioData(data) {
        if (!this.isConnected) return;
        
        try {
            const radioData = {
                callsign: document.getElementById('callsign')?.value || 'WEBRTC',
                latitude: parseFloat(document.getElementById('latitude')?.value) || 0,
                longitude: parseFloat(document.getElementById('longitude')?.value) || 0,
                altitude: parseFloat(document.getElementById('altitude')?.value) || 0,
                channels: [
                    {
                        frequency: parseFloat(document.getElementById('freq1')?.value) || 0,
                        power: parseInt(document.getElementById('power1')?.value) || 0,
                        volume: parseInt(document.getElementById('volume1')?.value) || 0,
                        squelch: parseInt(document.getElementById('squelch1')?.value) || 0,
                        ptt: this.isPTTActive,
                        operational: true
                    }
                ],
                timestamp: Date.now()
            };
            
            // Merge with provided data
            Object.assign(radioData, data);
            
            console.log('Sending radio data:', radioData);
            
            // Send via data channel
            if (this.dataChannel && this.dataChannel.readyState === 'open') {
                this.dataChannel.send(JSON.stringify(radioData));
            }
            
            // Send via socket
            this.socket.emit('radio-data', radioData);
            
        } catch (error) {
            console.error('Error sending radio data:', error);
        }
    }
    
    updateConnectionStatus(status, message) {
        const statusElement = document.getElementById('connectionStatus');
        const statusText = document.querySelector('.status-text');
        const statusIndicator = document.querySelector('.status-indicator');
        
        if (statusElement) {
            statusElement.className = `connection-status ${status}`;
        }
        
        if (statusText) {
            statusText.textContent = message;
        }
        
        if (statusIndicator) {
            statusIndicator.className = `status-indicator ${status}`;
        }
        
        this.isConnected = (status === 'connected');
        
        if (this.isConnected) {
            console.log('WebRTC connection established');
        }
    }
    
    updatePTTStatus(status) {
        const pttStatusElement = document.getElementById('pttStatusValue');
        if (pttStatusElement) {
            pttStatusElement.textContent = status;
        }
        
        // Update PTT button visual state
        const pttButtons = document.querySelectorAll('.btn-ptt');
        pttButtons.forEach(button => {
            if (this.isPTTActive) {
                button.classList.add('active');
            } else {
                button.classList.remove('active');
            }
        });
    }
    
    updateRadioStatus(radioData) {
        const frequencyElement = document.getElementById('frequencyStatusValue');
        if (frequencyElement && radioData.frequency) {
            frequencyElement.textContent = `${radioData.frequency} MHz`;
        }
    }
    
    handleDisconnection() {
        console.log('Handling disconnection...');
        this.isConnected = false;
        this.updateConnectionStatus('disconnected', 'Disconnected');
        
        if (this.peerConnection) {
            this.peerConnection.close();
            this.peerConnection = null;
        }
        
        if (this.localStream) {
            this.localStream.getTracks().forEach(track => {
                track.stop();
            });
            this.localStream = null;
        }
    }
    
    disconnect() {
        console.log('Disconnecting WebRTC client...');
        
        if (this.socket) {
            this.socket.disconnect();
            this.socket = null;
        }
        
        this.handleDisconnection();
    }
    
    // Public API methods
    getConnectionState() {
        return {
            connected: this.isConnected,
            pttActive: this.isPTTActive,
            audioLevel: this.audioLevel
        };
    }
    
    setAudioLevel(level) {
        if (this.localStream) {
            this.localStream.getAudioTracks().forEach(track => {
                const audioTrack = track;
                if (audioTrack.getSettings) {
                    // Adjust audio level if supported
                    console.log('Setting audio level to:', level);
                }
            });
        }
    }
}

// Export for use in other modules
window.WebRTCClient = WebRTCClient;
