/**
 * Main Application - Handles UI interactions and WebRTC client management
 */

class FGComApp {
    constructor() {
        this.webrtcClient = null;
        this.isAuthenticated = false;
        this.currentUser = null;
        
        this.initializeApp();
    }
    
    initializeApp() {
        console.log('Initializing FGCom-mumble WebRTC Client...');
        
        this.setupEventListeners();
        this.setupAudioDevices();
        this.setupFormHandlers();
        this.setupKeyboardShortcuts();
        
        // Auto-detect server URL
        this.setupServerURL();
        
        // Check if we're on the WebRTC client page
        if (window.location.pathname.includes('webrtc')) {
            this.initializeWebRTCClient();
        }
    }
    
    setupEventListeners() {
        // Connection button
        const connectBtn = document.getElementById('connectBtn');
        if (connectBtn) {
            connectBtn.addEventListener('click', () => this.handleConnect());
        }
        
        // Login form
        const loginForm = document.getElementById('loginFormElement');
        if (loginForm) {
            loginForm.addEventListener('submit', (e) => this.handleLogin(e));
        }
        
        // Register form
        const registerForm = document.getElementById('registerFormElement');
        if (registerForm) {
            registerForm.addEventListener('submit', (e) => this.handleRegister(e));
        }
        
        // Form switching
        const registerLink = document.getElementById('registerLink');
        const loginLink = document.getElementById('loginLink');
        
        if (registerLink) {
            registerLink.addEventListener('click', (e) => {
                e.preventDefault();
                this.showRegisterForm();
            });
        }
        
        if (loginLink) {
            loginLink.addEventListener('click', (e) => {
                e.preventDefault();
                this.showLoginForm();
            });
        }
        
        // Position update
        const updatePositionBtn = document.getElementById('updatePosition');
        if (updatePositionBtn) {
            updatePositionBtn.addEventListener('click', () => this.updatePosition());
        }
        
        // PTT buttons
        const pttButtons = document.querySelectorAll('.btn-ptt');
        pttButtons.forEach((button, index) => {
            button.addEventListener('mousedown', () => this.startPTT(index + 1));
            button.addEventListener('mouseup', () => this.stopPTT(index + 1));
            button.addEventListener('mouseleave', () => this.stopPTT(index + 1));
        });
        
        // Test audio buttons
        const testAudioBtn = document.getElementById('testAudio1');
        if (testAudioBtn) {
            testAudioBtn.addEventListener('click', () => this.testAudio());
        }
        
        // Audio level slider
        const audioLevelSlider = document.getElementById('audioLevel');
        if (audioLevelSlider) {
            audioLevelSlider.addEventListener('input', (e) => this.setAudioLevel(e.target.value));
        }
        
        // Settings button
        const settingsBtn = document.getElementById('settingsBtn');
        if (settingsBtn) {
            settingsBtn.addEventListener('click', () => this.showSettings());
        }
    }
    
    setupAudioDevices() {
        this.loadAudioDevices();
    }
    
    async loadAudioDevices() {
        try {
            // Check if mediaDevices is available (requires HTTPS or localhost)
            if (!navigator.mediaDevices || !navigator.mediaDevices.enumerateDevices) {
                console.log('Audio device access not available (requires HTTPS or localhost)');
                this.populateAudioDeviceSelect('inputDevice', []);
                this.populateAudioDeviceSelect('outputDevice', []);
                return;
            }
            
            const devices = await navigator.mediaDevices.enumerateDevices();
            const audioInputs = devices.filter(device => device.kind === 'audioinput');
            const audioOutputs = devices.filter(device => device.kind === 'audiooutput');
            
            this.populateAudioDeviceSelect('inputDevice', audioInputs);
            this.populateAudioDeviceSelect('outputDevice', audioOutputs);
            
        } catch (error) {
            console.error('Error loading audio devices:', error);
            // Fallback: populate with default options
            this.populateAudioDeviceSelect('inputDevice', []);
            this.populateAudioDeviceSelect('outputDevice', []);
        }
    }
    
    populateAudioDeviceSelect(selectId, devices) {
        const select = document.getElementById(selectId);
        if (!select) return;
        
        // Clear existing options
        select.innerHTML = '<option value="">Select device...</option>';
        
        devices.forEach(device => {
            const option = document.createElement('option');
            option.value = device.deviceId;
            option.textContent = device.label || `Device ${device.deviceId}`;
            select.appendChild(option);
        });
    }
    
    setupFormHandlers() {
        // Auto-fill position from geolocation
        this.setupGeolocation();
        
        // Form validation
        this.setupFormValidation();
    }
    
    setupGeolocation() {
        if (navigator.geolocation) {
            navigator.geolocation.getCurrentPosition(
                (position) => {
                    const lat = position.coords.latitude;
                    const lon = position.coords.longitude;
                    const alt = position.coords.altitude || 0;
                    
                    const latitudeInput = document.getElementById('latitude');
                    const longitudeInput = document.getElementById('longitude');
                    const altitudeInput = document.getElementById('altitude');
                    
                    if (latitudeInput) latitudeInput.value = lat.toFixed(6);
                    if (longitudeInput) longitudeInput.value = lon.toFixed(6);
                    if (altitudeInput) altitudeInput.value = Math.round(alt * 3.28084); // Convert to feet
                    
                    console.log('Position auto-filled from geolocation');
                },
                (error) => {
                    console.log('Geolocation not available:', error.message);
                }
            );
        }
    }
    
    setupFormValidation() {
        const forms = document.querySelectorAll('form');
        forms.forEach(form => {
            form.addEventListener('submit', (e) => {
                if (!form.checkValidity()) {
                    e.preventDefault();
                    e.stopPropagation();
                }
                form.classList.add('was-validated');
            });
        });
    }
    
    setupKeyboardShortcuts() {
        document.addEventListener('keydown', (e) => {
            // Prevent space bar from scrolling when PTT is active
            if (e.code === 'Space' && e.target.tagName !== 'INPUT') {
                e.preventDefault();
            }
        });
    }
    
    setupServerURL() {
        // Auto-detect server URL based on current location
        const serverUrlInput = document.getElementById('serverUrl');
        if (serverUrlInput) {
            const protocol = window.location.protocol;
            const hostname = window.location.hostname;
            const port = window.location.port || (protocol === 'https:' ? '443' : '80');
            const autoDetectedURL = `${protocol}//${hostname}:${port}`;
            serverUrlInput.value = autoDetectedURL;
            console.log('Auto-detected server URL:', autoDetectedURL);
        }
    }
    
    initializeWebRTCClient() {
        this.webrtcClient = new WebRTCClient();
        console.log('WebRTC client initialized');
    }
    
    async handleConnect() {
        const serverUrl = document.getElementById('serverUrl')?.value;
        const username = document.getElementById('username')?.value;
        
        if (!serverUrl || !username) {
            this.showError('Please enter server URL and username');
            return;
        }
        
        try {
            this.showLoading(true);
            
            if (this.webrtcClient) {
                await this.webrtcClient.connect(serverUrl, username);
                
                // Show radio interface
                this.showRadioInterface();
            } else {
                throw new Error('WebRTC client not initialized');
            }
            
        } catch (error) {
            console.error('Connection error:', error);
            this.showError('Connection failed: ' + error.message);
        } finally {
            this.showLoading(false);
        }
    }
    
    async handleLogin(e) {
        e.preventDefault();
        
        const formData = new FormData(e.target);
        const username = formData.get('username');
        const password = formData.get('password');
        
        try {
            this.showLoading(true);
            
            const response = await fetch('/api/auth/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ username, password })
            });
            
            const result = await response.json();
            
            if (result.success) {
                this.isAuthenticated = true;
                this.currentUser = result.user;
                this.showMainInterface();
                this.showSuccess('Login successful');
            } else {
                this.showError(result.message || 'Login failed');
            }
            
        } catch (error) {
            console.error('Login error:', error);
            this.showError('Login failed: ' + error.message);
        } finally {
            this.showLoading(false);
        }
    }
    
    async handleRegister(e) {
        e.preventDefault();
        
        const formData = new FormData(e.target);
        const username = formData.get('username');
        const email = formData.get('email');
        const password = formData.get('password');
        
        try {
            this.showLoading(true);
            
            const response = await fetch('/api/auth/register', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ username, email, password })
            });
            
            const result = await response.json();
            
            if (result.success) {
                this.showSuccess('Registration successful');
                this.showLoginForm();
            } else {
                this.showError(result.message || 'Registration failed');
            }
            
        } catch (error) {
            console.error('Registration error:', error);
            this.showError('Registration failed: ' + error.message);
        } finally {
            this.showLoading(false);
        }
    }
    
    showLoginForm() {
        document.getElementById('loginForm').style.display = 'block';
        document.getElementById('registerForm').style.display = 'none';
    }
    
    showRegisterForm() {
        document.getElementById('loginForm').style.display = 'none';
        document.getElementById('registerForm').style.display = 'block';
    }
    
    showMainInterface() {
        document.getElementById('loginForm').style.display = 'none';
        document.getElementById('registerForm').style.display = 'none';
        document.getElementById('mainInterface').style.display = 'block';
    }
    
    showRadioInterface() {
        document.querySelector('.connection-setup').style.display = 'none';
        document.getElementById('radioInterface').style.display = 'block';
    }
    
    updatePosition() {
        if (!this.webrtcClient) return;
        
        const radioData = {
            callsign: document.getElementById('callsign')?.value,
            latitude: parseFloat(document.getElementById('latitude')?.value),
            longitude: parseFloat(document.getElementById('longitude')?.value),
            altitude: parseFloat(document.getElementById('altitude')?.value)
        };
        
        this.webrtcClient.sendRadioData(radioData);
        this.showSuccess('Position updated');
    }
    
    startPTT(channel) {
        if (this.webrtcClient) {
            this.webrtcClient.startPTT();
        }
    }
    
    stopPTT(channel) {
        if (this.webrtcClient) {
            this.webrtcClient.stopPTT();
        }
    }
    
    setAudioLevel(level) {
        if (this.webrtcClient) {
            this.webrtcClient.setAudioLevel(level);
        }
        
        const audioLevelValue = document.getElementById('audioLevelValue');
        if (audioLevelValue) {
            audioLevelValue.textContent = level + '%';
        }
    }
    
    testAudio() {
        if (this.webrtcClient) {
            this.webrtcClient.generateTestAudio();
        }
    }
    
    showSettings() {
        // Implement settings modal
        console.log('Settings clicked');
    }
    
    showLoading(show) {
        const app = document.getElementById('app');
        if (show) {
            app.classList.add('loading');
        } else {
            app.classList.remove('loading');
        }
    }
    
    showError(message) {
        console.error('Error:', message);
        // Implement error display
        alert('Error: ' + message);
    }
    
    showSuccess(message) {
        console.log('Success:', message);
        // Implement success display
        alert('Success: ' + message);
    }
}

// Initialize app when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.fgcomApp = new FGComApp();
});

// Export for use in other modules
window.FGComApp = FGComApp;
