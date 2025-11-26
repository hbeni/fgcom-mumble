/**
 * Audio Processor - Handles audio conversion between WebRTC and Mumble formats
 */

const opus = require('node-opus');
const { Transform } = require('stream');

class AudioProcessor {
    constructor(config) {
        this.config = config;
        this.opusEncoder = null;
        this.opusDecoder = null;
        this.audioBuffer = Buffer.alloc(0);
        this.sampleRate = config.sampleRate || 48000;
        this.channels = config.channels || 1;
        this.bitrate = config.bitrate || 64000;
        
        this.initializeCodecs();
    }
    
    initializeCodecs() {
        try {
            // Check if opus is available and working
            if (typeof opus.OpusEncoder === 'function' && typeof opus.OpusDecoder === 'function') {
                // Initialize Opus encoder for outgoing audio (WebRTC -> Mumble)
                this.opusEncoder = new opus.OpusEncoder(this.sampleRate, this.channels);
                this.opusEncoder.setBitrate(this.bitrate);
                
                // Initialize Opus decoder for incoming audio (Mumble -> WebRTC)
                this.opusDecoder = new opus.OpusDecoder(this.sampleRate, this.channels);
                
                console.log('Audio codecs initialized successfully');
            } else {
                throw new Error('Opus codecs not available');
            }
        } catch (error) {
            console.error('Failed to initialize audio codecs:', error);
            // For now, disable Opus codecs and use fallback
            console.log('Falling back to PCM audio processing');
            this.opusEncoder = null;
            this.opusDecoder = null;
        }
    }
    
    processIncomingAudio(stream, callback) {
        try {
            console.log('Processing incoming audio stream');
            
            const audioChunks = [];
            
            stream.on('data', (chunk) => {
                audioChunks.push(chunk);
            });
            
            stream.on('end', () => {
                const audioBuffer = Buffer.concat(audioChunks);
                this.processAudioBuffer(audioBuffer, callback);
            });
            
            stream.on('error', (error) => {
                console.error('Audio stream error:', error);
                callback(null, error);
            });
            
        } catch (error) {
            console.error('Error processing incoming audio:', error);
            callback(null, error);
        }
    }
    
    processAudioBuffer(audioBuffer, callback) {
        try {
            // Convert WebRTC audio format to Mumble Opus format
            const processedAudio = this.convertWebRTCToMumble(audioBuffer);
            
            if (processedAudio) {
                callback(processedAudio);
            } else {
                callback(null, new Error('Audio conversion failed'));
            }
            
        } catch (error) {
            console.error('Error processing audio buffer:', error);
            callback(null, error);
        }
    }
    
    convertWebRTCToMumble(webRTCAudio) {
        try {
            // This is a simplified conversion - in reality, you'd need proper audio format handling
            console.log(`Converting WebRTC audio (${webRTCAudio.length} bytes) to Mumble format`);
            
            // For now, return the audio as-is
            // In a real implementation, you'd:
            // 1. Decode WebRTC audio format (PCM)
            // 2. Resample if necessary
            // 3. Encode to Opus for Mumble
            // 4. Apply any necessary audio processing
            
            return webRTCAudio;
            
        } catch (error) {
            console.error('Error converting WebRTC to Mumble audio:', error);
            return null;
        }
    }
    
    convertMumbleToWebRTC(mumbleAudio) {
        try {
            // Convert Mumble Opus audio to WebRTC format
            console.log(`Converting Mumble audio (${mumbleAudio.length} bytes) to WebRTC format`);
            
            // For now, return the audio as-is
            // In a real implementation, you'd:
            // 1. Decode Mumble Opus audio
            // 2. Resample if necessary
            // 3. Encode to WebRTC format
            // 4. Apply any necessary audio processing
            
            return mumbleAudio;
            
        } catch (error) {
            console.error('Error converting Mumble to WebRTC audio:', error);
            return null;
        }
    }
    
    // Create audio stream for WebRTC
    createAudioStream() {
        const audioStream = new Transform({
            objectMode: false,
            transform(chunk, encoding, callback) {
                try {
                    // Process audio chunk
                    const processedChunk = this.processAudioChunk(chunk);
                    callback(null, processedChunk);
                } catch (error) {
                    callback(error);
                }
            }
        });
        
        return audioStream;
    }
    
    processAudioChunk(chunk) {
        try {
            // Basic audio processing
            // In a real implementation, you'd apply:
            // - Noise reduction
            // - Echo cancellation
            // - Audio level adjustment
            // - Format conversion
            
            return chunk;
            
        } catch (error) {
            console.error('Error processing audio chunk:', error);
            return chunk; // Return original chunk on error
        }
    }
    
    // Audio quality settings
    setAudioQuality(quality) {
        try {
            const qualitySettings = {
                low: { bitrate: 32000, sampleRate: 16000 },
                medium: { bitrate: 64000, sampleRate: 24000 },
                high: { bitrate: 128000, sampleRate: 48000 }
            };
            
            const settings = qualitySettings[quality] || qualitySettings.medium;
            
            if (this.opusEncoder) {
                this.opusEncoder.setBitrate(settings.bitrate);
            }
            
            this.bitrate = settings.bitrate;
            this.sampleRate = settings.sampleRate;
            
            console.log(`Audio quality set to ${quality}: ${settings.bitrate}bps @ ${settings.sampleRate}Hz`);
            
        } catch (error) {
            console.error('Error setting audio quality:', error);
        }
    }
    
    // Get audio statistics
    getAudioStats() {
        return {
            sampleRate: this.sampleRate,
            channels: this.channels,
            bitrate: this.bitrate,
            codec: 'opus',
            bufferSize: this.audioBuffer.length
        };
    }
    
    // Cleanup resources
    destroy() {
        try {
            if (this.opusEncoder) {
                this.opusEncoder.destroy();
                this.opusEncoder = null;
            }
            
            if (this.opusDecoder) {
                this.opusDecoder.destroy();
                this.opusDecoder = null;
            }
            
            this.audioBuffer = Buffer.alloc(0);
            
            console.log('Audio processor destroyed');
            
        } catch (error) {
            console.error('Error destroying audio processor:', error);
        }
    }
}

module.exports = AudioProcessor;
