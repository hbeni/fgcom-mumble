/**
 * Protocol Translator - Converts between WebRTC JSON and Mumble UDP field=value formats
 */

class ProtocolTranslator {
    constructor() {
        this.fieldMappings = {
            // Radio data fields
            callsign: 'callsign',
            latitude: 'lat',
            longitude: 'lon',
            altitude: 'alt',
            frequency: 'freq',
            power: 'pwr',
            volume: 'vol',
            squelch: 'sq',
            ptt: 'ptt',
            operational: 'op',
            channel: 'ch',
            mode: 'mode',
            modulation: 'mod'
        };
        
        this.reverseMappings = {};
        for (const [jsonField, udpField] of Object.entries(this.fieldMappings)) {
            this.reverseMappings[udpField] = jsonField;
        }
    }
    
    /**
     * Convert WebRTC JSON format to Mumble UDP field=value format
     */
    jsonToUDP(jsonData) {
        try {
            console.log('Converting JSON to UDP format:', jsonData);
            
            const udpFields = [];
            
            // Handle main radio data
            if (jsonData.callsign) {
                udpFields.push(`callsign=${this.escapeValue(jsonData.callsign)}`);
            }
            
            if (jsonData.latitude !== undefined) {
                udpFields.push(`lat=${jsonData.latitude}`);
            }
            
            if (jsonData.longitude !== undefined) {
                udpFields.push(`lon=${jsonData.longitude}`);
            }
            
            if (jsonData.altitude !== undefined) {
                udpFields.push(`alt=${jsonData.altitude}`);
            }
            
            // Handle radio channels
            if (jsonData.channels && Array.isArray(jsonData.channels)) {
                jsonData.channels.forEach((channel, index) => {
                    if (channel.frequency) {
                        udpFields.push(`ch${index}.freq=${channel.frequency}`);
                    }
                    if (channel.power !== undefined) {
                        udpFields.push(`ch${index}.pwr=${channel.power}`);
                    }
                    if (channel.volume !== undefined) {
                        udpFields.push(`ch${index}.vol=${channel.volume}`);
                    }
                    if (channel.squelch !== undefined) {
                        udpFields.push(`ch${index}.sq=${channel.squelch}`);
                    }
                    if (channel.ptt !== undefined) {
                        udpFields.push(`ch${index}.ptt=${channel.ptt ? 1 : 0}`);
                    }
                    if (channel.operational !== undefined) {
                        udpFields.push(`ch${index}.op=${channel.operational ? 1 : 0}`);
                    }
                    if (channel.mode) {
                        udpFields.push(`ch${index}.mode=${this.escapeValue(channel.mode)}`);
                    }
                    if (channel.modulation) {
                        udpFields.push(`ch${index}.mod=${this.escapeValue(channel.modulation)}`);
                    }
                });
            }
            
            // Handle single channel data (backward compatibility)
            if (jsonData.frequency) {
                udpFields.push(`freq=${jsonData.frequency}`);
            }
            if (jsonData.power !== undefined) {
                udpFields.push(`pwr=${jsonData.power}`);
            }
            if (jsonData.volume !== undefined) {
                udpFields.push(`vol=${jsonData.volume}`);
            }
            if (jsonData.squelch !== undefined) {
                udpFields.push(`sq=${jsonData.squelch}`);
            }
            if (jsonData.ptt !== undefined) {
                udpFields.push(`ptt=${jsonData.ptt ? 1 : 0}`);
            }
            if (jsonData.operational !== undefined) {
                udpFields.push(`op=${jsonData.operational ? 1 : 0}`);
            }
            if (jsonData.mode) {
                udpFields.push(`mode=${this.escapeValue(jsonData.mode)}`);
            }
            if (jsonData.modulation) {
                udpFields.push(`mod=${this.escapeValue(jsonData.modulation)}`);
            }
            
            // Add timestamp
            udpFields.push(`timestamp=${Date.now()}`);
            
            const udpString = udpFields.join(' ');
            console.log('Generated UDP string:', udpString);
            
            return udpString;
            
        } catch (error) {
            console.error('Error converting JSON to UDP:', error);
            throw error;
        }
    }
    
    /**
     * Convert Mumble UDP field=value format to WebRTC JSON format
     */
    udpToJSON(udpString) {
        try {
            console.log('Converting UDP to JSON format:', udpString);
            
            const jsonData = {
                channels: []
            };
            
            const fields = udpString.split(' ');
            
            for (const field of fields) {
                const [key, value] = field.split('=');
                if (!key || value === undefined) continue;
                
                const unescapedValue = this.unescapeValue(value);
                
                // Handle channel-specific fields
                if (key.startsWith('ch') && key.includes('.')) {
                    const [channelIndex, channelField] = key.split('.');
                    const index = parseInt(channelIndex.replace('ch', ''));
                    
                    // Ensure channel exists
                    while (jsonData.channels.length <= index) {
                        jsonData.channels.push({});
                    }
                    
                    // Map field
                    const jsonField = this.reverseMappings[channelField] || channelField;
                    jsonData.channels[index][jsonField] = this.convertValue(unescapedValue, jsonField);
                } else {
                    // Handle main fields
                    const jsonField = this.reverseMappings[key] || key;
                    jsonData[jsonField] = this.convertValue(unescapedValue, jsonField);
                }
            }
            
            console.log('Generated JSON data:', jsonData);
            return jsonData;
            
        } catch (error) {
            console.error('Error converting UDP to JSON:', error);
            throw error;
        }
    }
    
    /**
     * Convert value to appropriate type
     */
    convertValue(value, field) {
        // Boolean fields
        if (['ptt', 'operational', 'op'].includes(field)) {
            return value === '1' || value === 'true';
        }
        
        // Numeric fields
        if (['latitude', 'lat', 'longitude', 'lon', 'altitude', 'alt', 'frequency', 'freq', 
             'power', 'pwr', 'volume', 'vol', 'squelch', 'sq', 'timestamp'].includes(field)) {
            const num = parseFloat(value);
            return isNaN(num) ? value : num;
        }
        
        // String fields (default)
        return value;
    }
    
    /**
     * Escape special characters in values
     */
    escapeValue(value) {
        if (typeof value !== 'string') {
            return String(value);
        }
        
        return value
            .replace(/\\/g, '\\\\')
            .replace(/ /g, '\\ ')
            .replace(/=/g, '\\=')
            .replace(/\n/g, '\\n')
            .replace(/\r/g, '\\r');
    }
    
    /**
     * Unescape special characters in values
     */
    unescapeValue(value) {
        if (typeof value !== 'string') {
            return value;
        }
        
        return value
            .replace(/\\r/g, '\r')
            .replace(/\\n/g, '\n')
            .replace(/\\=/g, '=')
            .replace(/\\ /g, ' ')
            .replace(/\\\\/g, '\\');
    }
    
    /**
     * Validate JSON radio data structure
     */
    validateJSONData(jsonData) {
        const errors = [];
        
        // Required fields
        if (!jsonData.callsign) {
            errors.push('Missing required field: callsign');
        }
        
        if (jsonData.latitude === undefined) {
            errors.push('Missing required field: latitude');
        }
        
        if (jsonData.longitude === undefined) {
            errors.push('Missing required field: longitude');
        }
        
        // Validate coordinates
        if (jsonData.latitude !== undefined && (jsonData.latitude < -90 || jsonData.latitude > 90)) {
            errors.push('Invalid latitude: must be between -90 and 90');
        }
        
        if (jsonData.longitude !== undefined && (jsonData.longitude < -180 || jsonData.longitude > 180)) {
            errors.push('Invalid longitude: must be between -180 and 180');
        }
        
        // Validate channels
        if (jsonData.channels && Array.isArray(jsonData.channels)) {
            jsonData.channels.forEach((channel, index) => {
                if (channel.frequency && (channel.frequency < 0 || channel.frequency > 10000)) {
                    errors.push(`Invalid frequency in channel ${index}: must be between 0 and 10000 MHz`);
                }
                
                if (channel.power !== undefined && (channel.power < 0 || channel.power > 1000)) {
                    errors.push(`Invalid power in channel ${index}: must be between 0 and 1000 watts`);
                }
            });
        }
        
        return {
            valid: errors.length === 0,
            errors
        };
    }
    
    /**
     * Get protocol statistics
     */
    getStats() {
        return {
            fieldMappings: Object.keys(this.fieldMappings).length,
            supportedFields: Object.keys(this.fieldMappings),
            protocol: 'JSON ↔ UDP field=value',
            version: '1.0.0'
        };
    }
}

module.exports = ProtocolTranslator;
