/**
 * Fake Moon API Examples for FGcom-Mumble (JavaScript/Node.js)
 * 
 * This script demonstrates how to use the Fake Moon Placement API
 * to create, manage, and communicate with artificial moons in the
 * FGcom-Mumble simulation system.
 * 
 * Author: FGcom-mumble Development Team
 * Date: 2025
 */

const axios = require('axios');

class FakeMoonAPI {
    constructor(baseUrl = 'http://localhost:8081/api/v1') {
        this.baseUrl = baseUrl;
        this.client = axios.create({
            baseURL: baseUrl,
            timeout: 10000,
            headers: {
                'Content-Type': 'application/json'
            }
        });
    }

    async addMoon(name, orbitalParams, physicalParams, frequencies, options = {}) {
        const data = {
            name: name,
            type: options.type || 'COMMUNICATION',
            mode: options.mode || 'REFLECTOR',
            orbital_parameters: orbitalParams,
            physical_parameters: physicalParams,
            frequencies: frequencies,
            power: options.power || 100,
            antenna_gain: options.antenna_gain || 10,
            minimum_elevation: options.minimum_elevation || 5,
            maximum_range: options.maximum_range || 500000,
            doppler_compensation: options.doppler_compensation !== false,
            atmospheric_effects: options.atmospheric_effects !== false,
            signal_degradation: options.signal_degradation !== false
        };

        try {
            const response = await this.client.post('/moon/add', data);
            return response.data;
        } catch (error) {
            throw new Error(`Failed to add moon: ${error.response?.data?.error || error.message}`);
        }
    }

    async getMoonPosition(moonId) {
        try {
            const response = await this.client.get(`/moon/position/${moonId}`);
            return response.data;
        } catch (error) {
            throw new Error(`Failed to get moon position: ${error.response?.data?.error || error.message}`);
        }
    }

    async simulateCommunication(moonId, groundStation, audioData, effects) {
        const data = {
            ground_station: groundStation,
            audio_data: audioData,
            effects: effects
        };

        try {
            const response = await this.client.post(`/moon/simulate/${moonId}`, data);
            return response.data;
        } catch (error) {
            throw new Error(`Failed to simulate communication: ${error.response?.data?.error || error.message}`);
        }
    }

    async listMoons() {
        try {
            const response = await this.client.get('/moon/list');
            return response.data;
        } catch (error) {
            throw new Error(`Failed to list moons: ${error.response?.data?.error || error.message}`);
        }
    }

    async removeMoon(moonId) {
        try {
            const response = await this.client.delete(`/moon/remove/${moonId}`);
            return response.data;
        } catch (error) {
            throw new Error(`Failed to remove moon: ${error.response?.data?.error || error.message}`);
        }
    }
}

async function createTestMoon(api, name) {
    console.log(`Creating test moon: ${name}`);

    // Orbital parameters (similar to Earth's Moon)
    const orbitalParams = {
        semi_major_axis: 384400,  // km (Earth-Moon distance)
        eccentricity: 0.0549,    // Moon's eccentricity
        inclination: 5.145,       // degrees
        longitude_of_ascending_node: 0.0,
        orbital_period: 27.3      // days (sidereal month)
    };

    // Physical parameters (similar to Earth's Moon)
    const physicalParams = {
        radius: 1737.4,           // km (Moon radius)
        mass: 7.342e22,           // kg (Moon mass)
        albedo: 0.136             // Moon's albedo
    };

    // Communication frequencies (amateur radio bands)
    const frequencies = {
        uplink: 145.900,          // MHz (2m band)
        downlink: 435.800         // MHz (70cm band)
    };

    // Additional parameters
    const options = {
        power: 100,               // watts
        antenna_gain: 10,         // dBi
        minimum_elevation: 5,     // degrees
        maximum_range: 500000,    // km
        doppler_compensation: true,
        atmospheric_effects: true,
        signal_degradation: true
    };

    try {
        const result = await api.addMoon(name, orbitalParams, physicalParams, frequencies, options);
        console.log(`✅ Moon created successfully: ${result.moon.id}`);
        return result.moon.id;
    } catch (error) {
        console.log(`❌ Failed to create moon: ${error.message}`);
        return null;
    }
}

async function demonstrateMoonTracking(api, moonId) {
    console.log(`\n🌙 Tracking moon: ${moonId}`);

    for (let i = 0; i < 5; i++) {  // Track for 5 updates
        try {
            const position = await api.getMoonPosition(moonId);
            const pos = position.position;
            const vis = position.visibility;

            console.log(`Update ${i + 1}:`);
            console.log(`  Position: (${pos.x.toFixed(1)}, ${pos.y.toFixed(1)}, ${pos.z.toFixed(1)}) km`);
            console.log(`  Distance: ${pos.distance.toFixed(1)} km`);
            console.log(`  Visible: ${vis.visible ? 'Yes' : 'No'}`);
            console.log(`  Elevation: ${vis.elevation.toFixed(1)}°`);
            console.log(`  Azimuth: ${vis.azimuth.toFixed(1)}°`);
            console.log(`  Doppler Shift: ${position.doppler_shift.toFixed(2)} Hz`);
        } catch (error) {
            console.log(`❌ Failed to get position: ${error.message}`);
        }

        await new Promise(resolve => setTimeout(resolve, 1000)); // Wait 1 second
    }
}

async function demonstrateCommunication(api, moonId) {
    console.log(`\n📡 Simulating communication with moon: ${moonId}`);

    // Ground station location (New York City)
    const groundStation = {
        latitude: 40.7128,
        longitude: -74.0060,
        altitude: 0.0
    };

    // Simulate audio data (base64 encoded)
    const audioData = Buffer.from('Test audio data for moon communication').toString('base64');

    // Communication effects
    const effects = {
        doppler_shift: true,
        signal_degradation: true,
        atmospheric_effects: true
    };

    try {
        const result = await api.simulateCommunication(moonId, groundStation, audioData, effects);
        const comm = result.communication;
        const pos = result.position;

        console.log(`✅ Communication simulation successful:`);
        console.log(`  Signal Quality: ${comm.signal_quality.toFixed(2)}`);
        console.log(`  Signal Strength: ${comm.signal_strength.toFixed(1)} dBm`);
        console.log(`  Communication Quality: ${comm.communication_quality.toFixed(2)}`);
        console.log(`  Doppler Shift: ${comm.doppler_shift.toFixed(2)} Hz`);
        console.log(`  Uplink Frequency: ${comm.uplink_frequency.toFixed(3)} MHz`);
        console.log(`  Downlink Frequency: ${comm.downlink_frequency.toFixed(3)} MHz`);
        console.log(`  Moon Distance: ${pos.distance.toFixed(1)} km`);
        console.log(`  Elevation: ${pos.elevation.toFixed(1)}°`);
    } catch (error) {
        console.log(`❌ Communication simulation failed: ${error.message}`);
    }
}

async function demonstrateMoonManagement(api) {
    console.log('\n📋 Moon Management Operations');

    try {
        const moons = await api.listMoons();
        console.log(`Total moons: ${moons.total_moons}/${moons.max_moons}`);
        moons.moons.forEach(moon => {
            console.log(`  - ${moon.id}: ${moon.name} (${moon.type})`);
        });
    } catch (error) {
        console.log(`❌ Failed to list moons: ${error.message}`);
    }
}

async function createMultipleMoons(api) {
    console.log('\n🛰️ Creating multiple moons with different configurations');

    const moonConfigs = [
        {
            name: 'LOW-ORBIT-MOON',
            orbitalParams: {
                semi_major_axis: 200000,  // Lower orbit
                eccentricity: 0.0,
                inclination: 0.0,
                longitude_of_ascending_node: 0.0,
                orbital_period: 10.0
            },
            frequencies: { uplink: 144.200, downlink: 430.200 }
        },
        {
            name: 'HIGH-ORBIT-MOON',
            orbitalParams: {
                semi_major_axis: 500000,  // Higher orbit
                eccentricity: 0.1,
                inclination: 15.0,
                longitude_of_ascending_node: 45.0,
                orbital_period: 40.0
            },
            frequencies: { uplink: 146.000, downlink: 436.000 }
        },
        {
            name: 'POLAR-MOON',
            orbitalParams: {
                semi_major_axis: 300000,
                eccentricity: 0.05,
                inclination: 90.0,  // Polar orbit
                longitude_of_ascending_node: 0.0,
                orbital_period: 20.0
            },
            frequencies: { uplink: 145.500, downlink: 435.500 }
        }
    ];

    const createdMoons = [];

    for (const config of moonConfigs) {
        try {
            const result = await api.addMoon(
                config.name,
                config.orbitalParams,
                {
                    radius: 1000.0,  // Smaller radius for test moons
                    mass: 1.0e20,    // Smaller mass
                    albedo: 0.1
                },
                config.frequencies,
                {
                    power: 50,
                    antenna_gain: 5
                }
            );

            createdMoons.push(result.moon.id);
            console.log(`✅ Created ${config.name}: ${result.moon.id}`);
        } catch (error) {
            console.log(`❌ Failed to create ${config.name}: ${error.message}`);
        }
    }

    return createdMoons;
}

async function demonstrateAdvancedFeatures(api, moonId) {
    console.log(`\n🔬 Advanced Features for moon: ${moonId}`);

    try {
        const position = await api.getMoonPosition(moonId);
        const pos = position.position;
        const vis = position.visibility;

        console.log(`Detailed Position Analysis:`);
        console.log(`  Cartesian Coordinates: (${pos.x.toFixed(1)}, ${pos.y.toFixed(1)}, ${pos.z.toFixed(1)}) km`);
        console.log(`  Distance from Earth: ${pos.distance.toFixed(1)} km`);
        console.log(`  True Anomaly: ${pos.true_anomaly.toFixed(1)}°`);
        console.log(`  Visibility Status: ${vis.visible ? 'Visible' : 'Not Visible'}`);
        console.log(`  Elevation Angle: ${vis.elevation.toFixed(1)}°`);
        console.log(`  Azimuth Angle: ${vis.azimuth.toFixed(1)}°`);
        console.log(`  Doppler Shift: ${position.doppler_shift.toFixed(2)} Hz`);

        // Calculate orbital velocity (simplified)
        const velocity = Math.abs(position.doppler_shift) * 299792.458 / 145.900; // km/s
        console.log(`  Estimated Orbital Velocity: ${velocity.toFixed(1)} km/s`);
    } catch (error) {
        console.log(`❌ Failed to get advanced features: ${error.message}`);
    }
}

async function cleanupMoons(api, moonIds) {
    console.log(`\n🧹 Cleaning up ${moonIds.length} moons`);

    for (const moonId of moonIds) {
        try {
            await api.removeMoon(moonId);
            console.log(`✅ Removed moon: ${moonId}`);
        } catch (error) {
            console.log(`❌ Failed to remove moon ${moonId}: ${error.message}`);
        }
    }
}

async function main() {
    console.log('🌙 Fake Moon API Demonstration');
    console.log('='.repeat(50));

    // Initialize API client
    const api = new FakeMoonAPI();

    try {
        // Test API connectivity
        console.log('Testing API connectivity...');
        const moons = await api.listMoons();
        console.log('✅ API is accessible');

        // Create a test moon
        const moonId = await createTestMoon(api, 'DEMO-MOON-1');
        if (!moonId) {
            return;
        }

        // Demonstrate moon tracking
        await demonstrateMoonTracking(api, moonId);

        // Demonstrate communication
        await demonstrateCommunication(api, moonId);

        // Demonstrate advanced features
        await demonstrateAdvancedFeatures(api, moonId);

        // Create multiple moons
        const additionalMoons = await createMultipleMoons(api);

        // Demonstrate moon management
        await demonstrateMoonManagement(api);

        // Clean up
        const allMoons = [moonId, ...additionalMoons];
        await cleanupMoons(api, allMoons);

        console.log('\n✅ Demonstration completed successfully!');

    } catch (error) {
        if (error.code === 'ECONNREFUSED') {
            console.log('❌ Could not connect to the Fake Moon API server.');
            console.log('Make sure the server is running on http://localhost:8081');
        } else {
            console.log(`❌ An error occurred: ${error.message}`);
        }
    }
}

// Run the demonstration if this script is executed directly
if (require.main === module) {
    main().catch(console.error);
}

module.exports = { FakeMoonAPI };

