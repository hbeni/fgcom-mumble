# Fake Moon API Examples

This directory contains comprehensive examples demonstrating how to use the Fake Moon Placement API for FGcom-Mumble.

## Overview

The Fake Moon API allows you to create, manage, and communicate with artificial moons in the FGcom-Mumble simulation system. These examples show how to:

- Create fake moons with custom orbital parameters
- Track moon positions and visibility
- Simulate communication with realistic effects
- Manage multiple moons simultaneously
- Use advanced features like Doppler shift compensation

## Files

- `fake_moon_examples.py` - Python examples with comprehensive demonstrations
- `fake_moon_examples.js` - JavaScript/Node.js examples
- `package.json` - Node.js dependencies
- `requirements.txt` - Python dependencies
- `README.md` - This documentation

## Prerequisites

### For Python Examples
```bash
pip install -r requirements.txt
```

### For JavaScript Examples
```bash
npm install
```

## Running the Examples

### Python
```bash
python3 fake_moon_examples.py
```

### JavaScript
```bash
npm start
# or
node fake_moon_examples.js
```

## API Server Setup

Before running the examples, make sure the Fake Moon API server is running:

```bash
cd server/api
luajit fake_moon_api.lua
```

The server will start on `http://localhost:8081`.

## Example Features

### 1. Moon Creation
- Create moons with realistic orbital parameters
- Configure physical properties (radius, mass, albedo)
- Set communication frequencies and power levels
- Enable/disable simulation effects

### 2. Real-time Tracking
- Track moon positions over time
- Monitor visibility from ground stations
- Calculate Doppler shift effects
- Display orbital parameters

### 3. Communication Simulation
- Simulate radio communication with moons
- Calculate signal quality and strength
- Apply atmospheric effects
- Compensate for Doppler shift

### 4. Multi-moon Management
- Create multiple moons with different configurations
- Manage low-orbit, high-orbit, and polar moons
- List and remove moons
- Monitor system capacity

### 5. Advanced Features
- Detailed position analysis
- Orbital velocity calculations
- Signal propagation modeling
- Real-time effect simulation

## API Endpoints Used

- `POST /api/v1/moon/add` - Create a new moon
- `GET /api/v1/moon/position/{id}` - Get moon position
- `POST /api/v1/moon/simulate/{id}` - Simulate communication
- `GET /api/v1/moon/list` - List all moons
- `DELETE /api/v1/moon/remove/{id}` - Remove a moon

## Configuration

The examples use default configuration values that can be customized:

- **API Server**: `http://localhost:8081`
- **Timeout**: 10 seconds
- **Ground Station**: New York City (40.7128, -74.0060)
- **Frequencies**: 2m/70cm amateur radio bands
- **Orbital Parameters**: Earth-Moon distance and characteristics

## Error Handling

All examples include comprehensive error handling for:

- Network connectivity issues
- API server unavailability
- Invalid moon IDs
- Communication failures
- Parameter validation errors

## Integration

These examples can be integrated into larger applications for:

- Flight simulation environments
- Radio communication training
- Satellite tracking systems
- Educational demonstrations
- Research and development

## Troubleshooting

### Common Issues

1. **Connection Refused**: Make sure the API server is running
2. **Timeout Errors**: Check network connectivity and server status
3. **Invalid Parameters**: Verify orbital and physical parameters
4. **Moon Not Found**: Ensure moon ID exists before operations

### Debug Mode

Enable debug logging by setting environment variables:

```bash
# Python
export DEBUG=1
python3 fake_moon_examples.py

# JavaScript
DEBUG=1 node fake_moon_examples.js
```

## Contributing

To add new examples or improve existing ones:

1. Follow the existing code structure
2. Include comprehensive error handling
3. Add detailed comments and documentation
4. Test with various moon configurations
5. Update this README with new features

## License

This code is part of the FGcom-Mumble project and is licensed under the GPL-3.0 License.

