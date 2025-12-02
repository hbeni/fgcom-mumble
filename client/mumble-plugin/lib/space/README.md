# Space Module

This module provides space-based radio propagation calculations including moon position tracking for EME (Earth-Moon-Earth) communication and satellite tracking for satellite communication.

## Module Structure

```
lib/space/
├── moon/                    # Moon position tracking for EME
│   ├── moon_position_tracker.h
│   └── moon_position_tracker.cpp
├── satellites/              # Satellite tracking
│   ├── satellite_tracker.h
│   └── satellite_tracker.cpp
└── README.md                # This file
```

## Module Components

### Moon Tracking (`moon/`)

Provides comprehensive moon position tracking for EME communication:
- Orbital position calculations
- Libration effects (longitude and latitude)
- Distance and delay calculations
- Doppler shift calculations
- EME path loss calculations
- Multi-band support (2m, 6m, 70cm, etc.)

### Satellite Tracking (`satellites/`)

Provides satellite tracking capabilities:
- Real-time position calculations
- Visibility predictions
- Pass predictions
- Doppler shift calculations
- Path loss calculations
- Support for various satellite types (military, amateur, navigation, etc.)

## Dependencies

- Standard C++ library
- `<chrono>` for time handling
- `<cmath>` for mathematical calculations

## Usage

### Moon Tracking

```cpp
#include "space/moon/moon_position_tracker.h"

FGCom::MoonPositionTracker tracker;
tracker.updatePosition();
auto position = tracker.getCurrentPosition();
auto eme_params = tracker.calculateEMEParameters(144.0, 100.0, 20.0);
```

### Satellite Tracking

```cpp
#include "space/satellites/satellite_tracker.h"

FGCom::space::satellites::SatelliteTracker tracker;
tracker.initialize(observer_lat, observer_lon, observer_alt);

SatelliteOrbit orbit;
// ... set orbit parameters ...
tracker.registerSatellite("ISS", orbit, SatelliteType::AMATEUR_FM);

auto position = tracker.getCurrentPosition("ISS");
auto doppler = tracker.calculateDopplerShift("ISS", 145.8);
```

## Building

```bash
# Build space module
make module-space

# Test space module
make test-module-space
```

## Module Interface

The module exposes functionality through:
- `space/moon/moon_position_tracker.h` - Moon tracking interface
- `space/satellites/satellite_tracker.h` - Satellite tracking interface

