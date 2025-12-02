# Work Unit Module

This module provides modular work unit distribution and sharing capabilities for propagation calculations.

## Module Structure

```
lib/work_unit/
├── work_unit_sharing.h      # Modular sharing interface
├── work_unit_sharing.cpp    # Sharing strategy implementations
└── README.md                # This file
```

## Dependencies

- `work_unit_distributor.h` - Work unit distribution system
- `client_work_unit_coordinator.h` - Client coordination

## Module Components

### Work Unit Sharing (`work_unit_sharing.h`)

Provides modular sharing strategies for work units:
- **Direct Assignment Strategy**: Assigns work units to a single client
- **Broadcast Strategy**: Shares work units with multiple clients
- **Load Balancing Strategy**: Distributes work units based on client load

### Usage

```cpp
#include "work_unit/work_unit_sharing.h"

// Get sharing manager instance
auto& manager = FGCom_WorkUnitSharingManager::getInstance();
manager.initialize("direct"); // or "broadcast", "load_balancing"

// Share work unit with client
WorkUnitSharingResult result = manager.shareWithClient(
    unit_id, unit, client_id, client_capability
);
```

## Building

```bash
# Build work unit module
make module-work-unit

# Test work unit module
make test-module-work-unit
```

## Module Interface

The module exposes functionality through:
- `work_unit/work_unit_sharing.h` - Main sharing interface

