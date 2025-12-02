# Module Development Guide

This document explains how to work with the modular codebase structure, allowing incremental implementation and testing of modules.

## Module Structure

The codebase is organized into independent modules:

```
lib/
├── propagation/
│   ├── core/          # Core propagation physics
│   ├── terrain/        # Terrain elevation and analysis
│   └── weather/        # Solar data and weather APIs
├── noise/              # Atmospheric noise and noise floor
├── audio/              # Audio processing
├── maps/               # OpenInfraMap data source (shared)
├── security/
│   ├── core/           # Core security utilities (encryption, hashing, authentication)
│   └── work_unit/      # Work unit security (AES256, RSA, digital signatures)
├── work_unit/           # Work unit distribution and sharing (modular work unit management)
└── space/
    ├── moon/           # Moon position tracking for EME communication
    └── satellites/     # Satellite tracking for satellite communication
```

## Building Individual Modules

Each module can be built independently:

```bash
# Build propagation module only
make module-propagation

# Build noise module only (includes maps dependency)
make module-noise

# Build audio module only
make module-audio

# Build maps module only
make module-maps

# Build security module only
make module-security

# Build work unit module only
make module-work-unit

# Build space module only
make module-space
```

## Incremental Development Workflow

### Step 1: Implement One Module

1. **Choose a module to work on** (e.g., propagation)
2. **Build just that module:**
   ```bash
   make module-propagation
   ```
3. **Test the module in isolation** (if module has unit tests)
4. **Verify it compiles without errors**

### Step 2: Integrate Module

1. **Build the full plugin** to test integration:
   ```bash
   make plugin
   ```
2. **Run plugin tests** to ensure nothing broke
3. **Test functionality** in the actual plugin

### Step 3: Move to Next Module

Repeat for the next module (noise, audio, etc.)

## Module Dependencies

Understanding dependencies helps with incremental work:

```
propagation/
  ├── core/          (no dependencies)
  ├── terrain/        (no dependencies)
  └── weather/        (depends on HTTP/JSON - external)

noise/
  └── (depends on maps/ for infrastructure data)

audio/
  └── (depends on frequency_offset, Mumble APIs)

maps/
  └── (shared between propagation and noise)

security/
  ├── core/            (depends on OpenSSL for encryption/hashing)
  └── work_unit/        (depends on core/, OpenSSL, work_unit_distributor)

work_unit/
  └── (depends on work_unit_distributor, client_work_unit_coordinator)

space/
  ├── moon/            (no dependencies)
  └── satellites/      (no dependencies)
```

## Testing Strategy

### Module-Level Testing

1. **Compile module:**
   ```bash
   make module-<name>
   ```

2. **Check for compilation errors** - if it compiles, the module's internal structure is correct

3. **Test module integration:**
   ```bash
   make plugin  # Builds everything together
   ```

### Integration Testing

After implementing a module:

1. Build full plugin: `make plugin`
2. Run existing tests: `make test` (if available)
3. Test in actual Mumble plugin environment

## Module Implementation Order

Recommended order for implementing modules:

1. **maps/** - Shared module, needed by others
2. **propagation/core/** - Core physics, no dependencies
3. **propagation/terrain/** - Terrain analysis
4. **propagation/weather/** - Weather data
5. **noise/** - Noise calculations (uses maps)
6. **audio/** - Audio processing (uses noise)
7. **security/** - Security and encryption (optional, for voice encryption and work unit security)
8. **work_unit/** - Work unit distribution and sharing (for distributed propagation calculations)
9. **space/** - Space-based propagation (moon tracking for EME, satellite tracking)

## Making Changes to a Module

### Example: Modifying Propagation Module

1. **Edit files in `lib/propagation/core/`**
2. **Build just that module:**
   ```bash
   make module-propagation
   ```
3. **If successful, build full plugin:**
   ```bash
   make plugin
   ```
4. **Test the changes**

### Example: Adding New Functionality

1. **Add new files to appropriate module directory**
2. **Update Makefile** to include new object files in module's OBJS variable
3. **Build module:**
   ```bash
   make module-<name>
   ```
4. **Build full plugin and test**

## Module Interfaces

Each module exposes its functionality through header files:

- **propagation/core/**: `propagation_physics.h`, `atmospheric_ducting.h`, `enhanced_multipath.h`
- **propagation/terrain/**: `terrain_elevation.h`, `terrain_environmental_api.h`
- **propagation/weather/**: `solar_data.h`, `weather_data.h`
- **noise/**: `atmospheric_noise.h`, `noise_floor.h`
- **audio/**: `audio.h`
- **maps/**: `openinframap_data_source.h`
- **security/core/**: `security.h` (encryption, hashing, authentication)
- **security/work_unit/**: `work_unit_security.h` (AES256, RSA, digital signatures)
- **work_unit/**: `work_unit_sharing.h` (modular work unit sharing strategies)
- **space/moon/**: `moon_position_tracker.h` (EME communication, moon tracking)
- **space/satellites/**: `satellite_tracker.h` (satellite tracking, visibility, Doppler)

## Benefits of This Structure

1. **Incremental Development**: Work on one module at a time
2. **Easier Testing**: Test modules independently before integration
3. **Clear Boundaries**: Each module has a clear purpose and location
4. **Reduced Complexity**: Smaller scope makes debugging easier
5. **Parallel Development**: Multiple developers can work on different modules
6. **Selective Integration**: Can enable/disable modules if needed

## Troubleshooting

### Module Won't Compile

1. Check includes - make sure paths are correct (use `lib/module/file.h`)
2. Check dependencies - ensure required modules are built first
3. Check Makefile - verify object files are listed correctly

### Integration Issues

1. Build all modules: `make libs`
2. Check for missing symbols in linker errors
3. Verify includes in files that use the module

### Module Dependencies

If module A needs module B:
- Build module B first: `make module-B`
- Then build module A: `make module-A`
- Or build everything: `make libs`

