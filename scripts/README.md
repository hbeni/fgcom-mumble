# FGCom-mumble Scripts Directory

This directory contains all scripts organized by category for better maintainability and organization.

## Directory Structure

```
scripts/
├── pattern_generation/     # Unified pattern generation script
├── testing/               # Unified testing script
├── server/                # Server-side scripts
├── utilities/             # General utility scripts
└── README.md              # This file
```

## Script Categories

### Pattern Generation Scripts (`pattern_generation/`)

**`generate_patterns.sh`** - Unified multi-threaded pattern generation script

**Features:**
- **Multi-threaded**: Uses up to 20 CPU cores for fast pattern generation
- **Safe by default**: Does not overwrite existing pattern files
- **Flexible options**: Command-line options for customization
- **Dry-run mode**: Preview what would be generated without actually doing it
- **Category-based**: Generate patterns for specific vehicle categories

**Usage:**
```bash
# Show help
./scripts/pattern_generation/generate_patterns.sh --help

# Generate all patterns (safe mode - won't overwrite existing)
./scripts/pattern_generation/generate_patterns.sh

# Generate only aircraft patterns
./scripts/pattern_generation/generate_patterns.sh aircraft

# Dry run to see what would be generated
./scripts/pattern_generation/generate_patterns.sh --dry-run coastal

# Overwrite existing patterns
./scripts/pattern_generation/generate_patterns.sh --overwrite maritime

# Use specific number of parallel jobs
./scripts/pattern_generation/generate_patterns.sh --jobs 10 all
```

### Testing Scripts (`testing/`)

**`run_tests.sh`** - Unified multi-threaded testing script

**Features:**
- **Multi-threaded**: Uses up to 20 CPU cores for parallel testing
- **Comprehensive**: Tests compilation, frequencies, and load
- **Flexible options**: Command-line options for customization
- **Dry-run mode**: Preview what tests would be run

**Usage:**
```bash
# Show help
./scripts/testing/run_tests.sh --help

# Run all tests
./scripts/testing/run_tests.sh

# Run only setup tests
./scripts/testing/run_tests.sh setup

# Dry run to see what tests would be run
./scripts/testing/run_tests.sh --dry-run frequencies

# Use specific number of parallel jobs
./scripts/testing/run_tests.sh --jobs 5 all
```

### Server Scripts (`server/`)

These scripts are used for server operations:

- **`fgcom-botmanager.sh`** - Bot manager for FGCom server
- **`loadTest.sh`** - Load testing script

### Utility Scripts (`utilities/`)

These are general utility scripts used by other scripts:

- **`eznec2nec.sh`** - Convert EZNEC files to NEC2 format
- **`extract_pattern_advanced.sh`** - Extract radiation patterns from NEC2 output

## Usage

### Running Pattern Generation Scripts

```bash
# Generate all patterns
./scripts/pattern_generation/generate_all_patterns.sh

# Regenerate coastal patterns with Bergen Radio specifications
./scripts/pattern_generation/regenerate_coastal_patterns.sh

# Generate specific antenna patterns
./scripts/pattern_generation/generate_yagi_144mhz_patterns.sh
```

### Running Test Scripts

```bash
# Run frequency tests
./scripts/testing/genAllFrq.sh

# Run setup tests
./scripts/testing/test_setup.sh
```

### Running Server Scripts

```bash
# Start bot manager
./scripts/server/fgcom-botmanager.sh

# Run load tests
./scripts/server/loadTest.sh
```

## Dependencies

Most scripts require:
- **NEC2C**: For electromagnetic simulations
- **EZNEC2NEC**: For file format conversion
- **Bash**: For script execution
- **Standard Unix tools**: sed, awk, grep, etc.

## Script Organization Benefits

1. **Centralized Location**: All scripts in one place
2. **Logical Grouping**: Scripts organized by function
3. **Easy Maintenance**: Clear structure for updates
4. **Better Documentation**: Each category documented
5. **Reduced Clutter**: Cleaner main codebase

## Contributing

When adding new scripts:
1. Place them in the appropriate category
2. Update this README with description
3. Ensure scripts are executable (`chmod +x`)
4. Test scripts before committing

## Notes

- All scripts use absolute paths to avoid path issues
- Scripts are designed to be run from the project root
- Pattern generation scripts create output in appropriate directories
- Test scripts validate functionality and performance
