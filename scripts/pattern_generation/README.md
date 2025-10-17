# Pattern Generation Scripts Directory

This directory contains scripts for generating antenna radiation patterns using electromagnetic simulation software (NEC2) and advanced pattern processing techniques.

## Scripts Overview

### `antenna-radiation-pattern-generator.sh`
**Purpose**: Advanced 3D attitude pattern generation script for comprehensive antenna radiation pattern analysis.

**Features**:
- **Python-Based Transformations**: Reliable trigonometry using Python instead of AWK for accurate 3D coordinate transformations
- **3D Attitude Patterns**: Generates patterns for all roll/pitch combinations at multiple altitudes
- **Aviation Coordinate System**: Proper implementation of pitch around Y-axis, roll around X-axis
- **Real-time Yaw Support**: Integration with Vehicle Dynamics API for real-time antenna orientation control
- **Parallel Processing**: Uses multiple CPU cores for fast pattern generation with work unit distribution
- **Progress Indicators**: Real-time progress tracking with detailed status information
- **Altitude Band Organization**: Organizes patterns by RF propagation physics (ground_effects, boundary_layer, free_space)
- **Safe by default**: Does not overwrite existing pattern files
- **Flexible options**: Command-line options for customization
- **Dry-run mode**: Preview what would be generated without actually doing it
- **Security Integration**: Secure work unit processing with authentication and encryption
- **Quality Assurance**: Zero tolerance for race conditions, memory leaks, or security vulnerabilities

**Usage**:
```bash
# Show help
./antenna-radiation-pattern-generator.sh --help

# Generate all patterns with parallel processing
./antenna-radiation-pattern-generator.sh --jobs 8 --force

# Dry run to see what would be generated
./antenna-radiation-pattern-generator.sh --dry-run --verbose

# Generate with verbose output
./antenna-radiation-pattern-generator.sh --jobs 8 --verbose --force

# Generate specific vehicle patterns
./antenna-radiation-pattern-generator.sh --aircraft "cessna_172" --jobs 4
```

**Output Structure**:
- **Aircraft**: 5,460 patterns per aircraft (28 altitudes × 15 roll × 13 pitch)
- **Ground Vehicles**: 195 patterns per vehicle (1 altitude × 15 roll × 13 pitch)
- **Total**: 92,820 patterns for complete 3D attitude coverage

### `debug_script.sh`
**Purpose**: Debugging script for pattern generation troubleshooting and validation.

**Features**:
- Pattern generation debugging
- NEC2 simulation validation
- Error detection and reporting
- Performance monitoring
- Quality assurance

**Usage**:
```bash
# Debug pattern generation
./debug_script.sh

# Debug specific patterns
./debug_script.sh --patterns yagi_144mhz

# Debug with verbose output
./debug_script.sh --verbose

# Debug specific frequency
./debug_script.sh --frequency 144.200
```

### `generate_4m_yagi_pitch_patterns.sh`
**Purpose**: Specialized script for generating 4-meter Yagi antenna pitch patterns.

**Features**:
- 4-meter Yagi antenna patterns
- Pitch angle variations
- Frequency-specific patterns
- Performance optimization
- Quality validation

**Usage**:
```bash
# Generate 4m Yagi patterns
./generate_4m_yagi_pitch_patterns.sh

# Generate with specific parameters
./generate_4m_yagi_pitch_patterns.sh --frequency 70.200 --pitch-range 0,90

# Generate with validation
./generate_4m_yagi_pitch_patterns.sh --validate
```

### `pattern_validation_test_suite.sh`
**Purpose**: Comprehensive test suite for validating generated antenna patterns.

**Features**:
- Pattern validation testing
- Quality assurance checks
- Performance benchmarking
- Regression testing
- Compliance verification

**Usage**:
```bash
# Run pattern validation tests
./pattern_validation_test_suite.sh

# Test specific patterns
./pattern_validation_test_suite.sh --patterns yagi_144mhz,vertical_2m

# Test with specific criteria
./pattern_validation_test_suite.sh --criteria strict
```

### `test_pattern.txt`
**Purpose**: Test pattern file for validation and testing purposes.

**Features**:
- Sample pattern data
- Format validation
- Testing reference
- Quality benchmarks
- Documentation examples

### `test_single_pattern.sh`
**Purpose**: Single pattern testing script for individual pattern validation.

**Features**:
- Single pattern testing
- Individual validation
- Quick testing
- Error isolation
- Performance testing

**Usage**:
```bash
# Test single pattern
./test_single_pattern.sh pattern_file.pat

# Test with specific parameters
./test_single_pattern.sh --frequency 144.200 --elevation 0 pattern_file.pat

# Test with validation
./test_single_pattern.sh --validate pattern_file.pat
```

## Pattern Generation Workflow

### 1. Preparation
```bash
# Check system requirements
./antenna-radiation-pattern-generator.sh --check-requirements

# Validate input files
./debug_script.sh --validate-input
```

### 2. Generation
```bash
# Generate all patterns
./antenna-radiation-pattern-generator.sh --jobs 8 --force

# Generate specific patterns
./antenna-radiation-pattern-generator.sh --aircraft "cessna_172" --jobs 4
```

### 3. Validation
```bash
# Validate generated patterns
./pattern_validation_test_suite.sh

# Test individual patterns
./test_single_pattern.sh pattern_file.pat
```

### 4. Quality Assurance
```bash
# Run quality checks
./pattern_validation_test_suite.sh --quality-check

# Performance benchmarking
./pattern_validation_test_suite.sh --benchmark
```

## Pattern Categories

### Aircraft Patterns
- **Cessna 172**: General aviation aircraft
- **Boeing 737**: Commercial airliner
- **F-16**: Military fighter
- **Helicopter**: Rotary-wing aircraft
- **Glider**: Sailplane patterns

### Ground Vehicle Patterns
- **Jeep**: Military ground vehicle
- **Tank**: Armored vehicle
- **Truck**: Commercial vehicle
- **Car**: Civilian vehicle
- **Motorcycle**: Two-wheel vehicle

### Antenna Types
- **Yagi**: Directional antenna
- **Vertical**: Omnidirectional antenna
- **Loop**: Loop antenna
- **Dipole**: Dipole antenna
- **Helical**: Helical antenna

## Configuration

### Generation Settings
- `pattern_config.json` - Pattern generation configuration
- `antenna_specs.conf` - Antenna specifications
- `simulation_params.conf` - NEC2 simulation parameters

### Quality Standards
- `quality_standards.conf` - Pattern quality standards
- `validation_rules.conf` - Validation rules
- `performance_benchmarks.conf` - Performance benchmarks

## Integration

### With Development Workflow
```bash
# Pre-commit pattern generation
./antenna-radiation-pattern-generator.sh --pre-commit

# Post-build validation
./pattern_validation_test_suite.sh --post-build
```

### With CI/CD
```bash
# CI pattern generation
./antenna-radiation-pattern-generator.sh --ci-mode

# Automated validation
./pattern_validation_test_suite.sh --automated
```

## Performance Optimization

### Parallel Processing
- Multi-core utilization
- Work unit distribution
- Load balancing
- Resource management
- Queue optimization

### Memory Management
- Memory optimization
- Cache management
- Resource monitoring
- Garbage collection
- Memory leak prevention

## Quality Assurance

### Pattern Quality
- Accuracy validation
- Consistency checks
- Completeness verification
- Standards compliance
- Performance benchmarking

### Generation Quality
- Process validation
- Error detection
- Quality metrics
- Regression testing
- Continuous improvement

## Troubleshooting

### Common Issues

1. **NEC2 Not Found**
   ```bash
   # Check NEC2 installation
   which nec2c
   # Install NEC2
   sudo apt-get install nec2c
   ```

2. **Pattern Generation Fails**
   ```bash
   # Debug generation
   ./debug_script.sh --verbose
   # Check input files
   ./debug_script.sh --validate-input
   ```

3. **Performance Issues**
   ```bash
   # Check system resources
   ./antenna-radiation-pattern-generator.sh --check-resources
   # Optimize settings
   ./antenna-radiation-pattern-generator.sh --optimize
   ```

### Debugging

1. **Verbose Output**
   ```bash
   # Enable verbose output
   ./antenna-radiation-pattern-generator.sh --verbose
   ./debug_script.sh --verbose
   ```

2. **Debug Mode**
   ```bash
   # Enable debug mode
   ./antenna-radiation-pattern-generator.sh --debug
   ./test_single_pattern.sh --debug
   ```

3. **Log Analysis**
   ```bash
   # Check generation logs
   tail -f logs/pattern_generation.log
   # Analyze error logs
   grep ERROR logs/pattern_generation.log
   ```

## Best Practices

### Pattern Generation
1. **Backup Data**: Always backup existing patterns
2. **Validate Input**: Validate input files before generation
3. **Monitor Resources**: Monitor system resources during generation
4. **Quality Checks**: Perform quality checks on generated patterns
5. **Documentation**: Document generation process and results

### Testing and Validation
1. **Regular Testing**: Test patterns regularly
2. **Incremental Validation**: Validate patterns incrementally
3. **Regression Testing**: Test for regressions
4. **Performance Monitoring**: Monitor generation performance
5. **Continuous Improvement**: Improve generation processes

## Future Enhancements

- Machine learning-based pattern generation
- Advanced electromagnetic modeling
- Real-time pattern generation
- Cloud-based processing
- Advanced visualization

## Support

For pattern generation issues:
1. Check generation logs in `logs/pattern_generation/`
2. Verify NEC2 installation
3. Review configuration files
4. Check input file formats
5. Validate system resources
