# Debug Scripts Directory

This directory contains debugging and diagnostic scripts for troubleshooting FGcom-Mumble components and identifying issues.

## Scripts Overview

### `debug_nec2.sh`
**Purpose**: Debugs NEC2 electromagnetic simulation issues and validates antenna pattern calculations.

**Features**:
- NEC2 simulation validation
- Antenna pattern verification
- Electromagnetic field calculations
- Pattern file integrity checks
- Performance diagnostics

**Usage**:
```bash
# Debug NEC2 simulation
./debug_nec2.sh

# Debug specific antenna
./debug_nec2.sh --antenna yagi_144mhz

# Verbose debugging
./debug_nec2.sh --verbose

# Debug with specific frequency
./debug_nec2.sh --frequency 144.200
```

### `debug_script_execution.sh`
**Purpose**: Debugs script execution issues, permission problems, and environment setup.

**Features**:
- Script execution validation
- Permission checking
- Environment variable verification
- Dependency validation
- Path resolution debugging

**Usage**:
```bash
# Debug script execution
./debug_script_execution.sh

# Debug specific script
./debug_script_execution.sh --script antenna-radiation-pattern-generator.sh

# Check environment
./debug_script_execution.sh --check-env

# Validate permissions
./debug_script_execution.sh --check-permissions
```

### `nec2_diagnostic.sh`
**Purpose**: Comprehensive NEC2 diagnostic tool for antenna simulation troubleshooting.

**Features**:
- NEC2 installation verification
- Input file validation
- Output file analysis
- Simulation parameter checking
- Error pattern recognition

**Usage**:
```bash
# Full diagnostic
./nec2_diagnostic.sh

# Check NEC2 installation
./nec2_diagnostic.sh --check-install

# Validate input files
./nec2_diagnostic.sh --validate-input

# Analyze output files
./nec2_diagnostic.sh --analyze-output
```

## Debugging Workflow

### 1. Environment Check
```bash
# Check system environment
./debug_script_execution.sh --check-env

# Verify dependencies
./debug_script_execution.sh --check-deps
```

### 2. NEC2 Validation
```bash
# Validate NEC2 installation
./nec2_diagnostic.sh --check-install

# Test NEC2 simulation
./debug_nec2.sh --test-simulation
```

### 3. Pattern Generation Debug
```bash
# Debug pattern generation
./debug_nec2.sh --debug-patterns

# Validate output files
./nec2_diagnostic.sh --validate-output
```

## Common Issues and Solutions

### NEC2 Issues
1. **NEC2 not found**
   ```bash
   # Check installation
   which nec2c
   # Install if missing
   sudo apt-get install nec2c
   ```

2. **Simulation errors**
   ```bash
   # Debug simulation
   ./debug_nec2.sh --verbose
   # Check input files
   ./nec2_diagnostic.sh --validate-input
   ```

3. **Pattern file issues**
   ```bash
   # Validate pattern files
   ./nec2_diagnostic.sh --analyze-output
   # Check file permissions
   ./debug_script_execution.sh --check-permissions
   ```

### Script Execution Issues
1. **Permission denied**
   ```bash
   # Fix permissions
   chmod +x script_name.sh
   # Check ownership
   ls -la script_name.sh
   ```

2. **Environment variables**
   ```bash
   # Check environment
   ./debug_script_execution.sh --check-env
   # Set required variables
   export NEC2_PATH=/usr/bin/nec2c
   ```

3. **Path issues**
   ```bash
   # Check PATH
   echo $PATH
   # Add to PATH if needed
   export PATH=$PATH:/path/to/nec2
   ```

## Debug Output

### Log Files
- `logs/debug_nec2.log` - NEC2 debugging output
- `logs/debug_script_execution.log` - Script execution logs
- `logs/nec2_diagnostic.log` - NEC2 diagnostic results

### Debug Levels
- `--verbose` - Detailed output
- `--debug` - Debug-level logging
- `--trace` - Full execution trace

## Integration

### With Development Workflow
```bash
# Pre-commit debugging
./debug_script_execution.sh --pre-commit

# Post-build validation
./nec2_diagnostic.sh --post-build
```

### With CI/CD
```bash
# CI debugging
./debug_script_execution.sh --ci-mode
./nec2_diagnostic.sh --ci-validation
```

## Configuration

### Debug Settings
- `debug_config.json` - Debug configuration
- `debug_levels.conf` - Debug level settings
- `exclude_patterns.txt` - Files to exclude from debugging

### Environment Variables
- `DEBUG_LEVEL` - Debug verbosity level
- `NEC2_DEBUG` - NEC2 debugging mode
- `SCRIPT_DEBUG` - Script execution debugging

## Best Practices

1. **Regular Debugging**: Run debug scripts regularly
2. **Log Analysis**: Review debug logs for patterns
3. **Environment Validation**: Check environment before development
4. **Issue Tracking**: Document issues and solutions
5. **Performance Monitoring**: Monitor debug script performance

## Troubleshooting

### Debug Scripts Not Working
1. Check script permissions
2. Verify dependencies
3. Review environment variables
4. Check log files
5. Validate configuration

### NEC2 Issues
1. Verify NEC2 installation
2. Check input file format
3. Validate simulation parameters
4. Review error messages
5. Check system resources

## Future Enhancements

- Automated issue detection
- Performance profiling integration
- Memory leak detection
- Thread debugging support
- Real-time monitoring

## Support

For debugging issues:
1. Check debug logs in `logs/debug/`
2. Review script permissions
3. Verify environment setup
4. Check dependency versions
5. Review configuration files
