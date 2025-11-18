# JSIMConnect Build Test Suite

This test suite validates the JSIMConnect (MSFS2020 integration) build process and functionality for the FGCom-mumble project.

## Overview

The JSIMConnect Build Test Suite ensures that:
- Git submodules are properly initialized and checked out
- JSIMConnect library builds correctly with Maven
- RadioGUI builds successfully with and without JSIMConnect
- Maven dependencies are properly resolved
- JAR files are generated and installed correctly
- Makefile configuration is correct
- GitHub Actions workflow compatibility is maintained

## Test Categories

### 1. Submodule Management
- **Git Submodule Status**: Verifies that the jsimconnect submodule is properly registered and checked out
- **Directory Structure**: Ensures all essential files and directories exist

### 2. Build Process
- **Maven Build**: Tests that JSIMConnect builds successfully with Maven
- **JAR Generation**: Verifies that the jsimconnect JAR file is created
- **RadioGUI Integration**: Tests RadioGUI build with JSIMConnect enabled and disabled

### 3. Dependency Management
- **Maven Dependency Resolution**: Ensures all dependencies can be resolved
- **JAR Installation**: Tests installation of JSIMConnect JAR to local Maven repository

### 4. Configuration Testing
- **Makefile Configuration**: Verifies ENABLE_JSIMCONNECT setting
- **GitHub Actions Compatibility**: Ensures build process matches CI/CD expectations

## Running the Tests

```bash
# Run the complete test suite
./run_jsimconnect_build_tests.sh
```

## Test Results

The test suite generates:
- **Console Output**: Real-time test results with color-coded status
- **HTML Report**: Comprehensive test report at `test_results/jsimconnect_build_test_report.html`
- **Build Logs**: Detailed logs for each build process
- **Exit Code**: 0 for success, 1 for failure

## Prerequisites

Required tools:
- `git` - For submodule management
- `mvn` - For Maven builds
- `java` - For Java runtime
- `make` - For Makefile execution

## Test Output

The test suite provides detailed feedback on:
- ✅ **PASS**: Test completed successfully
- ❌ **FAIL**: Test failed with error details
- ⚠️ **WARN**: Test completed with warnings

## Troubleshooting

### Common Issues

1. **Submodule not initialized**: Run `git submodule update --init --recursive`
2. **Maven build fails**: Check Java version and Maven configuration
3. **Dependency resolution fails**: Ensure internet connection and Maven repository access
4. **JAR installation fails**: Check Maven local repository permissions

### Debug Information

All build logs are saved to the `test_results/` directory:
- `radiogui_build_with_jsimconnect.log`
- `radiogui_build_without_jsimconnect.log`
- `maven_dependency_resolution.log`
- `jsimconnect_jar_installation.log`

## Integration with CI/CD

This test suite is designed to work with GitHub Actions and other CI/CD systems. The tests verify that the build process matches the expectations defined in `.github/workflows/make-release.yml`.

## Maintenance

The test suite should be updated when:
- JSIMConnect library version changes
- Maven configuration changes
- Makefile build process changes
- GitHub Actions workflow changes
