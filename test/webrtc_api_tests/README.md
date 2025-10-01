# WebRTC API Tests

This test suite validates the WebRTC API implementation for FGCom-mumble, ensuring proper functionality of web browser clients connecting to the FGCom-mumble server.

## Test Coverage

### Core WebRTC Functionality
- **WebRTC Connection**: Test WebRTC peer connection establishment
- **Signaling**: Test offer/answer exchange and ICE candidate handling
- **Audio Streams**: Test audio stream processing and codec conversion
- **Data Transmission**: Test radio data transmission between WebRTC and Mumble

### Protocol Translation
- **JSON to UDP**: Test conversion from WebRTC JSON format to UDP field=value format
- **UDP to JSON**: Test conversion from Mumble UDP format to WebRTC JSON format
- **Data Validation**: Test input validation and error handling
- **Field Mapping**: Test proper mapping of all radio data fields

### WebRTC Gateway
- **Gateway Server**: Test WebRTC gateway server functionality
- **Authentication**: Test user authentication and session management
- **Connection Management**: Test client connection and disconnection
- **Error Handling**: Test error recovery and connection resilience

### Web Interface
- **Radio Controls**: Test radio control interface functionality
- **Map Integration**: Test map display and station markers
- **Status Display**: Test real-time status updates
- **Mobile Support**: Test mobile-optimized interface

### Performance and Security
- **Audio Quality**: Test audio quality and latency
- **Bandwidth Usage**: Test bandwidth optimization
- **Security**: Test authentication and data encryption
- **Scalability**: Test multiple concurrent connections

## Test Structure

### Unit Tests
- `test_webrtc_connection.cpp` - WebRTC connection establishment
- `test_protocol_translation.cpp` - Protocol translation functionality
- `test_audio_processing.cpp` - Audio stream processing
- `test_web_interface.cpp` - Web interface components
- `test_authentication.cpp` - User authentication system

### Integration Tests
- `test_webrtc_mumble_integration.cpp` - WebRTC to Mumble integration
- `test_multi_client.cpp` - Multiple WebRTC clients
- `test_audio_quality.cpp` - End-to-end audio quality testing
- `test_performance.cpp` - Performance and scalability testing

### End-to-End Tests
- `test_full_workflow.cpp` - Complete WebRTC client workflow
- `test_mobile_compatibility.cpp` - Mobile browser compatibility
- `test_cross_platform.cpp` - Cross-platform compatibility
- `test_error_recovery.cpp` - Error handling and recovery

## Running Tests

### Prerequisites
- Node.js (v16 or higher)
- npm or yarn package manager
- WebRTC testing tools (Chrome, Firefox, Safari)
- Mumble server for integration testing

### Quick Start
```bash
# Install dependencies
npm install

# Run all tests
./run_webrtc_api_tests.sh

# Run specific test categories
./run_webrtc_api_tests.sh --unit
./run_webrtc_api_tests.sh --integration
./run_webrtc_api_tests.sh --e2e
```

### Test Configuration
- **Test Server**: Configure test Mumble server
- **Browser Testing**: Set up browser automation
- **Audio Testing**: Configure audio input/output devices
- **Network Testing**: Set up network simulation

## Test Results

### Coverage Reports
- **Code Coverage**: HTML coverage reports in `coverage/` directory
- **Audio Quality**: Audio quality metrics and analysis
- **Performance**: Performance benchmarks and analysis
- **Security**: Security testing results and recommendations

### Test Reports
- **Unit Test Results**: Individual test results and coverage
- **Integration Test Results**: Cross-component integration results
- **End-to-End Results**: Complete workflow validation
- **Performance Results**: Performance benchmarks and optimization recommendations

## Continuous Integration

### Automated Testing
- **GitHub Actions**: Automated test runs on code changes
- **Browser Testing**: Cross-browser compatibility testing
- **Performance Monitoring**: Continuous performance monitoring
- **Security Scanning**: Automated security vulnerability scanning

### Quality Gates
- **Code Coverage**: Minimum 90% code coverage required
- **Performance**: Maximum 100ms audio latency
- **Security**: No critical security vulnerabilities
- **Compatibility**: Support for 95% of modern browsers

## Troubleshooting

### Common Issues
- **WebRTC Connection Failures**: Check firewall and NAT configuration
- **Audio Quality Issues**: Verify audio device configuration
- **Browser Compatibility**: Test on multiple browsers and versions
- **Performance Issues**: Monitor CPU and memory usage

### Debug Tools
- **WebRTC Debugging**: Chrome DevTools WebRTC debugging
- **Network Analysis**: Wireshark for network traffic analysis
- **Audio Analysis**: Audio quality analysis tools
- **Performance Profiling**: Browser performance profiling tools

## Contributing

### Adding New Tests
1. Create test file following naming convention: `test_*.cpp`
2. Add test to CMakeLists.txt
3. Update test runner script
4. Add documentation for new test

### Test Standards
- **Naming**: Use descriptive test names
- **Documentation**: Document test purpose and expected behavior
- **Coverage**: Ensure adequate test coverage
- **Performance**: Keep test execution time reasonable

## References

- [WebRTC API Documentation](https://developer.mozilla.org/en-US/docs/Web/API/WebRTC_API)
- [FGCom-mumble Documentation](../docs/)
- [Test Framework Documentation](../test/TestFramework.h)
- [WebRTC Testing Best Practices](https://webrtc.org/testing/)
