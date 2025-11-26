# FGCom LibFuzzer Harnesses

This directory contains comprehensive LibFuzzer harnesses for testing FGCom (FlightGear Communication) components.

## **FUZZING TARGETS**

### **Core FGCom Functionality:**
- **Radio Propagation Calculations** - Frequency validation, path loss, signal strength
- **Antenna Pattern Calculations** - Gain patterns, beamwidth, efficiency
- **Geographic Coordinate Transformations** - Distance/bearing calculations
- **Atmospheric Noise Modeling** - Noise floor calculations, interference detection

### **Audio Processing:**
- **AGC (Automatic Gain Control)** - Gain adjustment, attack/release
- **Squelch Detection** - Threshold detection, CTCSS tone detection
- **Audio Filtering** - IIR filters, biquad filters, effects
- **Professional Audio Engine** - Sample rate conversion, audio effects

### **Network & Protocols:**
- **UDP Communication** - Packet parsing, connection handling
- **HTTP API Endpoints** - Request parsing, response generation
- **WebRTC Operations** - SDP parsing, ICE candidates, media streams
- **Mumble Plugin Protocol** - Message parsing, state management

### **Security Functions:**
- **Encryption/Decryption** - AES, STANAG 4197, key management
- **Hash Functions** - SHA-256, MD5, authentication
- **Input Validation** - SQL injection, XSS, path traversal protection
- **Secure Random Generation** - Cryptographic randomness

### **Data Processing:**
- **JSON/XML Parsing** - Structure validation, attribute parsing
- **SQL Query Parsing** - Statement validation, injection detection
- **Configuration Parsing** - Key-value pairs, format validation
- **ATIS Message Parsing** - Weather data, airport information

### **Mathematical Functions:**
- **Distance/Bearing Calculations** - Haversine formula, coordinate validation
- **Signal Strength Computations** - Path loss, Fresnel zones
- **Noise Floor Calculations** - Atmospheric absorption, terrain shadowing
- **Interference Detection** - Frequency separation, power analysis

## **QUICK START**

### **1. Compile All Fuzzers:**
```bash
chmod +x scripts/compile_fuzzers.sh
./scripts/compile_fuzzers.sh
```

### **2. Run All Fuzzers (12 hours):**
```bash
./run_fuzzers.sh
```

### **3. Run Individual Fuzzer:**
```bash
chmod +x scripts/run_individual_fuzzer.sh
./scripts/run_individual_fuzzer.sh fuzz_radio_propagation 12
```

## **DIRECTORY STRUCTURE**

```
fuzzing-tests/
├── harnesses/           # Fuzzing harness source files
│   ├── fuzz_radio_propagation.cpp
│   ├── fuzz_audio_processing.cpp
│   ├── fuzz_network_protocol.cpp
│   ├── fuzz_security_functions.cpp
│   ├── fuzz_data_parsing.cpp
│   ├── fuzz_mathematical_calculations.cpp
│   └── fuzz_file_io.cpp
├── scripts/             # Build and run scripts
│   ├── compile_fuzzers.sh
│   ├── run_individual_fuzzer.sh
│   └── generate_corpus.py
├── corpus/              # Initial seed files (generated)
├── build/               # Compiled fuzzers (generated)
├── crashes/             # Crash outputs (generated)
└── README.md            # This file
```

## **FUZZER CONFIGURATION**

### **Critical Requirements:**
- **Duration**: 12 hours (`-max_total_time=43200`)
- **Crash Handling**: Continue on crashes (`-error_exitcode=0`)
- **Hang Prevention**: 25 second timeouts (`-timeout=25`, `-hang=25`)
- **Memory Management**: 4GB limit (`-rss_limit_mb=4096`)

### **Sanitizers Enabled:**
- **AddressSanitizer (ASan)** - Memory error detection
- **UndefinedBehaviorSanitizer (UBSan)** - Undefined behavior detection
- **FuzzerSanitizer** - LibFuzzer instrumentation

### **Coverage Tracking:**
- **Edge Coverage** - Basic block coverage
- **Line Coverage** - Source line coverage
- **Function Coverage** - Function entry coverage

## **CORPUS GENERATION**

The corpus contains binary seed files covering:

### **Radio Propagation Seeds:**
- Valid frequency ranges (118.0-137.0 MHz)
- Geographic coordinates (lat/lon pairs)
- Power levels (1-1000 watts)
- Antenna configurations

### **Audio Processing Seeds:**
- Silence samples (16-bit PCM)
- Tone samples (1kHz sine wave)
- Noise samples (random data)
- Various sample rates (8kHz-48kHz)

### **Network Protocol Seeds:**
- UDP packets with headers
- HTTP requests with headers
- Mumble protocol messages
- WebRTC SDP offers

### **Security Function Seeds:**
- AES encryption keys (128/192/256 bit)
- Hash function inputs
- Authentication credentials
- Random number sequences

### **Data Parsing Seeds:**
- Valid JSON structures
- XML documents with attributes
- SQL queries (SELECT/INSERT/UPDATE)
- Configuration files (key-value pairs)
- ATIS weather messages

## **COMPILATION FLAGS**

```bash
clang++ -g -O1 -fsanitize=fuzzer,address,undefined \
    -fsanitize-recover=all \
    -fno-omit-frame-pointer \
    -fno-optimize-sibling-calls \
    -fno-common -fno-builtin \
    -std=c++17 -Wall -Wextra \
    harness.cpp -o fuzzer
```

## **MONITORING & RESULTS**

### **Fuzzer Output:**
- **Execution Speed** - Executions per second
- **Coverage** - Edges discovered, coverage percentage
- **Crashes** - Number of crashes found
- **Hangs** - Number of timeouts detected

### **Crash Analysis:**
- **Crashes Directory** - Contains crash inputs
- **Stack Traces** - Detailed crash information
- **Reproduction** - Replay crash inputs

### **Coverage Analysis:**
- **Edge Coverage** - Basic block coverage
- **Line Coverage** - Source line coverage
- **Function Coverage** - Function entry coverage

## **TROUBLESHOOTING**

### **Common Issues:**

1. **Compilation Errors:**
   - Check FGCom library paths
   - Verify include directories
   - Ensure all dependencies installed

2. **Runtime Crashes:**
   - Check sanitizer output
   - Verify input validation
   - Review timeout settings

3. **Low Coverage:**
   - Add more corpus seeds
   - Review fuzzing logic
   - Check input consumption

4. **Memory Issues:**
   - Adjust RSS limit
   - Check for memory leaks
   - Review allocation patterns

### **Debug Commands:**
```bash
# Check running fuzzers
ps aux | grep fuzz

# Stop all fuzzers
killall fuzz_*

# Check crash outputs
ls -la crashes/

# View fuzzer logs
tail -f fuzzer.log
```

## **PERFORMANCE TUNING**

### **Optimization Tips:**
- Use `-O1` for faster execution
- Enable `-fsanitize-recover=all` for crash continuation
- Set appropriate timeout values
- Monitor memory usage

### **Parallel Fuzzing:**
- Use `-fork=N` for parallel execution
- Distribute across multiple cores
- Monitor system resources

## **SECURITY CONSIDERATIONS**

### **Input Validation:**
- All inputs are validated and sanitized
- Dangerous patterns are detected
- Path traversal attempts are blocked
- SQL injection patterns are identified

### **Memory Safety:**
- Bounds checking on all operations
- Safe memory allocation patterns
- Secure string operations
- Buffer overflow protection

## 📚 **REFERENCES**

- [LibFuzzer Documentation](https://llvm.org/docs/LibFuzzer.html)
- [AddressSanitizer](https://github.com/google/sanitizers/wiki/AddressSanitizer)
- [UndefinedBehaviorSanitizer](https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html)
- [FGCom Documentation](https://github.com/hbeni/fgcom-mumble)

## **CONTRIBUTING**

1. Add new harnesses to `harnesses/`
2. Update corpus generation in `scripts/generate_corpus.py`
3. Test with `scripts/run_individual_fuzzer.sh`
4. Update documentation as needed

## **LICENSE**

This fuzzing infrastructure is part of the FGCom project and follows the same licensing terms.
