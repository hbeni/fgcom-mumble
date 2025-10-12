# ATrocessing Fuzzing Corpusrvice) processing in FGCom-mumble.

## Test Data Files

### calm_wind.txt
- **Purpose**: Calm wind condition data
- **Format**: Weather information strings
- **Size**: Variable
- **Usage**: Tests ATIS processing with calm wind conditions

### full_atis.txt
- **Purpose**: Complete ATIS message data
- **Format**: Full ATIS weather report
- **Size**: Variable
- **Usage**: Tests comprehensive ATIS message processing

### invalid_atis.txt
- **Purpose**: Malformed ATIS data
- **Format**: Invalid ATIS message format
- **Size**: Variable
- **Usage**: Tests error handling for invalid ATIS messages

### minimal_atis.txt
- **Purpose**: Minimal ATIS data
- **Format**: Basic ATIS information
- **Size**: Variable
- **Usage**: Tests ATIS processing with minimal data

### wind_info.txt
- **Purpose**: Wind information data
- **Format**: Wind speed and direction data
- **Size**: Variable
- **Usage**: Tests wind information processing

## Fuzzing Target
- **Binary**: `test/build-fuzz/fuzz_atis_processing`
- **Purpose**: Tests ATIS processing for:
  - Weather information parsing
  - ATIS message validation
  - Wind data processing
  - Airport information handling
  - ATIS playback functionality

## Expected Behaviors
- ATIS messages should be parsed correctly
- Weather data should be processed accurately
- Invalid ATIS should be handled gracefully
- Wind information should be reliable
- ATIS playback should be robust

## Coverage Areas
- ATIS message parsing
- Weather information processing
- Wind data calculations
- Airport information handling
- ATIS playback systems
- Weather report generation
- ATIS message validation
- Weather data integrity
