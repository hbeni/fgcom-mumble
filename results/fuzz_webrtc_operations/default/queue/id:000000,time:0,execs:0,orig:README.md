# We Operatius

## Overview
This corpus contains test data for fuzzing WebRTC operations in FGCom-mumble.

## Test Data Files
*Note: WebRTC operations corpus files are designed to test various WebRTC edge cases*

## Fuzzing Target
- **Binary**: `test/build-fuzz/fuzz_webrtc_operations`
- **Purpose**: Tests WebRTC operations for:
  - WebRTC connection establishment
  - WebRTC data transmission
  - WebRTC error handling
  - WebRTC security validation
  - WebRTC performance optimization

## Expected Behaviors
- WebRTC connections should be established reliably
- WebRTC data transmission should be secure
- WebRTC error handling should be robust
- WebRTC security should be validated
- WebRTC performance should be optimized

## Coverage Areas
- WebRTC connection establishment
- WebRTC data transmission
- WebRTC error handling
- WebRTC security validation
- WebRTC performance optimization
- WebRTC signaling
- WebRTC media handling
- WebRTC peer-to-peer communication