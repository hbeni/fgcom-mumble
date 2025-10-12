# FGCom-Mumble Architecture Documentation

## Overview

FGCom-Mumble is a comprehensive radio communication simulation system for flight simulators, built on the Mumble voice communication platform.

## System Architecture

### Core Components

1. **C++ Plugin (`fgcom-mumble.so`)**
   - Main Mumble plugin providing radio simulation
   - Handles audio processing, radio propagation, and communication protocols
   - Supports multiple radio models (VHF, UHF, HF, Amateur, String)

2. **Radio GUI (`FGCom-mumble-radioGUI.jar`)**
   - Java-based graphical user interface
   - Provides radio controls and frequency management
   - Integrates with Microsoft Flight Simulator 2020 via jsimconnect

3. **FlightGear Addon**
   - FlightGear-specific integration
   - Provides radio controls within FlightGear environment

4. **Server Components**
   - Status page for monitoring active users
   - Bot management for automated services
   - Recording and playback capabilities

### Radio Models

- **VHF (Very High Frequency)**: Civil aviation communications
- **UHF (Ultra High Frequency)**: Military and civilian UHF communications
- **HF (High Frequency)**: Long-range communications with skywave propagation
- **Amateur Radio**: Ham radio frequency bands and protocols
- **String**: Perfect worldwide communication (for testing)

### Audio Processing

- Real-time audio effects simulation
- Radio static and noise generation
- Signal quality degradation based on distance and conditions
- AGC (Automatic Gain Control) and squelch functionality

### Network Architecture

- UDP-based communication between clients and server
- WebRTC support for browser-based clients
- Dynamic GPU scaling for high user loads
- Network GPU sharing capabilities

## Installation and Configuration

See the main README.md for detailed installation instructions and configuration options.

## Development

This system is built with modern C++ and Java, utilizing:
- CMake for build system
- Maven for Java components
- Google Test for testing framework
- RapidCheck for property-based testing
