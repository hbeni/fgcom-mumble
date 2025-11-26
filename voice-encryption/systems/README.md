# Voice Encryption Systems Directory

This directory contains all military-grade voice encryption systems implemented in the FGcom-Mumble project. These systems provide authentic Cold War-era and modern military communication simulation for flight simulators and games.

## IMPORTANT DISCLAIMER

**All voice encryption systems in this project are implemented for educational and simulation purposes only.** These systems are designed to provide authentic Cold War-era and modern military communication simulation for flight simulators and games. **If used for any illegal activities, the responsibility lies solely with the user.** The developers and maintainers of this project are not responsible for any misuse of these systems.

## Available Systems

### Cold War Era Systems

#### Soviet/East Bloc Systems
- **[Yachta T-219](yachta-t219/README.md)** - Soviet analog voice scrambler with time-frequency scrambling
- **[Granit](granit/README.md)** - Soviet time-scrambling voice encryption system

#### NATO Systems
- **[VINSON KY-57](vinson-ky57/README.md)** - NATO secure voice system with digital encryption
- **[STANAG 4197](stanag-4197/README.md)** - NATO QPSK OFDM voice encryption system
- **[MELPe with NATO Type 1 Encryption](melpe/README.md)** - NATO standard vocoder (STANAG 4591) with Cold War-era encryption

### Modern Systems
- **[FreeDV with ChaCha20-Poly1305](freedv/README.md)** - Modern digital voice system with authenticated encryption

### Satellite Communication
- **[Satellite Communication Systems](satellites/README.md)** - Real-time satellite tracking and communication simulation

## System Characteristics

| System | Type | Key Length | Security Level | Era |
|--------|------|------------|----------------|-----|
| **Yachta T-219** | Analog Scrambler | 64-bit | Medium | Cold War (Soviet) |
| **VINSON KY-57** | Digital Encryption | 128-bit | High | Cold War (NATO) |
| **Granit** | Time Scrambling | 80-bit | Medium | Cold War (Soviet) |
| **STANAG 4197** | OFDM Encryption | 256-bit | High | Cold War (NATO) |
| **MELPe + NATO Type 1** | Vocoder + Encryption | 128-bit | High | Cold War (NATO) |
| **FreeDV + ChaCha20** | Digital Voice + AEAD | 128-bit | Very High | Modern |

## Documentation Structure

Each system includes:
- **README.md** - System overview and basic usage
- **docs/** - Detailed documentation and analysis
- **include/** - Header files and API definitions
- **src/** - Implementation source code
- **CMakeLists.txt** - Build configuration (where applicable)

## Integration

All systems are integrated into the main FGcom-Mumble voice encryption module and can be accessed through the unified `VoiceEncryptionManager` API.

## Educational Purpose

These systems are designed for:
- **Flight Simulation** - Authentic military radio communication
- **Historical Accuracy** - Cold War-era communication simulation
- **Educational Research** - Understanding of military encryption systems
- **Game Development** - Realistic military communication in games

## Legal Notice

These implementations are for educational and simulation purposes only. They do not provide real security and should not be used for any actual secure communications. The developers are not responsible for any misuse of these systems.
