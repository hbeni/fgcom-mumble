# EME Power Budget Mathematics - Multi-Band Support

## Supported EME Bands

FGCom-mumble supports EME communication across multiple amateur radio bands:

| Band | Frequency | Wavelength | Typical Gain | Moon Reflection Loss | Atmospheric Loss |
|------|-----------|------------|--------------|---------------------|------------------|
| **6m** | 50 MHz | 6.0 m | 12.0 dBi | 4.0 dB | 0.1 dB |
| **2m** | 144 MHz | 2.083 m | 14.8 dBi | 6.0 dB | 0.5 dB |
| **70cm** | 432 MHz | 0.694 m | 16.5 dBi | 8.0 dB | 1.0 dB |
| **23cm** | 1296 MHz | 0.231 m | 20.0 dBi | 10.0 dB | 2.0 dB |
| **13cm** | 2304 MHz | 0.130 m | 22.0 dBi | 12.0 dB | 3.0 dB |
| **9cm** | 3456 MHz | 0.087 m | 24.0 dBi | 14.0 dB | 4.0 dB |
| **6cm** | 5760 MHz | 0.052 m | 26.0 dBi | 16.0 dB | 5.0 dB |
| **3cm** | 10368 MHz | 0.029 m | 28.0 dBi | 18.0 dB | 6.0 dB |

## 2m Band System Parameters (Example)

- **Frequency**: 144 MHz (2m amateur band)
- **Antenna Gain**: 14.8 dBi
- **Transmit Power**: 1000W = 30 dBW
- **Wavelength**: λ = c/f = 3×10⁸/144×10⁶ = 2.083 m

## 1. Effective Radiated Power (ERP)

### ERP Calculation
```
ERP (dBW) = Transmit Power (dBW) + Antenna Gain (dBi) - Feed Line Loss (dB)
```

Assuming minimal feed line loss for this calculation:
```
ERP = 30 dBW + 14.8 dBi = 44.8 dBW
ERP = 10^(44.8/10) = 30,200W = 30.2 kW
```

## 2. Path Loss Calculations

### Free Space Path Loss (One Way)
The Friis transmission equation for free space path loss:
```
L_fs = (4πd/λ)²
```

Where:
- d = distance to moon = 384,400 km (average)
- λ = wavelength = 2.083 m

In dB:
```
L_fs(dB) = 20 log₁₀(4πd/λ)
L_fs(dB) = 20 log₁₀(4π × 384,400,000 / 2.083)
L_fs(dB) = 20 log₁₀(2.315 × 10⁹)
L_fs(dB) = 20 × 9.364 = 187.3 dB
```

### Round Trip Path Loss
EME involves a round trip, so:
```
L_round_trip = 2 × L_fs = 2 × 187.3 = 374.6 dB
```

### Moon Reflection Loss
The moon is not a perfect reflector. Typical reflection characteristics:
- **Surface reflection efficiency**: ~7% (-11.5 dB)
- **Scattering losses**: ~3 dB
- **Polarization rotation**: ~3 dB (random, can be 0-6 dB)

Total moon reflection loss: ~6 dB (optimistic conditions)

### Total Path Loss
```
L_total = L_round_trip + L_moon_reflection + L_atmospheric
L_total = 374.6 + 6 + 0.5 = 381.1 dB
```

### Received Power
```
P_rx(dBW) = ERP(dBW) - L_total(dB) + G_rx(dBi)
P_rx(dBW) = 44.8 - 381.1 + 14.8 = -321.5 dBW
```

## 3. Signal-to-Noise Ratio Analysis

### Thermal Noise Floor
Boltzmann constant: k = 1.38 × 10⁻²³ J/K
Standard temperature: T = 290K (room temperature)
Bandwidth: B (depends on mode)

Thermal noise power:
```
P_noise = kTB
```

For different bandwidths:
- **CW (500 Hz)**: P_noise = 1.38×10⁻²³ × 290 × 500 = 2.00×10⁻¹⁸ W = -147 dBW
- **SSB (2.4 kHz)**: P_noise = 1.38×10⁻²³ × 290 × 2400 = 9.61×10⁻¹⁸ W = -140 dBW
- **JT65 (2.7 Hz)**: P_noise = 1.38×10⁻²³ × 290 × 2.7 = 1.08×10⁻²⁰ W = -170 dBW

### System Noise Temperature Considerations
**Sky Temperature at 144 MHz**:
- Cold sky: ~50K
- Galactic noise: ~200K at 144 MHz
- Ground pickup: Varies with antenna pattern

Typical system noise temperature: T_sys = 200-400K

With realistic system noise (T_sys = 300K):
```
P_noise(CW) = kT_sys × B = 1.38×10⁻²³ × 300 × 500 = 2.07×10⁻¹⁸ W = -146.8 dBW
SNR(CW) = -321.5 - (-146.8) = -174.7 dB
```

### Required Signal Levels for Communication
**Detection Thresholds**:
- CW audible copy: SNR ≥ -20 dB (in 500 Hz)
- JT65 decode: SNR ≥ -25 dB (in 2.7 Hz)
- Weak signal JT modes: Can decode down to -28 dB

## 4. Moon Path Variations

### Distance Variation
Moon distance varies from 356,400 km (perigee) to 406,700 km (apogee).

**Path loss variation**:
```
ΔL = 40 log₁₀(406,700/356,400) = 40 × 0.0573 = 2.3 dB
```

### Declination Effects
Moon declination varies ±28.5°, affecting:
- Ground reflection interference
- Atmospheric absorption
- Antenna elevation angle

Typical variation: ±3 dB

## 5. EME Signal Time Delay Analysis

### Basic Time Delay Calculation
**Round Trip Time**:
```
t = 2d/c
```

Where:
- d = distance to moon
- c = speed of light = 299,792,458 m/s

### Moon Distance Variations
The moon's orbit is elliptical, causing distance variations:

| Orbital Position | Distance (km) | Distance (m) |
|------------------|---------------|--------------|
| Perigee (closest) | 356,400 | 3.564 × 10⁸ |
| Average | 384,400 | 3.844 × 10⁸ |
| Apogee (farthest) | 406,700 | 4.067 × 10⁸ |

### Time Delay Calculations

**At Perigee (Minimum Delay)**:
```
t_min = 2 × 356,400,000 / 299,792,458
t_min = 712,800,000 / 299,792,458
t_min = 2.378 seconds
```

**At Average Distance**:
```
t_avg = 2 × 384,400,000 / 299,792,458
t_avg = 768,800,000 / 299,792,458
t_avg = 2.565 seconds
```

**At Apogee (Maximum Delay)**:
```
t_max = 2 × 406,700,000 / 299,792,458
t_max = 813,400,000 / 299,792,458
t_max = 2.713 seconds
```

**Delay Variation Range**:
```
Δt = t_max - t_min = 2.713 - 2.378 = 0.335 seconds
```

## 6. Libration Effects on Delay

### What is Libration?
The moon "rocks" slightly in its orbit due to:
- **Longitude libration**: ±7.9° (elliptical orbit)
- **Latitude libration**: ±6.7° (orbital inclination)

### Libration Distance Effects
- Additional distance variation ≈ ±1,700 km
- Additional delay variation ≈ ±0.011 seconds

### Why Delay Doesn't Depend on Frequency
c = fλ (constant for all EM radiation in vacuum)
The speed c is invariant, so delay = distance/c is also invariant.

### Monthly Delay Variation Pattern
The moon's orbital period is 27.32 days, so delay follows this cycle:

| Day in Orbit | Distance | Round Trip Delay |
|--------------|----------|------------------|
| 0 (Perigee) | 356,400 km | 2.378 s |
| 7 | 380,000 km | 2.536 s |
| 13.66 (Apogee) | 406,700 km | 2.713 s |
| 20 | 380,000 km | 2.536 s |
| 27.32 (Perigee) | 356,400 km | 2.378 s |

### Daily Change Rate
Maximum rate of change occurs at quadrature:
- dD/dt ≈ ±1,400 km/day
- dt/dt ≈ ±0.009 seconds/day

### Doppler vs Delay
- **Delay**: Constant ~2.6s (just time offset)
- **Doppler**: Frequency shift due to moon's motion
- **Independent effects**: Both must be considered

## 7. Practical Implications

### Voice Communications (SSB/FM)
- **Echo Effect**: You hear your own voice back after ~2.6 seconds
- **Psychological Impact**: Very disorienting for normal conversation
- **Solution**: Use PTT discipline - wait for echo before releasing PTT
- **QSO Pace**: Much slower than terrestrial contacts

### CW (Morse Code)
- **Echo Timing**: Your dits and dahs return 2.6 seconds later
- **Speed Limitation**: Must send slowly enough to avoid confusion
- **Typical Speed**: 12-15 WPM maximum (vs 25+ WPM for terrestrial)
- **Timing Discipline**: Wait for complete echo before sending next element

## 8. FGCom-mumble Integration

### Moon Position Tracking API
The FGCom-mumble system includes a comprehensive Moon Position Tracking API that provides:

- **Real-time moon position calculations**
- **Libration effects modeling**
- **Delay and Doppler shift calculations**
- **Manual position override capabilities**
- **EME communication parameter calculations**

### API Usage Examples

#### Multi-Band EME Calculations
```cpp
// Initialize moon position tracker
FGCom::MoonPositionTracker tracker;

// Get current moon position
auto position = tracker.getCurrentPosition();

// Calculate EME parameters for different bands
auto eme_2m = tracker.calculateEMEParametersForBand("2m", 1000.0, 14.8);
auto eme_6m = tracker.calculateEMEParametersForBand("6m", 1000.0, 12.0);
auto eme_70cm = tracker.calculateEMEParametersForBand("70cm", 1000.0, 16.5);

// Check if frequency is supported
bool is_supported = tracker.isFrequencySupported(144.5);  // 2m band
bool is_6m_supported = tracker.isFrequencySupported(50.0);  // 6m band

// Get band specification
auto band_spec = tracker.getBandSpec(144.5);
std::cout << "Band: " << band_spec.name << std::endl;
std::cout << "Frequency: " << band_spec.frequency_mhz << " MHz" << std::endl;
std::cout << "Wavelength: " << band_spec.wavelength_m << " m" << std::endl;

// Set manual override for testing
tracker.setManualDistance(356400.0, true);  // Perigee distance
```

#### Supported Bands Query
```cpp
// Get all supported EME bands
auto bands = tracker.getSupportedEMEBands();
for (const auto& band : bands) {
    std::cout << "Band: " << band.name 
              << " (" << band.frequency_mhz << " MHz)"
              << " - Gain: " << band.typical_gain_dbi << " dBi"
              << " - Supported: " << (band.is_supported ? "Yes" : "No") << std::endl;
}
```

### Integration with Radio System
The moon position data integrates with FGCom-mumble's radio propagation system to provide:
- **Realistic EME delay simulation**
- **Doppler shift tracking**
- **Signal quality calculations based on moon distance**
- **Optimal communication window predictions**

## 9. Conclusion

EME communication on the 2m band represents the ultimate challenge in amateur radio, requiring:
- **High power systems** (1000W+)
- **High-gain antennas** (14.8 dBi Yagi)
- **Sophisticated signal processing** (JT65, JT9, etc.)
- **Careful timing discipline** (2.6 second delays)
- **Advanced tracking systems** (Doppler, libration effects)

The mathematical analysis shows why EME is considered the pinnacle of amateur radio achievement, requiring both technical expertise and significant equipment investment.
